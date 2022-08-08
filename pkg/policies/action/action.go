// Copyright 2022 Allstar Authors

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package actionuse implements the Interactions security policy.
package action

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/ossf/allstar/pkg/config"
	"github.com/ossf/allstar/pkg/config/operator"
	"github.com/ossf/allstar/pkg/policydef"
	"github.com/rhysd/actionlint"

	"github.com/google/go-github/v43/github"
	"github.com/rs/zerolog/log"
)

const configFile = "actions.yaml"
const polName = "GitHub Actions"

const maxWorkflows = 50

var actionNameVersionRegex = regexp.MustCompile(`([a-zA-Z0-9_\-.]+\/[a-zA-Z0-9_\-.]+)@([a-zA-Z0-9.]+)`)

const failText = "This policy, specified at the organization level, sets requirements for Action use by repos within the organization. This repo is failing to fully comply with organization policies, as explained below.\n\n```\n%s```\n\nSee the org-level %s policy configuration for details."
const repoSelectorExcludeDepthLimit = 3

// OrgConfig is the org-level config definition for Action Use
type OrgConfig struct {
	// OptConfig is the standard org-level opt in/out config, RepoOverride applies to all
	// config.
	OptConfig config.OrgOptConfig `json:"optConfig"`

	// Action defines which action to take, default log, other: issue...
	Action string `json:"action"`

	// Rules is a priority-ordered list of Action Use rules
	Rules []*Rule `json:"rules"`
}

// RepoConfig is the repo-level config for Action Use
type RepoConfig struct {
	// OptConfig is the standard repo-level opt in/out config.
	OptConfig config.RepoOptConfig `json:"optConfig"`
}

// Rule is an Action Use rule
type Rule struct {
	// Name is the name used to identify the rule
	Name string `json:"name"`

	// Method is the type of rule. One of "require", "allow", and "deny".
	Method string `json:"method"`

	// Repo is a RepoSelector to which apply the rule.
	// Use nil to apply to all repos.
	Repo *RepoSelector `json:"repo"`

	// MustPass specifies whether the rule's Action(s) are required to
	// be part of a passing workflow on latest commit
	MustPass bool `json:"mustPass"`

	// Count is the number of Actions listed to which a require rule
	// applies
	Count *int `json:"count"`

	// Actions is a set of ActionSelectors.
	// If nil, all Actions will be selected
	Actions []*ActionSelector `json:"actions"`
}

// RepoSelector specifies a selection of repos
type RepoSelector struct {
	// Name is the repo name in glob format
	Name string `json:"name"`

	// Language is a set of programming languages.
	// See the section about language detection below
	Language []string `json:"language"`

	// Exclude is a set of RepoSelectors targeting repos that should
	// not be matched by this selector.
	Exclude []*RepoSelector `json:"exclude"`
}

// ActionSelector specifies a selection of Actions
type ActionSelector struct {
	// Name is the Action name in glob format
	Name string `json:"name"`

	// Version is a semver condition or commit ref
	// Default "" targets any version
	Version string `json:"version"`
}

type details struct {
}

type workflowMetadata struct {
	filename string
	workflow *actionlint.Workflow
}

type actionMetadata struct {
	name             string
	version          string
	workflowFilename string
	workflowName     string
}

var doNothingOnOptOut = operator.DoNothingOnOptOut

var configFetchConfig func(context.Context, *github.Client, string, string, string, config.ConfigLevel, interface{}) error

var configIsEnabled func(ctx context.Context, o config.OrgOptConfig, orc, r config.RepoOptConfig, c *github.Client, owner, repo string) (bool, error)

var listWorkflows func(ctx context.Context, c *github.Client, owner, repo string, on []string) ([]*workflowMetadata, error)
var repoSelectorMatch func(rs *RepoSelector, ctx context.Context, c *github.Client, owner, repo string, excludeDepth int, gc globCache, sc semverCache) (bool, error)
var listWorkflowRunsByFilename func(ctx context.Context, c *github.Client, owner, repo string, workflowFilename string) ([]*github.WorkflowRun, error)
var getLatestCommitHash func(ctx context.Context, c *github.Client, owner, repo string) (string, error)

func init() {
	configFetchConfig = config.FetchConfig
	configIsEnabled = config.IsEnabled
	listWorkflows = githubListWorkflows
	repoSelectorMatch = githubRepoSelectorMatch
	listWorkflowRunsByFilename = githubListWorkflowRunsByFilename
	getLatestCommitHash = githubGetLatestCommitHash
}

// Action is the Action Use policy object, implements policydef.Policy.
type Action bool

// NewAction returns a new Action Use policy.
func NewAction() policydef.Policy {
	var a Action
	return a
}

// Name returns the name of this policy, implementing policydef.Policy.Name()
func (a Action) Name() string {
	return polName
}

// Check performs the policy check for Action Use policy based on the
// configuration stored in the org, implementing policydef.Policy.Check()
func (a Action) Check(ctx context.Context, c *github.Client, owner,
	repo string) (*policydef.Result, error) {
	oc, orc, rc := getConfig(ctx, c, owner, repo)
	enabled, err := configIsEnabled(ctx, oc.OptConfig, orc.OptConfig, rc.OptConfig, c, owner, repo)
	if err != nil {
		return nil, err
	}
	log.Info().
		Str("org", owner).
		Str("repo", repo).
		Str("area", polName).
		Bool("enabled", enabled).
		Msg("Check repo enabled")
	if !enabled && doNothingOnOptOut || len(oc.Rules) < 1 {
		// Don't run this policy if disabled and requested by operator. This is
		// only checking enablement of policy, but not Allstar overall, this is
		// ok for now.
		// Also do nothing if no rules exist.
		return &policydef.Result{
			Enabled:    enabled,
			Pass:       true,
			NotifyText: "Disabled",
			Details:    details{},
		}, nil
	}
	// Get workflows.
	// Workflows should have push and pull_request listed as trigger events
	// in order to qualify.
	wfs, err := listWorkflows(ctx, c, owner, repo, []string{"push", "pull_request"})
	if err != nil {
		return nil, err
	}

	// Create index of which workflows run which Actions
	var actions []*actionMetadata

	for _, wf := range wfs {
		if wf.workflow.Name == nil {
			wf.workflow.Name = &actionlint.String{Value: wf.filename}
		}
		if wf.workflow.Jobs == nil {
			continue
		}
		for _, j := range wf.workflow.Jobs {
			if j == nil {
				continue
			}
			for _, s := range j.Steps {
				if s == nil || s.Exec == nil {
					continue
				}
				actionStep, ok := s.Exec.(*actionlint.ExecAction)
				if !ok || actionStep == nil {
					continue
				}
				if actionStep.Uses == nil {
					// Missing uses in step
					continue
				}
				sm := actionNameVersionRegex.FindStringSubmatch(actionStep.Uses.Value)
				if sm == nil {
					// ignore invalid Action
					log.Info().
						Str("org", owner).
						Str("repo", repo).
						Str("area", polName).
						Str("action", actionStep.Uses.Value).
						Msg("Ignoring invalid action")
					continue
				}
				name := sm[1]
				version := sm[2]
				actions = append(actions, &actionMetadata{
					name:             name,
					version:          version,
					workflowFilename: wf.filename,
					workflowName:     wf.workflow.Name.Value,
				})
			}
		}
	}

	// Init caches

	gc := newGlobCache()
	sc := newSemverCache()

	// Determine applicable rules

	var applicableRules []*Rule

	for _, r := range oc.Rules {
		match, err := repoSelectorMatch(r.Repo, ctx, c, owner, repo, repoSelectorExcludeDepthLimit, gc, sc)
		if err != nil {
			log.Info().
				Str("org", owner).
				Str("repo", repo).
				Str("area", polName).
				Err(err).
				Msg("Skipping rule with invalid RepoSelector")
			continue
		}
		if match {
			applicableRules = append(applicableRules, r)
		}
	}

	// Evaluate rules using index

	var results []ruleEvaluationResult

	// => First, evaluate deny rules
	// Note: deny rules are evaluated Action-wise

	for _, a := range actions {
		denyResult, _ := evaluateActionDenied(applicableRules, a, gc, sc)
		// errors can be ignored because they are all glob / version parse
		// errors (user-created) and are reflected in denyResult steps

		results = append(results, denyResult)
	}

	// => Next, evaluate require rules

	var wfr *github.WorkflowRuns
	var headSHA string

	for _, r := range applicableRules {
		if r.Method == "require" {
			if r.MustPass && wfr == nil {
				var err error
				hash, err := getLatestCommitHash(ctx, c, owner, repo)
				if err != nil {
					log.Error().
						Str("org", owner).
						Str("repo", repo).
						Str("area", polName).
						Err(err).
						Msg("Error getting latest commit hash. Skipping rule evaluation.")
					break
				}
				headSHA = hash
			}

			result, err := evaluateRequireRule(ctx, c, owner, repo, r, actions, headSHA, gc, sc)
			if err != nil {
				log.Warn().
					Str("org", owner).
					Str("repo", repo).
					Str("area", polName).
					Err(err).
					Msg("Error evaluating require rule")
				continue
			}
			results = append(results, result)
		}
	}

	passing := true
	combinedExplain := ""

	for _, result := range results {
		if !result.passed() {
			passing = false
			if combinedExplain != "" {
				combinedExplain += "\n"
			}
			combinedExplain += result.explain()
		}
	}

	notifyText := fmt.Sprintf(failText, combinedExplain, polName)

	if passing {
		notifyText = "OK"
	}

	return &policydef.Result{
		Enabled:    enabled,
		Pass:       passing,
		NotifyText: notifyText,
		Details:    details{},
	}, nil
}

// Fix implementing policydef.Policy.Fix(). Not supported.
func (a Action) Fix(ctx context.Context, c *github.Client, owner, repo string) error {
	log.Warn().
		Str("org", owner).
		Str("repo", repo).
		Str("area", polName).
		Msg("Action fix is configured, but not implemented.")
	return nil
}

// GetAction returns the configured action from Action Use policy's
// configuration stored in the org repo, default log. Implementing
// policydef.Policy.GetAction()
func (a Action) GetAction(ctx context.Context, c *github.Client, owner, repo string) string {
	oc, _, _ := getConfig(ctx, c, owner, repo)
	return oc.Action
}

// githubGetLatestCommitHash gets the latest commit hash for a repo's default
// branch using the GitHub API
func githubGetLatestCommitHash(ctx context.Context, c *github.Client, owner, repo string) (string, error) {
	commits, _, err := c.Repositories.ListCommits(ctx, owner, repo, &github.CommitsListOptions{})
	if err != nil {
		return "", err
	}
	if len(commits) > 0 && commits[0].SHA != nil {
		return *commits[0].SHA, nil
	}
	return "", fmt.Errorf("repo has no commits: %w", err)
}

// githubListWorkflows returns workflows for a repo. If on is specified, will
// filter to workflows with all trigger events listed in on.
func githubListWorkflows(ctx context.Context, c *github.Client, owner, repo string, on []string) ([]*workflowMetadata, error) {
	_, workflowDirContents, resp, err := c.Repositories.GetContents(ctx, owner, repo, ".github/workflows", &github.RepositoryContentGetOptions{})
	if err != nil {
		if resp.StatusCode == 404 {
			// No workflows dir should yield no workflows
			return []*workflowMetadata{}, nil
		}
		return nil, err
	}
	// Limit number of considered workflows to maxWorkflows
	if len(workflowDirContents) > maxWorkflows {
		workflowDirContents = workflowDirContents[:maxWorkflows]
	}
	// Get content for workflows
	for _, wff := range workflowDirContents {
		fc, _, _, err := c.Repositories.GetContents(ctx, owner, repo, wff.GetPath(), &github.RepositoryContentGetOptions{})
		if err != nil {
			return nil, err
		}
		content, err := fc.GetContent()
		if err != nil {
			return nil, err
		}
		wff.Content = &content
	}
	var workflows []*workflowMetadata
	for _, wfc := range workflowDirContents {
		if wfc.Name == nil {
			// missing name?
			log.Error().
				Str("org", owner).
				Str("repo", repo).
				Str("area", polName).
				Str("path", wfc.GetPath()).
				Msg("Workflow file missing name field unexpectedly.")
			continue
		}
		sc, err := wfc.GetContent()
		if err != nil {
			log.Error().
				Str("org", owner).
				Str("repo", repo).
				Str("area", polName).
				Str("path", wfc.GetPath()).
				Str("downloadURL", wfc.GetDownloadURL()).
				Err(err).
				Msg("Unexpected error while getting workflow file content. Skipping.")
			continue
		}
		bc := []byte(sc)
		wf, errs := actionlint.Parse(bc)
		if len(errs) > 0 || wf == nil {
			var errors []error
			for _, err := range errs {
				errors = append(errors, fmt.Errorf("actionlist.Parse error: %w", err))
			}
			log.Warn().
				Str("org", owner).
				Str("repo", repo).
				Str("area", polName).
				Str("path", wfc.GetPath()).
				Errs("errors", errors).
				Msg("Errors while parsing workflow file content.")
		}
		// Filter if required trigger events specified
		if on != nil {
			allowByOnFilter := true
			for _, o := range on {
				contains := false
				for _, oa := range wf.On {
					if o == oa.EventName() {
						contains = true
					}
				}
				if !contains {
					allowByOnFilter = false
					break
				}
			}
			if !allowByOnFilter {
				log.Info().
					Str("org", owner).
					Str("repo", repo).
					Str("area", polName).
					Str("path", wfc.GetPath()).
					Strs("on", on).
					Msg("Skipping workflow due to missing on trigger(s).")
				continue
			}
		}
		workflows = append(workflows, &workflowMetadata{
			filename: wfc.GetName(),
			workflow: wf,
		})
	}
	return workflows, nil
}

// githubListWorkflowRunsByFilename returns workflow runs for a repo by workflow filename
func githubListWorkflowRunsByFilename(ctx context.Context, c *github.Client, owner, repo string, workflowFilename string) ([]*github.WorkflowRun, error) {
	runs, _, err := c.Actions.ListWorkflowRunsByFileName(ctx, owner, repo, workflowFilename, &github.ListWorkflowRunsOptions{
		Event: "push",
	})

	return runs.WorkflowRuns, err
}

func getConfig(ctx context.Context, c *github.Client, owner, repo string) (*OrgConfig, *RepoConfig, *RepoConfig) {
	oc := &OrgConfig{ // Fill out non-zero defaults
		Action: "log",
	}
	if err := configFetchConfig(ctx, c, owner, "", configFile, config.OrgLevel, oc); err != nil {
		log.Error().
			Str("org", owner).
			Str("repo", repo).
			Str("configLevel", "orgLevel").
			Str("area", polName).
			Str("file", configFile).
			Err(err).
			Msg("Unexpected config error, using defaults.")
	}
	orc := &RepoConfig{}
	if err := configFetchConfig(ctx, c, owner, repo, configFile, config.OrgRepoLevel, orc); err != nil {
		log.Error().
			Str("org", owner).
			Str("repo", repo).
			Str("configLevel", "orgRepoLevel").
			Str("area", polName).
			Str("file", configFile).
			Err(err).
			Msg("Unexpected config error, using defaults.")
	}
	rc := &RepoConfig{}
	if err := configFetchConfig(ctx, c, owner, repo, configFile, config.RepoLevel, rc); err != nil {
		log.Error().
			Str("org", owner).
			Str("repo", repo).
			Str("configLevel", "repoLevel").
			Str("area", polName).
			Str("file", configFile).
			Err(err).
			Msg("Unexpected config error, using defaults.")
	}
	return oc, orc, rc
}

func (as *ActionSelector) match(m *actionMetadata, gc globCache, sc semverCache) (match, matchName, matchVersion bool, err error) {
	if as.Name != "" {
		nameGlob, err := gc.compileGlob(as.Name)
		if err != nil {
			return false, false, false, err
		}
		if !nameGlob.Match(m.name) {
			return false, false, false, nil
		}
	}
	if as.Version == "" {
		return true, true, true, nil
	}
	if as.Version == m.version {
		return true, true, true, nil
	}
	if as.Version != "" {
		constraint, err := sc.compileConstraints(as.Version)
		if err != nil {
			// on error, assume this is a ref
			return false, true, false, nil
		}
		version, err := sc.compileVersion(m.version)
		if err != nil {
			return false, true, false, err
		}
		if !constraint.Check(version) {
			return false, true, false, nil
		}
	}
	return true, true, true, nil
}

// githubRepoSelectorMatch uses GitHub API while matching a repo using a RepoSelector.
// Set excludeDepth to > 0 for exclusion depth limit, or < 0 for no depth limit.
func githubRepoSelectorMatch(rs *RepoSelector, ctx context.Context, c *github.Client, owner, repo string, excludeDepth int, gc globCache, sc semverCache) (bool, error) {
	if rs == nil {
		return true, nil
	}
	if rs.Name != "" {
		ng, err := gc.compileGlob(rs.Name)
		if err != nil {
			return false, err
		}
		if !ng.Match(repo) {
			return false, nil
		}
	}
	if rs.Language != nil {
		langs, _, err := c.Repositories.ListLanguages(ctx, owner, repo)
		if err != nil {
			return false, err
		}
		languageSatisfied := false
		for l := range langs {
			for _, sl := range rs.Language {
				if strings.EqualFold(sl, l) {
					languageSatisfied = true
				}
			}
		}
		if !languageSatisfied {
			return false, nil
		}
	}
	// Check if covered by exclusion case
	if excludeDepth != 0 {
		for _, exc := range rs.Exclude {
			match, err := githubRepoSelectorMatch(exc, ctx, c, owner, repo, excludeDepth-1, gc, sc)
			if err != nil {
				// API error? Ignore exclusion
				continue
			}
			if match {
				return false, nil
			}
		}
	}
	return true, nil
}
