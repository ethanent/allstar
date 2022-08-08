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

package action

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/gobwas/glob"
	"github.com/google/go-github/v43/github"
	"github.com/ossf/allstar/pkg/config"
	"github.com/rhysd/actionlint"
)

func TestCheck(t *testing.T) {
	createWorkflowRun := func(sha, status string) *github.WorkflowRun {
		return &github.WorkflowRun{
			HeadSHA: &sha,
			Status:  &status,
		}
	}

	type testingWorkflowMetadata struct {
		// File is the actual filename of the workflow to load.
		// Will be loaded from test_workflows/ directory.
		File string

		Runs []*github.WorkflowRun

		// Repos is the set of repos in which this workflow is included
		Repos []string
	}

	denyAll := &Rule{
		Name:   "Deny default",
		Method: "deny",
	}

	tests := []struct {
		Name string

		Repo    RepoConfig
		OrgRepo RepoConfig
		Org     OrgConfig

		ConfigEnabled bool

		// Workflows is a map of filenames to workflowMetadata structs.
		// Filename: just filename eg. "my_workflow.yaml"
		Workflows map[string]testingWorkflowMetadata

		LatestCommitHash string

		ExpectMessage []string
		ExpectPass    bool
	}{
		{
			Name: "Deny all, has Action",
			Org: OrgConfig{
				Action: "issue",
				Rules: []*Rule{
					denyAll,
				},
			},
			ConfigEnabled: true,
			Workflows: map[string]testingWorkflowMetadata{
				"test.yaml": {
					File: "basic.yaml",
				},
			},
			ExpectPass:    false,
			ExpectMessage: []string{"denied by deny rule \"Deny default\""},
		},
		{
			Name: "Deny all, no Action",
			Org: OrgConfig{
				Action: "issue",
				Rules: []*Rule{
					denyAll,
				},
			},
			ConfigEnabled: true,
			Workflows:     map[string]testingWorkflowMetadata{},
			ExpectPass:    true,
		},
		{
			Name: "Deny all, no Action (but Workflow present)",
			Org: OrgConfig{
				Action: "issue",
				Rules: []*Rule{
					denyAll,
				},
			},
			ConfigEnabled: true,
			Workflows: map[string]testingWorkflowMetadata{
				"actionless.yaml": {
					File: "actionless.yaml",
				},
			},
			ExpectPass: true,
		},
		{
			Name: "Allowlist new versions, new version",
			Org: OrgConfig{
				Action: "issue",
				Rules: []*Rule{
					{
						Name:   "Allowlist trusted rules",
						Method: "allow",
						Actions: []*ActionSelector{
							{
								Name: "actions/*",
							},
							{
								Name:    "gradle/wrapper-validation-action",
								Version: ">= 1",
							},
						},
					},
					denyAll,
				},
			},
			ConfigEnabled: true,
			Workflows: map[string]testingWorkflowMetadata{
				"test.yaml": {
					File: "gradle-wrapper-validate.yaml",
				},
			},
			ExpectPass: true,
		},
		{
			Name: "Allowlist new versions, old version",
			Org: OrgConfig{
				Action: "issue",
				Rules: []*Rule{
					{
						Name:   "Allowlist trusted rules",
						Method: "allow",
						Actions: []*ActionSelector{
							{
								Name: "actions/*",
							},
							{
								Name:    "gradle/wrapper-validation-action",
								Version: ">= 2",
							},
						},
					},
					denyAll,
				},
			},
			ConfigEnabled: true,
			Workflows: map[string]testingWorkflowMetadata{
				"test.yaml": {
					File: "gradle-wrapper-validate.yaml",
				},
			},
			ExpectPass: false,
			ExpectMessage: []string{
				"does not meet version requirement \">= 2\" for allow rule \"Allowlist",
				"denied by deny rule \"Deny default\"",
			},
		},
		{
			Name: "Require new version, new version",
			Org: OrgConfig{
				Action: "issue",
				Rules: []*Rule{
					{
						Name:   "Require Gradle Wrapper validation",
						Method: "require",
						Actions: []*ActionSelector{
							{
								Name:    "gradle/wrapper-validation-action",
								Version: ">= 1.0.4",
							},
						},
					},
				},
			},
			ConfigEnabled: true,
			Workflows: map[string]testingWorkflowMetadata{
				"test.yaml": {
					File: "gradle-wrapper-validate.yaml",
				},
			},
			ExpectPass: true,
		},
		{
			Name: "Require new version, old version",
			Org: OrgConfig{
				Action: "issue",
				Rules: []*Rule{
					{
						Name:   "Require Gradle Wrapper validation",
						Method: "require",
						Actions: []*ActionSelector{
							{
								Name:    "gradle/wrapper-validation-action",
								Version: ">= 2",
							},
						},
					},
				},
			},
			ConfigEnabled: true,
			Workflows: map[string]testingWorkflowMetadata{
				"test.yaml": {
					File: "gradle-wrapper-validate.yaml",
				},
			},
			ExpectPass: false,
			ExpectMessage: []string{
				"Require rule \"Require Gradle * not satisfied",
				"0 / 1 requisites met",
				"Update *\"gradle/wrapper-val*\" to version satisfying \">= 2\"",
			},
		},
		{
			Name: "Require passing, passing on latest",
			Org: OrgConfig{
				Action: "issue",
				Rules: []*Rule{
					{
						Name:     "Require Gradle Wrapper validation",
						Method:   "require",
						MustPass: true,
						Actions: []*ActionSelector{
							{
								Name:    "gradle/wrapper-validation-action",
								Version: ">= 1.0.4",
							},
						},
					},
				},
			},
			ConfigEnabled: true,
			Workflows: map[string]testingWorkflowMetadata{
				"test.yaml": {
					File: "gradle-wrapper-validate.yaml",
					Runs: []*github.WorkflowRun{
						createWorkflowRun("sha-latest", "completed"),
					},
				},
			},
			LatestCommitHash: "sha-latest",
			ExpectPass:       true,
		},
		{
			Name: "Require passing, passing only on old commit",
			Org: OrgConfig{
				Action: "issue",
				Rules: []*Rule{
					{
						Name:     "Require Gradle Wrapper validation",
						Method:   "require",
						MustPass: true,
						Actions: []*ActionSelector{
							{
								Name:    "gradle/wrapper-validation-action",
								Version: ">= 1.0.4",
							},
						},
					},
				},
			},
			ConfigEnabled: true,
			Workflows: map[string]testingWorkflowMetadata{
				"test.yaml": {
					File: "gradle-wrapper-validate.yaml",
					Runs: []*github.WorkflowRun{
						createWorkflowRun("sha-old", "completed"),
					},
				},
			},
			LatestCommitHash: "sha-latest",
			ExpectPass:       false,
			ExpectMessage: []string{
				"Require rule \"Require * not satisfied",
				"0 / 1 requisites met",
				"Fix failing * \"gradle/wrapper*\"",
			},
		},
		{
			Name: "Require passing, failing on current commit",
			Org: OrgConfig{
				Action: "issue",
				Rules: []*Rule{
					{
						Name:     "Require Gradle Wrapper validation",
						Method:   "require",
						MustPass: true,
						Actions: []*ActionSelector{
							{
								Name:    "gradle/wrapper-validation-action",
								Version: ">= 1.0.4",
							},
						},
					},
				},
			},
			ConfigEnabled: true,
			Workflows: map[string]testingWorkflowMetadata{
				"test.yaml": {
					File: "gradle-wrapper-validate.yaml",
					Runs: []*github.WorkflowRun{
						createWorkflowRun("sha-latest", "failure"),
					},
				},
			},
			LatestCommitHash: "sha-latest",
			ExpectPass:       false,
			ExpectMessage: []string{
				"Require rule \"Require * not satisfied",
				"0 / 1 requisites met",
				"Fix failing * \"gradle/wrapper*\"",
			},
		},
		{
			Name: "Require, not present",
			Org: OrgConfig{
				Action: "issue",
				Rules: []*Rule{
					{
						Name:   "Require Gradle Wrapper validation",
						Method: "require",
						Actions: []*ActionSelector{
							{
								Name:    "gradle/wrapper-validation-action",
								Version: ">= 1.0.4",
							},
						},
					},
				},
			},
			ConfigEnabled: true,
			Workflows: map[string]testingWorkflowMetadata{
				"test.yaml": {
					File: "basic.yaml",
				},
			},
			LatestCommitHash: "sha-latest",
			ExpectPass:       false,
			ExpectMessage: []string{
				"Require rule \"Require * not satisfied",
				"0 / 1 requisites met",
				"Add Action \"gradle/wrapper*\" with version satisfying \">= 1.0.4\"",
			},
		},
	}

	a := NewAction()

	for i, test := range tests {
		// Override external functions

		configFetchConfig = func(ctx context.Context, c *github.Client, owner, repo, path string,
			ol config.ConfigLevel, out interface{}) error {
			switch ol {
			case config.RepoLevel:
				rc := out.(*RepoConfig)
				*rc = test.Repo
			case config.OrgRepoLevel:
				orc := out.(*RepoConfig)
				*orc = test.OrgRepo
			case config.OrgLevel:
				oc := out.(*OrgConfig)
				*oc = test.Org
			}
			return nil
		}

		configIsEnabled = func(ctx context.Context, o config.OrgOptConfig, orc,
			r config.RepoOptConfig, c *github.Client, owner, repo string) (bool, error) {
			return test.ConfigEnabled, nil
		}

		listWorkflows = func(ctx context.Context, c *github.Client, owner, repo string,
			on []string) ([]*workflowMetadata, error) {
			var wfs []*workflowMetadata
			for fn, w := range test.Workflows {
				inThisRepo := false
				for _, r := range w.Repos {
					if r == repo {
						inThisRepo = true
					}
				}
				if w.Repos == nil {
					inThisRepo = true
				}
				if !inThisRepo {
					continue
				}
				d, err := ioutil.ReadFile(filepath.Join("test_workflows", w.File))
				if err != nil {
					return nil, fmt.Errorf("failed to open test workflow file: %w", err)
				}
				workflow, errs := actionlint.Parse(d)
				if len(errs) > 0 {
					for _, er := range errs {
						t.Logf("parse err: %s", er.Error())
					}
				}
				wfs = append(wfs, &workflowMetadata{
					filename: fn,
					workflow: workflow,
				})
			}
			return wfs, nil
		}

		// The testing repoSelectorMatch function only matches by name
		repoSelectorMatch = func(rs *RepoSelector, ctx context.Context, c *github.Client,
			owner, repo string, gc globCache, sc semverCache) (bool, error) {
			if rs == nil {
				return true, nil
			}
			comp, err := glob.Compile(rs.Name)
			if err != nil {
				return false, err
			}
			return comp.Match(repo), nil
		}

		listWorkflowRunsByFilename = func(ctx context.Context, c *github.Client, owner, repo,
			workflowFilename string) ([]*github.WorkflowRun, error) {
			twm, ok := test.Workflows[workflowFilename]
			if !ok {
				return nil, fmt.Errorf("could not find testWorkflowMetadata for filename %s", workflowFilename)
			}
			return twm.Runs, nil
		}

		getLatestCommitHash = func(ctx context.Context, c *github.Client, owner, repo string) (string, error) {
			return test.LatestCommitHash, nil
		}

		res, err := a.Check(context.Background(), nil, "thisorg", "thisrepo")

		// Check result

		if err != nil {
			t.Errorf("Test \"%s\" (%d) failed: %e", test.Name, i, err)
			continue
		}

		if res.Pass != test.ExpectPass {
			t.Errorf("Test \"%s\" (%d) failed: expect pass = %t, got pass = %t", test.Name, i, test.ExpectPass, res.Pass)
		}

		for _, message := range test.ExpectMessage {
			comp, err := glob.Compile("*" + message + "*")
			if err != nil {
				t.Fatalf("failed to parse ExpectMessage glob: %s", err.Error())
			}
			if !comp.Match(res.NotifyText) {
				t.Errorf("Test \"%s\" (%d) failed: \"%s\" does not contain \"%s\"", test.Name, i, res.NotifyText, message)
			}
		}
	}
}
