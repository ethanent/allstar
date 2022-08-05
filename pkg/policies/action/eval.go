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

// Package actionuse implements the Action Use security policy.
package action

import (
	"context"
	"fmt"

	"github.com/google/go-github/v43/github"
)

// evaluateActionDenied evaluates an Action against a set of Rules.
func evaluateActionDenied(rules []*Rule, action *actionMetadata, gc globCache, sc semverCache) (*denyRuleEvaluationResult, []error) {
	result := &denyRuleEvaluationResult{
		denied:         false,
		actionMetadata: action,
	}

	var errs []error

	for _, r := range rules {
		stepResult := &denyRuleEvaluationStepResult{
			status: denyRuleStepStatusError,
			rule:   r,
		}
		switch r.Method {
		case "allow":
			fallthrough
		case "require":
			// check if action contained within allow or require
			for _, a := range r.Actions {
				match, matchName, _, err := a.match(action, gc, sc)
				if err != nil {
					errs = append(errs, err)
					stepResult.status = denyRuleStepStatusError
					continue
				}
				if !match {
					if matchName {
						stepResult.status = denyRuleStepStatusActionVersionMismatch
						continue
					}
					stepResult.status = denyRuleStepStatusMissingAction
					continue
				}
				// this is a permissible Action
				stepResult.status = denyRuleStepStatusAllowed
				stepResult.ruleVersionConstraint = a.Version
				break
			}
		case "deny":
			// check if Action is denied
			for _, a := range r.Actions {
				match, matchName, _, err := a.match(action, gc, sc)
				if err != nil {
					errs = append(errs, err)
					stepResult.status = denyRuleStepStatusError
					break
				}
				if !match {
					if matchName {
						stepResult.status = denyRuleStepStatusActionVersionMismatch
						continue
					}
					stepResult.status = denyRuleStepStatusMissingAction
					continue
				}
				// this is a denied Action
				stepResult.status = denyRuleStepStatusDenied
				stepResult.ruleVersionConstraint = a.Version
				break
			}
		default:
			continue
		}
		result.steps = append(result.steps, stepResult)
		if len(result.steps) > 0 {
			// exit if previous step has specifically allowed or denied the Action.
			lastStatus := result.steps[len(result.steps)-1].status
			if lastStatus == denyRuleStepStatusAllowed || lastStatus == denyRuleStepStatusDenied {
				break
			}
		}
	}

	return result, errs
}

// evaluateRequireRule evaluates a require rule against a set of Actions
func evaluateRequireRule(ctx context.Context, c *github.Client, owner, repo string, rule *Rule,
	actions []*actionMetadata, headSHA string, gc globCache, sc semverCache) (*requireRuleEvaluationResult, error) {
	if rule.Method != "require" {
		return nil, fmt.Errorf("rule is not a require rule")
	}
	result := &requireRuleEvaluationResult{
		satisfied: false,

		numberRequired:  rule.Count,
		numberSatisfied: 0,

		// fixes
	}

	for _, ra := range rule.Actions {
		// check if this rule is satisfied

		satisfied := false

		for _, a := range actions {
			match, matchName, _, err := ra.match(a, gc, sc)
			if err != nil {
				return nil, err
			}
			if !match {
				if matchName {
					// version mismatch
					result.fixes = append(result.fixes, &requireRuleEvaluationFix{
						fixMethod:               requireRuleEvaluationFixMethodUpdate,
						actionName:              a.name,
						actionVersionConstraint: ra.Version,
					})
					break
				}
				// name mismatch, keep looking
				continue
			}

			// Check if passing (if the Action is required to be)

			if rule.MustPass {
				passing := false
				runs, err := listWorkflowRuns(ctx, c, owner, repo, a.workflowFilename)
				if err != nil {
					return nil, err
				}
				for _, run := range runs {
					if run.HeadCommit == nil || run.HeadCommit.SHA == nil || *run.HeadCommit.SHA != headSHA {
						// Irrelevant run
						continue
					}
					if run.Status != nil && *run.Status == "completed" {
						passing = true
					}
				}
				if !passing {
					// Not passing. Suggest fix.
					result.fixes = append(result.fixes, &requireRuleEvaluationFix{
						fixMethod:               requireRuleEvaluationFixMethodFix,
						actionName:              a.name,
						actionVersionConstraint: ra.Version,
					})
					break
				}
			}

			// satisfied!
			satisfied = true
			break
		}

		if satisfied {
			result.numberSatisfied++
			continue
		}

		// not passing due to missing Action, add add fix suggestion

		result.fixes = append(result.fixes, &requireRuleEvaluationFix{
			fixMethod:               requireRuleEvaluationFixMethodAdd,
			actionName:              ra.Name,
			actionVersionConstraint: ra.Version,
		})
	}

	if result.numberSatisfied == result.numberRequired {
		result.satisfied = true
	}

	return result, nil
}
