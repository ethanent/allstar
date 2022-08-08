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

import "fmt"

// ruleEvaluationResult represents a result of evaluating a rule.
type ruleEvaluationResult interface {
	// passed specifies whether the rule evaluation yielded an OK result.
	passed() bool

	// explain provides a string explanation for the outcome of the evaluation.
	explain() string
}

// denyRuleEvaluationResult represents the result of a deny rule evaluation on
// an Action.
type denyRuleEvaluationResult struct {
	// denied specifies whether the Action was denied.
	denied bool

	// denyingRule is the rule which denied the Action, or "" if not
	// denied.
	denyingRule *Rule

	// actionMetadata is the metadata of the Action being evaluated.
	actionMetadata *actionMetadata

	// steps is a set of steps during the evaluation.
	steps []*denyRuleEvaluationStepResult
}

// denyRuleStepStatus is the result of evaluating the Action against a specific
// rule.
type denyRuleStepStatus int

const (
	denyRuleStepStatusMissingAction denyRuleStepStatus = iota
	denyRuleStepStatusActionVersionMismatch
	denyRuleStepStatusAllowed
	denyRuleStepStatusDenied
	denyRuleStepStatusError
)

// denyRuleEvaluationStepResult represents a single rule evaluation while
// evaluating an Action.
type denyRuleEvaluationStepResult struct {
	// status is the result of this check against a rule.
	status denyRuleStepStatus

	// rule is the rule being evaluated at this step.
	rule *Rule

	// ruleVersionConstraint is the version constraint for the evaluated Action
	// within the rule evaluated on this step.
	// Must be present if result is denyRuleStepStatusActionVersionMismatch.
	ruleVersionConstraint string
}

func (de *denyRuleEvaluationResult) passed() bool {
	return !de.denied
}

func (de *denyRuleEvaluationResult) explain() string {
	if de.denyingRule == nil {
		de.denyingRule = &Rule{Name: "Name unknown"}
	}
	s := ""
	if de.denied {
		s = fmt.Sprintf("Action \"%s\" version %s hit deny rule \"%s\":\n", de.actionMetadata.name, de.actionMetadata.version, de.denyingRule.Name)
	} else {
		s = fmt.Sprintf("Action \"%s\" version %s did not hit a deny rule.\n", de.actionMetadata.name, de.actionMetadata.version)
	}
	// add step results
	for _, stepResult := range de.steps {
		s += fmt.Sprintf("-> %s\n", stepResult.string())
	}
	return s
}

// string returns the string representation of this step
func (des *denyRuleEvaluationStepResult) string() string {
	switch des.status {
	case denyRuleStepStatusActionVersionMismatch:
		return fmt.Sprintf("does not meet version requirement \"%s\" for %s rule \"%s\"", des.ruleVersionConstraint, des.rule.Method, des.rule.Name)
	case denyRuleStepStatusMissingAction:
		return fmt.Sprintf("is not listed in %s rule \"%s\"", des.rule.Method, des.rule.Name)
	case denyRuleStepStatusAllowed:
		return fmt.Sprintf("allowed by %s rule \"%s\"", des.rule.Method, des.rule.Name)
	case denyRuleStepStatusDenied:
		return fmt.Sprintf("denied by %s rule \"%s\"", des.rule.Method, des.rule.Name)
	case denyRuleStepStatusError:
		return fmt.Sprintf("%s rule \"%s\" experienced an error", des.rule.Method, des.rule.Name)
	default:
		return "unknown deny eval step result"
	}
}

// requireRuleEvaluationResult represents the result of a require rule evaluation.
type requireRuleEvaluationResult struct {
	satisfied bool

	numberRequired  int
	numberSatisfied int

	ruleName string

	fixes []*requireRuleEvaluationFix
}

// requireRuleEvaluationFixMethod represents a way to help satisfy the require rule
type requireRuleEvaluationFixMethod int

const (
	requireRuleEvaluationFixMethodAdd requireRuleEvaluationFixMethod = iota
	requireRuleEvaluationFixMethodFix
	requireRuleEvaluationFixMethodUpdate
)

// requireRuleEvaluationFix represents a fix option for a require rule evaluation
type requireRuleEvaluationFix struct {
	fixMethod requireRuleEvaluationFixMethod

	actionName string

	actionVersionConstraint string
}

func (re *requireRuleEvaluationResult) passed() bool {
	return re.satisfied
}

func (re *requireRuleEvaluationResult) explain() string {
	s := ""
	if !re.satisfied {
		s = fmt.Sprintf("Require rule \"%s\" not satisfied:\n", re.ruleName)
	} else {
		s = fmt.Sprintf("Require rule \"%s\" satisfied:\n", re.ruleName)
	}
	s += fmt.Sprintf("-> %d / %d requisites met\n", re.numberSatisfied, re.numberRequired)
	if re.satisfied {
		return s
	}
	s += fmt.Sprintf("-> To resolve, do %d of the following:\n", re.numberRequired-re.numberSatisfied)
	for _, fix := range re.fixes {
		s += fmt.Sprintf("     - %s\n", fix.string())
	}
	return s
}

func (rf *requireRuleEvaluationFix) string() string {
	switch rf.fixMethod {
	case requireRuleEvaluationFixMethodAdd:
		return fmt.Sprintf("Add Action \"%s\" with version satisfying \"%s\"", rf.actionName, rf.actionVersionConstraint)
	case requireRuleEvaluationFixMethodFix:
		return fmt.Sprintf("Fix failing Action \"%s\"", rf.actionName)
	case requireRuleEvaluationFixMethodUpdate:
		return fmt.Sprintf("Update Action \"%s\" to version satisfying \"%s\"", rf.actionName, rf.actionVersionConstraint)
	default:
		return "unknown require rule eval fix"
	}
}
