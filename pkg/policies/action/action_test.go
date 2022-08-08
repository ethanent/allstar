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
	"strings"
	"testing"

	"github.com/gobwas/glob"
	"github.com/google/go-github/v43/github"
	"github.com/ossf/allstar/pkg/config"
	"github.com/rhysd/actionlint"
)

func TestCheck(t *testing.T) {
	type testingWorkflowMetadata struct {
		Workflow *actionlint.Workflow

		Runs []*github.WorkflowRun
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
	}{}

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
				wfs = append(wfs, &workflowMetadata{
					filename: fn,
					workflow: w.Workflow,
				})
			}
			return wfs, nil
		}

		// The testing repoSelectorMatch function only matches by name
		repoSelectorMatch = func(rs *RepoSelector, ctx context.Context, c *github.Client,
			owner, repo string, gc globCache, sc semverCache) (bool, error) {
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
			t.Errorf("Test \"%s\" (%d) failed: expect pass = %t, pass = %t", test.Name, i, test.ExpectPass, res.Pass)
		}

		for _, message := range test.ExpectMessage {
			if !strings.Contains(res.NotifyText, message) {
				t.Errorf("Test \"%s\" (%d) failed: \"%s\" does not contain \"%s\"", test.Name, i, res.Details, message)
			}
		}
	}
}
