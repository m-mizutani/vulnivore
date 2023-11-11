package usecase_test

import (
	_ "embed"
	"encoding/json"
	"testing"
	"text/template"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/google/go-github/v56/github"
	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/m-mizutani/vulnivore/pkg/usecase"
)

func TestTemplateOption(t *testing.T) {
	tmpl := template.Must(template.New("test").Parse("replaced template"))

	var report types.Report
	gt.NoError(t, json.Unmarshal(trivyGHAuditReport, &report))

	ts := setupTestSuite(t, usecase.WithTrivyOSPkgTemplate(tmpl))

	ctx := model.NewContext(
		model.WithGitHubActionContext(&model.GitHubActionContext{
			GitHubRepo: model.GitHubRepo{
				RepoID: 4321,
				Owner:  "m-mizutani",
				Name:   "ghaudit",
			},
		}),
	)

	var count int
	ts.ghApp.CreateIssueMock = func(ctx *model.Context, issue *model.GitHubIssue) (*github.Issue, error) {
		if count == 0 {
			gt.S(t, issue.Body).Contains("replaced template")
		}
		count++
		return &github.Issue{
			Number: &count,
		}, nil
	}

	gt.NoError(t, ts.uc.HandleTrivy(ctx, &report))
}
