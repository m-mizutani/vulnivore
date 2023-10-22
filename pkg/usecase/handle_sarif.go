package usecase

import (
	_ "embed"

	"bytes"
	"fmt"
	"text/template"

	"github.com/m-mizutani/goerr"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/securego/gosec/v2/report/sarif"
)

func (x *useCase) HandleSarif(ctx *model.Context, report *sarif.Report) error {
	repo := ctx.GitHubRepo()
	if repo == nil {
		return goerr.Wrap(model.ErrInvalidContext, "GitHub repository is not set")
	}

	existsRecords, err := x.clients.Database().GetVulnRecords(ctx, repo.RepoID)
	if err != nil {
		return err
	}

	var newRecords []model.VulnRecord
	for _, run := range report.Runs {
		for _, result := range run.Results {
			for _, loc := range result.Locations {
				key := model.VulnRecordKey{
					RepoID:   repo.RepoID,
					VulnID:   result.RuleID,
					Location: loc.Message.Text,
				}
				existsRecord := existsRecords.Find(key)
				if existsRecord != nil {
					continue
				}

				contents, err := resultToIssueContents(defaultIssueBodyTmpl, run.Tool, result)
				if err != nil {
					return err
				}

				issue := &model.GitHubIssue{
					GitHubRepo:          *repo,
					GitHubIssueContents: *contents,
				}

				newIssue, err := x.clients.GitHubApp().CreateIssue(ctx, issue)
				if err != nil {
					return err
				}

				newRecords = append(newRecords, model.VulnRecord{
					VulnRecordKey: key,

					Owner:         repo.Owner,
					RepoName:      repo.Name,
					GitHubIssueID: newIssue.GetNumber(),
				})
			}
		}
	}

	if err := x.clients.Database().PutVulnRecords(ctx, newRecords); err != nil {
		return err
	}

	return nil
}

//go:embed templates/github_issue_body.md
var githubIssueBodyTmpl string

var defaultIssueBodyTmpl *template.Template

func init() {
	defaultIssueBodyTmpl = template.Must(template.New("issue").Parse(githubIssueBodyTmpl))
}

func resultToIssueContents(tmpl *template.Template, tool *sarif.Tool, result *sarif.Result) (*model.GitHubIssueContents, error) {
	rule := tool.Driver.Rules[result.RuleIndex]
	input := struct {
		Tool   *sarif.Tool
		Rule   *sarif.ReportingDescriptor
		Result *sarif.Result
	}{
		Tool:   tool,
		Rule:   rule,
		Result: result,
	}

	var body bytes.Buffer
	if err := tmpl.Execute(&body, input); err != nil {
		return nil, goerr.Wrap(err, "Failed to execute template")
	}

	var loc string
	if len(result.Locations) > 0 {
		loc = result.Locations[0].Message.Text
	}

	return &model.GitHubIssueContents{
		Title: fmt.Sprintf("%s: %s: %s", rule.ID, loc, rule.ShortDescription.Text),
		Body:  body.String(),
	}, nil
}
