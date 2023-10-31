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
	existsRecordMap := make(map[model.RecordID]*model.VulnRecord, len(existsRecords))
	for i, record := range existsRecords {
		existsRecordMap[record.RecordID] = &existsRecords[i]
	}

	for _, run := range report.Runs {
		for _, result := range run.Results {
			for _, loc := range result.Locations {
				recordID := model.SarifKey{
					VulnID:   result.RuleID,
					Location: loc.Message.Text,
				}.RecordID()
				existsRecord := existsRecords.Find(recordID)
				if existsRecord != nil {
					delete(existsRecordMap, recordID)
					continue
				}

				contents, err := resultSarifToIssueContents(defaultSarifIssueBodyTmpl, run.Tool, result)
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

				newRecord := model.VulnRecord{
					RecordID: recordID,

					RepoID:     repo.RepoID,
					Owner:      repo.Owner,
					RepoName:   repo.Name,
					IssueID:    newIssue.GetNumber(),
					IssueState: newIssue.GetState(),
				}

				if err := x.clients.Database().PutVulnRecords(ctx, []model.VulnRecord{newRecord}); err != nil {
					return err
				}

			}
		}
	}

	for _, record := range existsRecordMap {
		if record.IssueState == "closed" {
			continue
		}

		if err := x.clients.GitHubApp().CloseIssue(ctx, repo, record.IssueID); err != nil {
			return err
		}
	}

	return nil
}

//go:embed templates/sarif_github_issue_body.md
var githubIssueBodyTmpl string

var defaultSarifIssueBodyTmpl *template.Template

func init() {
	defaultSarifIssueBodyTmpl = template.Must(template.New("issue").Parse(githubIssueBodyTmpl))
}

func resultSarifToIssueContents(tmpl *template.Template, tool *sarif.Tool, result *sarif.Result) (*model.GitHubIssueContents, error) {
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
