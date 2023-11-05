package usecase

import (
	"bytes"
	_ "embed"
	"fmt"
	"text/template"

	"github.com/m-mizutani/goerr"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"

	"github.com/aquasecurity/trivy/pkg/types"
)

func (x *useCase) HandleTrivy(ctx *model.Context, report *types.Report) error {
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

	for ri, result := range report.Results {
		var tmpl *template.Template

		switch result.Class {
		case types.ClassOSPkg:
			tmpl = x.trivyOSPkgTemplate
		case types.ClassLangPkg:
			tmpl = x.trivyLangPkgTemplate
		default:
			ctx.Logger().Warn("unsupported trivy result class", "class", result.Class)
			continue
		}

		for vi, vuln := range result.Vulnerabilities {
			var recordID model.RecordID

			switch result.Class {
			case types.ClassOSPkg:
				recordID = model.TrivyOSPkgKey{
					VulnID:  vuln.VulnerabilityID,
					OSType:  string(result.Type),
					PkgName: vuln.PkgName,
				}.RecordID()

			case types.ClassLangPkg:
				recordID = model.TrivyLangPkgKey{
					VulnID:  vuln.VulnerabilityID,
					Target:  result.Target,
					PkgName: vuln.PkgName,
					PkgPath: vuln.PkgPath,
				}.RecordID()

			default:
				ctx.Logger().Warn("unsupported trivy result class", "class", result.Class)
				continue
			}

			existsRecord := existsRecords.Find(recordID)
			if existsRecord != nil {
				delete(existsRecordMap, recordID)
				continue
			}

			// Eval policy
			var evalResult model.EvalOutput
			{
				input := model.NewEvalInputTrivyVuln(*report, result, vuln)
				if err := x.clients.Policy().Query(ctx, "trivy", input, &evalResult); err != nil {
					return err
				}
				if evalResult.Action == "ignore" {
					continue // skip
				}
			}

			contents, err := buildTrivyVulnContents(
				tmpl,
				&report.Metadata,
				&report.Results[ri],
				&result.Vulnerabilities[vi],
			)
			if err != nil {
				return err
			}
			if contents == nil {
				continue // skip
			}

			issue := &model.GitHubIssue{
				GitHubRepo:          *repo,
				GitHubIssueContents: *contents,
			}
			if len(evalResult.Labels) > 0 {
				issue.Labels = evalResult.Labels
			}
			if len(evalResult.Assignees) > 0 {
				issue.Assignees = evalResult.Assignees
			}

			newIssue, err := x.clients.GitHubApp().CreateIssue(ctx, issue)
			if err != nil {
				return err
			}

			newRecord := model.VulnRecord{
				RecordID:       recordID,
				RepoID:         repo.RepoID,
				RepoName:       repo.Name,
				Owner:          repo.Owner,
				IssueID:        newIssue.GetNumber(),
				IssueState:     newIssue.GetState(),
				LastModifiedAt: vuln.LastModifiedDate,
			}
			if err := x.clients.Database().PutVulnRecords(ctx, []model.VulnRecord{newRecord}); err != nil {
				return err
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

func buildTrivyVulnContents(
	tmpl *template.Template,
	meta *types.Metadata,
	result *types.Result,
	vuln *types.DetectedVulnerability,
) (*model.GitHubIssueContents, error) {
	input := struct {
		Metadata *types.Metadata
		Result   *types.Result
		Vuln     *types.DetectedVulnerability
	}{
		Metadata: meta,
		Result:   result,
		Vuln:     vuln,
	}

	var body bytes.Buffer
	if err := tmpl.Execute(&body, input); err != nil {
		return nil, goerr.Wrap(err, "Failed to execute template")
	}

	return &model.GitHubIssueContents{
		Title: fmt.Sprintf("%s: %s", vuln.VulnerabilityID, vuln.Title),
		Body:  body.String(),
	}, nil
}
