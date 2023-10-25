package usecase_test

import (
	"net/http"

	"github.com/google/go-github/v56/github"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
)

type dbMock struct {
	getVulnRecordsCount int
	getVulnRecords      func(ctx *model.Context, repoID model.GitHubRepoID) (model.VulnRecords, error)

	putVulnRecordsCount int
	putVulnRecords      func(ctx *model.Context, vulns []model.VulnRecord) error

	records []model.VulnRecord
}

func (x *dbMock) GetVulnRecords(ctx *model.Context, repoID model.GitHubRepoID) (model.VulnRecords, error) {
	x.getVulnRecordsCount++

	if result, err := x.getVulnRecords(ctx, repoID); result != nil || err != nil {
		return result, err
	}

	var resp []model.VulnRecord
	for _, r := range x.records {
		if r.RepoID == repoID {
			resp = append(resp, r)
		}
	}
	return resp, nil
}

func (x *dbMock) PutVulnRecords(ctx *model.Context, vulns []model.VulnRecord) error {
	x.putVulnRecordsCount++
	x.records = append(x.records, vulns...)
	return x.putVulnRecords(ctx, vulns)
}

type ghAppMock struct {
	createIssueCount          int
	createIssue               func(ctx *model.Context, issue *model.GitHubIssue) (*github.Issue, error)
	closeIssueCount           int
	closeIssue                func(ctx *model.Context, repo *model.GitHubRepo, issueNo int) error
	validateEventPayloadCount int
	validateEventPayload      func(r *http.Request) ([]byte, error)
}

func (x *ghAppMock) ValidateEventPayload(r *http.Request) ([]byte, error) {
	x.validateEventPayloadCount++
	return x.validateEventPayload(r)
}

func (x *ghAppMock) CreateIssue(ctx *model.Context, issue *model.GitHubIssue) (*github.Issue, error) {
	x.createIssueCount++
	return x.createIssue(ctx, issue)
}

func (x *ghAppMock) CloseIssue(ctx *model.Context, repo *model.GitHubRepo, issueNo int) error {
	x.closeIssueCount++
	return x.closeIssue(ctx, repo, issueNo)
}
