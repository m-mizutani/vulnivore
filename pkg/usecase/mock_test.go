package usecase_test

import (
	"net/http"

	"github.com/google/go-github/v56/github"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
)

type dbMock struct {
	getVulnRecords func(ctx *model.Context, repoID model.GitHubRepoID) (model.VulnRecords, error)
	putVulnRecords func(ctx *model.Context, vulns []model.VulnRecord) error
}

func (x *dbMock) GetVulnRecords(ctx *model.Context, repoID model.GitHubRepoID) (model.VulnRecords, error) {
	return x.getVulnRecords(ctx, repoID)
}

func (x *dbMock) PutVulnRecords(ctx *model.Context, vulns []model.VulnRecord) error {
	return x.putVulnRecords(ctx, vulns)
}

type ghAppMock struct {
	createIssue          func(ctx *model.Context, issue *model.GitHubIssue) (*github.Issue, error)
	validateEventPayload func(r *http.Request) ([]byte, error)
}

func (x *ghAppMock) ValidateEventPayload(r *http.Request) ([]byte, error) {
	return x.validateEventPayload(r)
}

func (x *ghAppMock) CreateIssue(ctx *model.Context, issue *model.GitHubIssue) (*github.Issue, error) {
	return x.createIssue(ctx, issue)
}
