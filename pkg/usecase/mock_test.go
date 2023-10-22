package usecase_test

import (
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
	createIssue func(ctx *model.Context, issue *model.GitHubIssue) (*github.Issue, error)
}

func (x *ghAppMock) CreateIssue(ctx *model.Context, issue *model.GitHubIssue) (*github.Issue, error) {
	return x.createIssue(ctx, issue)
}
