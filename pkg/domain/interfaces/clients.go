package interfaces

import (
	"github.com/google/go-github/v56/github"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
)

type Database interface {
	GetVulnRecords(ctx *model.Context, repoID model.GitHubRepoID) (model.VulnRecords, error)
	PutVulnRecords(ctx *model.Context, vulns []model.VulnRecord) error
}

type GitHubApp interface {
	CreateIssue(ctx *model.Context, issue *model.GitHubIssue) (*github.Issue, error)
}
