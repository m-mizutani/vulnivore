package interfaces

import (
	"net/http"

	"github.com/google/go-github/v56/github"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
)

type Database interface {
	GetVulnRecords(ctx *model.Context, repoID model.GitHubRepoID) (model.VulnRecords, error)
	PutVulnRecords(ctx *model.Context, vulns []model.VulnRecord) error
}

type GitHubApp interface {
	CreateIssue(ctx *model.Context, issue *model.GitHubIssue) (*github.Issue, error)
	CloseIssue(ctx *model.Context, repo *model.GitHubRepo, issueNo int) error
	ValidateEventPayload(r *http.Request) ([]byte, error)

	GetMetaData(ctx *model.Context, repo *model.GitHubRepo) (*github.Repository, error)
	GetWorkflowRun(ctx *model.Context, repo *model.GitHubRepo, runID int64) (*github.WorkflowRun, error)
	CreatePullRequestComment(ctx *model.Context, repo *model.GitHubRepo, prNo int, body string) error
}

type Policy interface {
	Query(ctx *model.Context, query string, input any, output any) error
}
