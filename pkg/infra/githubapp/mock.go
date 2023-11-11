package githubapp

import (
	"net/http"

	"github.com/google/go-github/v56/github"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
)

type Mock struct {
	CreateIssueCount          int
	CreateIssueMock           func(ctx *model.Context, issue *model.GitHubIssue) (*github.Issue, error)
	CloseIssueCount           int
	CloseIssueMock            func(ctx *model.Context, repo *model.GitHubRepo, issueNo int) error
	ValidateEventPayloadCount int
	ValidateEventPayloadMock  func(r *http.Request) ([]byte, error)

	GetMetaDataCount    int
	GetMetaDataMock     func(ctx *model.Context, repo *model.GitHubRepo) (*github.Repository, error)
	GetWorkflowRunCount int
	GetWorkflowRunMock  func(ctx *model.Context, repo *model.GitHubRepo, runID int64) (*github.WorkflowRun, error)

	CreatePullRequestCommentCount int
	CreatePullRequestCommentMock  func(ctx *model.Context, repo *model.GitHubRepo, prNo int, body string) error
}

func (x *Mock) ValidateEventPayload(r *http.Request) ([]byte, error) {
	x.ValidateEventPayloadCount++
	return x.ValidateEventPayloadMock(r)
}

func (x *Mock) CreateIssue(ctx *model.Context, issue *model.GitHubIssue) (*github.Issue, error) {
	x.CreateIssueCount++
	return x.CreateIssueMock(ctx, issue)
}

func (x *Mock) CloseIssue(ctx *model.Context, repo *model.GitHubRepo, issueNo int) error {
	x.CloseIssueCount++
	return x.CloseIssueMock(ctx, repo, issueNo)
}

func (x *Mock) GetMetaData(ctx *model.Context, repo *model.GitHubRepo) (*github.Repository, error) {
	x.GetMetaDataCount++
	return x.GetMetaDataMock(ctx, repo)
}

func (x *Mock) GetWorkflowRun(ctx *model.Context, repo *model.GitHubRepo, runID int64) (*github.WorkflowRun, error) {
	x.GetWorkflowRunCount++
	return x.GetWorkflowRunMock(ctx, repo, runID)
}

func (x *Mock) CreatePullRequestComment(ctx *model.Context, repo *model.GitHubRepo, prNo int, body string) error {
	x.CreatePullRequestCommentCount++
	return x.CreatePullRequestCommentMock(ctx, repo, prNo, body)
}
