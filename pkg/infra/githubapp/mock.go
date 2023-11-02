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
