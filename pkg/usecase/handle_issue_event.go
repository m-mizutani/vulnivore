package usecase

import (
	"net/http"

	"github.com/google/go-github/v56/github"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
)

func (x *useCase) ValidateGitHubEvent(r *http.Request) ([]byte, error) {
	return x.clients.GitHubApp().ValidateEventPayload(r)
}

func (x *useCase) HandleIssueEvent(ctx *model.Context, event *github.IssueEvent) error {
	return nil
}
