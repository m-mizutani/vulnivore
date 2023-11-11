package interfaces

import (
	"net/http"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/google/go-github/v56/github"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/securego/gosec/v2/report/sarif"
)

type UseCase interface {
	ValidateGitHubEvent(r *http.Request) ([]byte, error)
	ValidateGitHubIDToken(ctx *model.Context, token string) (*model.GitHubActionContext, error)
	HandleIssueEvent(ctx *model.Context, event *github.IssueEvent) error
	HandleSarif(ctx *model.Context, report *sarif.Report) error
	HandleTrivy(ctx *model.Context, report *types.Report) error
}
