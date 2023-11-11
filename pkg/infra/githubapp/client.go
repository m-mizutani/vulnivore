package githubapp

import (
	"net/http"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v56/github"
	"github.com/m-mizutani/goerr"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
)

type client struct {
	cfg *model.GitHubApp
}

func New(cfg *model.GitHubApp) (*client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &client{
		cfg: cfg,
	}, nil
}

func (x *client) setupClient(ctx *model.Context) (*github.Client, error) {
	installID := x.cfg.InstallID.Int64()
	if v := ctx.GitHubInstallID(); v > 0 {
		installID = v
	}

	tr := http.DefaultTransport
	itr, err := ghinstallation.New(tr, x.cfg.AppID.Int64(), installID, x.cfg.PrivateKey.Byte())
	if err != nil {
		return nil, goerr.Wrap(err, "Failed to create GitHub App client").With("cfg", x.cfg)
	}

	return github.NewClient(&http.Client{Transport: itr}), nil
}

func (x *client) ValidateEventPayload(r *http.Request) ([]byte, error) {
	payload, err := github.ValidatePayload(r, []byte(x.cfg.WebhookSecret))
	if err != nil {
		return nil, goerr.Wrap(err, "validating payload")
	}

	return payload, nil
}

func (x *client) CreateIssue(ctx *model.Context, issue *model.GitHubIssue) (*github.Issue, error) {
	client, err := x.setupClient(ctx)
	if err != nil {
		return nil, err
	}

	// Create an issue
	input := &github.IssueRequest{
		Title: github.String(issue.Title),
		Body:  github.String(issue.Body),
	}
	if len(issue.Assignees) > 0 {
		input.Assignees = &issue.Assignees
	}
	if len(issue.Labels) > 0 {
		input.Labels = &issue.Labels
	}

	resp, _, err := client.Issues.Create(ctx, issue.Owner, issue.Name, input)
	if err != nil {
		return nil, goerr.Wrap(err, "Failed to create GitHub issue")
	}

	return resp, nil
}

func (x *client) CloseIssue(ctx *model.Context, repo *model.GitHubRepo, issueNo int) error {
	client, err := x.setupClient(ctx)
	if err != nil {
		return err
	}

	// Close an issue
	input := &github.IssueRequest{
		State: github.String("closed"),
	}

	_, _, err = client.Issues.Edit(ctx, repo.Owner, repo.Name, issueNo, input)
	if err != nil {
		return goerr.Wrap(err, "Failed to close GitHub issue")
	}

	return nil
}

func (x *client) GetMetaData(ctx *model.Context, repo *model.GitHubRepo) (*github.Repository, error) {
	client, err := x.setupClient(ctx)
	if err != nil {
		return nil, err
	}

	resp, _, err := client.Repositories.Get(ctx, repo.Owner, repo.Name)
	if err != nil {
		return nil, goerr.Wrap(err, "Failed to get GitHub repository").With("repo", repo)
	}

	return resp, nil
}

func (x *client) GetWorkflowRun(ctx *model.Context, repo *model.GitHubRepo, runID int64) (*github.WorkflowRun, error) {
	client, err := x.setupClient(ctx)
	if err != nil {
		return nil, err
	}

	run, _, err := client.Actions.GetWorkflowRunByID(ctx, repo.Owner, repo.Name, runID)
	if err != nil {
		return nil, goerr.Wrap(err, "Failed to get GitHub workflow runs").With("repo", repo)
	}

	return run, nil
}

func (x *client) CreatePullRequestComment(ctx *model.Context, repo *model.GitHubRepo, prNo int, body string) error {
	client, err := x.setupClient(ctx)
	if err != nil {
		return err
	}

	input := &github.PullRequestComment{
		Body: github.String(body),
	}

	_, _, err = client.PullRequests.CreateComment(ctx, repo.Owner, repo.Name, prNo, input)
	if err != nil {
		return goerr.Wrap(err, "Failed to create GitHub pull request comment")
	}

	return nil
}
