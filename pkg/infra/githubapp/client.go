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

func (x *client) setupClient() (*github.Client, error) {
	tr := http.DefaultTransport
	itr, err := ghinstallation.New(tr, x.cfg.AppID.Int64(), x.cfg.InstallID.Int64(), x.cfg.PrivateKey.Byte())
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
	client, err := x.setupClient()
	if err != nil {
		return nil, err
	}

	// Create an issue
	input := &github.IssueRequest{
		Title: github.String(issue.Title),
		Body:  github.String(issue.Body),
		// Assignee: github.String("username"),
		// Labels:   &[]string{"bug"},
	}

	resp, _, err := client.Issues.Create(ctx, issue.Owner, issue.Name, input)
	if err != nil {
		return nil, goerr.Wrap(err, "Failed to create GitHub issue")
	}

	return resp, nil
}
