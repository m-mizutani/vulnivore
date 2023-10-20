package model

import "github.com/m-mizutani/goerr"

type (
	GitHubPrivateKey string
	GitHubSecret     string
)

func (x GitHubPrivateKey) Byte() []byte { return []byte(x) }

type GitHubApp struct {
	AppID         int64
	InstallID     int64
	PrivateKey    GitHubPrivateKey
	WebhookSecret GitHubSecret
}

func (x *GitHubApp) Validate() error {
	if x.AppID == 0 {
		return goerr.Wrap(ErrInvalidConfig, "GitHub App ID is not set")
	}
	if x.InstallID == 0 {
		return goerr.Wrap(ErrInvalidConfig, "GitHub App Installation ID is not set")
	}
	if len(x.PrivateKey) == 0 {
		return goerr.Wrap(ErrInvalidConfig, "GitHub App Private Key is not set")
	}

	return nil
}

type GitHubRepo struct {
	RepoID int64
	Owner  string
	Name   string
}

type GitHubIssue struct {
	GitHubRepo
	GitHubIssueContents
}

type GitHubIssueContents struct {
	Title string
	Body  string
}
