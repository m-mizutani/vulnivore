package model

import "github.com/m-mizutani/goerr"

type GitHubApp struct {
	AppID         GitHubAppID
	InstallID     GitHubAppInstallID
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
	RepoID GitHubRepoID
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
