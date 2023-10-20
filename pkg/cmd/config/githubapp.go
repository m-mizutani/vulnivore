package config

import (
	"github.com/m-mizutani/vulnivore/pkg/domain/interfaces"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/m-mizutani/vulnivore/pkg/infra/githubapp"
	"github.com/urfave/cli/v2"
)

type GitHubApp struct {
	cfg model.GitHubApp
}

func (x *GitHubApp) Flags() []cli.Flag {
	const category = "GitHub App"
	return []cli.Flag{
		&cli.Int64Flag{
			Category:    category,
			Name:        "github-app-id",
			Usage:       "GitHub App ID",
			Destination: &x.cfg.AppID,
			EnvVars:     []string{"VULNIVORE_GITHUB_APP_ID"},
			Required:    true,
		},
		&cli.Int64Flag{
			Category:    category,
			Name:        "github-installation-id",
			Usage:       "GitHub App Installation ID",
			Destination: &x.cfg.InstallID,
			EnvVars:     []string{"VULNIVORE_GITHUB_APP_INSTALLATION_ID"},
			Required:    true,
		},
		&cli.StringFlag{
			Category:    category,
			Name:        "github-private-key",
			Usage:       "GitHub App Private Key",
			Destination: (*string)(&x.cfg.PrivateKey),
			EnvVars:     []string{"VULNIVORE_GITHUB_APP_PRIVATE_KEY"},
			Required:    true,
		},
		&cli.StringFlag{
			Category:    category,
			Name:        "github-secret",
			Usage:       "GitHub App secret",
			Destination: (*string)(&x.cfg.WebhookSecret),
			EnvVars:     []string{"VULNIVORE_GITHUB_APP_SECRET"},
		},
	}
}

func (x *GitHubApp) NewClient() (interfaces.GitHubApp, error) {
	return githubapp.New(&x.cfg)
}
