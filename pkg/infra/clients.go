package infra

import "github.com/m-mizutani/vulnivore/pkg/domain/interfaces"

type Clients struct {
	db    interfaces.Database
	ghApp interfaces.GitHubApp
}

func New(options ...Option) *Clients {
	c := &Clients{}

	for _, opt := range options {
		opt(c)
	}

	return c
}

func (x *Clients) Database() interfaces.Database   { return x.db }
func (x *Clients) GitHubApp() interfaces.GitHubApp { return x.ghApp }

type Option func(*Clients)

func WithDB(db interfaces.Database) Option {
	return func(c *Clients) {
		c.db = db
	}
}

func WithGitHubApp(ghApp interfaces.GitHubApp) Option {
	return func(c *Clients) {
		c.ghApp = ghApp
	}
}