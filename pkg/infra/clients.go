package infra

import (
	"github.com/m-mizutani/vulnivore/pkg/domain/interfaces"
	"github.com/m-mizutani/vulnivore/pkg/infra/policy"
)

type Clients struct {
	db     interfaces.Database
	ghApp  interfaces.GitHubApp
	policy interfaces.Policy
}

func New(options ...Option) *Clients {
	emptyPolicy, err := policy.New()
	if err != nil {
		panic(err)
	}

	c := &Clients{
		policy: emptyPolicy,
	}

	for _, opt := range options {
		opt(c)
	}

	return c
}

func (x *Clients) Database() interfaces.Database   { return x.db }
func (x *Clients) GitHubApp() interfaces.GitHubApp { return x.ghApp }
func (x *Clients) Policy() interfaces.Policy       { return x.policy }

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

func WithPolicy(policy interfaces.Policy) Option {
	return func(c *Clients) {
		c.policy = policy
	}
}
