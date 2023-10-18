package infra

import "github.com/m-mizutani/vulsink/pkg/domain/interfaces"

type Clients struct {
	db interfaces.DB
}

func New(options ...Option) *Clients {
	c := &Clients{}

	for _, opt := range options {
		opt(c)
	}

	return c
}

func (x *Clients) DB() interfaces.DB { return x.db }

type Option func(*Clients)

func WithDB(db interfaces.DB) Option {
	return func(c *Clients) {
		c.db = db
	}
}
