package model

import "context"

type Context struct {
	context.Context
	repo *GitHubRepo
}

func NewContext(options ...CtxOption) *Context {
	ctx := &Context{
		Context: context.Background(),
	}

	for _, opt := range options {
		opt(ctx)
	}
	return ctx
}

func (x *Context) GitHubRepo() *GitHubRepo { return x.repo }

type CtxOption func(*Context)

func WithContext(ctx context.Context) CtxOption {
	return func(c *Context) {
		c.Context = ctx
	}
}

func WithGitHubRepo(repo *GitHubRepo) CtxOption {
	return func(c *Context) {
		c.repo = repo
	}
}
