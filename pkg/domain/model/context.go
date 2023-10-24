package model

import (
	"context"

	"log/slog"

	"github.com/m-mizutani/vulnivore/pkg/utils"
)

type Context struct {
	context.Context
	repo   *GitHubRepo
	logger *slog.Logger
}

func NewContext(options ...CtxOption) *Context {
	ctx := &Context{
		Context: context.Background(),
		logger:  utils.Logger(),
	}

	for _, opt := range options {
		opt(ctx)
	}
	return ctx
}

func (x *Context) New(options ...CtxOption) *Context {
	ctx := *x // shallow copy
	for _, opt := range options {
		opt(&ctx)
	}
	return &ctx
}

func (x *Context) GitHubRepo() *GitHubRepo { return x.repo }
func (x *Context) Logger() *slog.Logger    { return x.logger }

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

func WithLogger(logger *slog.Logger) CtxOption {
	return func(c *Context) {
		c.logger = logger
	}
}
