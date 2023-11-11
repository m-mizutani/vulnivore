package model

import (
	"context"

	"log/slog"

	"github.com/m-mizutani/vulnivore/pkg/utils"
)

type Context struct {
	context.Context
	actionCtx *GitHubActionContext
	installID int64
	logger    *slog.Logger
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

func (x *Context) GitHubActionContext() *GitHubActionContext {
	if x.actionCtx == nil {
		return nil
	}
	copied := *x.actionCtx
	return &copied
}
func (x *Context) GitHubInstallID() int64 { return x.installID }
func (x *Context) Logger() *slog.Logger   { return x.logger }

type CtxOption func(*Context)

func WithContext(ctx context.Context) CtxOption {
	return func(c *Context) {
		c.Context = ctx
	}
}

func WithGitHubActionContext(repo *GitHubActionContext) CtxOption {
	return func(c *Context) {
		c.actionCtx = repo
	}
}

func WithGitHubInstallationID(id int64) CtxOption {
	return func(c *Context) {
		c.installID = id
	}
}

func WithLogger(logger *slog.Logger) CtxOption {
	return func(c *Context) {
		c.logger = logger
	}
}
