package interfaces

import "github.com/m-mizutani/vulnivore/pkg/domain/model"

type DB interface {
}

type GitHubApp interface {
	CreateIssue(ctx *model.Context, issue *model.GitHubIssue) error
}
