package usecase

import (
	"strconv"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/m-mizutani/goerr"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
)

func (x *useCase) ValidateGitHubIDToken(ctx *model.Context, token string) (*model.GitHubActionContext, error) {
	set, err := jwk.Fetch(ctx, "https://token.actions.githubusercontent.com/.well-known/jwks")
	if err != nil {
		return nil, goerr.Wrap(err, "failed to fetch JWK")
	}

	tok, err := jwt.Parse([]byte(token), jwt.WithKeySet(set))
	if err != nil {
		return nil, goerr.Wrap(err, "failed to parse JWT")
	}

	return token2GitHubRepo(tok)

}

func token2GitHubRepo(tok jwt.Token) (*model.GitHubActionContext, error) {
	var repo model.GitHubActionContext
	if v, ok := tok.Get("repository_id"); !ok {
		return nil, goerr.Wrap(model.ErrInvalidGitHubIDToken, "repository_id is not found")
	} else if s, ok := v.(string); !ok {
		return nil, goerr.Wrap(model.ErrInvalidGitHubIDToken, "repository_id is not string").With("repository_id", v)
	} else if repoID, err := strconv.ParseInt(s, 10, 64); err != nil {
		return nil, goerr.Wrap(model.ErrInvalidGitHubIDToken, "repository_id can not be parsed as number").With("repository_id", s)
	} else {
		repo.RepoID = model.GitHubRepoID(repoID)
	}

	if v, ok := tok.Get("repository"); !ok {
		return nil, goerr.Wrap(model.ErrInvalidGitHubIDToken, "repository is not found")
	} else if r, ok := v.(string); !ok {
		return nil, goerr.Wrap(model.ErrInvalidGitHubIDToken, "repository is not string").With("repository", v)
	} else if sep := strings.Split(r, "/"); len(sep) != 2 {
		return nil, goerr.Wrap(model.ErrInvalidGitHubIDToken, "repository format is invalid").With("repository", r)
	} else {
		repo.Owner = sep[0]
		repo.Name = sep[1]
	}

	if v, ok := tok.Get("run_id"); !ok {
		return nil, goerr.Wrap(model.ErrInvalidGitHubIDToken, "run_id is not found")
	} else if s, ok := v.(string); !ok {
		return nil, goerr.Wrap(model.ErrInvalidGitHubIDToken, "run_id is not string").With("run_id", v)
	} else if runID, err := strconv.ParseInt(s, 10, 64); err != nil {
		return nil, goerr.Wrap(model.ErrInvalidGitHubIDToken, "run_id can not be parsed as number").With("run_id", s)
	} else {
		repo.WorkflowRunID = runID
	}

	return &repo, nil
}
