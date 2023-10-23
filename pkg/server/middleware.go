package server

import (
	"net/http"
	"strconv"
	"strings"

	"log/slog"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/m-mizutani/goerr"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/m-mizutani/vulnivore/pkg/utils"
)

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (x *statusWriter) WriteHeader(status int) {
	x.status = status
	x.ResponseWriter.WriteHeader(status)
}

func accessLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}

		next.ServeHTTP(sw, r)
		utils.Logger().Info("http access",
			slog.Int("status", sw.status),
			slog.String("method", r.Method),
			slog.String("remote", r.RemoteAddr),
			slog.Any("path", r.URL.Path),
			slog.Any("query", r.URL.Query()),
		)
	})
}

func respondError(w http.ResponseWriter, status int, msg string) {
	data := map[string]string{
		"error": msg,
	}
	w.WriteHeader(status)
	utils.SafeMarshal(w, data)
}

func authGitHubAction(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		authHdr := r.Header.Get("Authorization")
		if authHdr == "" {
			respondError(w, http.StatusUnauthorized, "Authorization header is missing")
			return
		}

		authVal := strings.SplitN(authHdr, " ", 2)
		if len(authVal) != 2 {
			respondError(w, http.StatusUnauthorized, "invalid Authorization header")
			return
		}

		if strings.ToLower(authVal[0]) != "bearer" {
			respondError(w, http.StatusUnauthorized, "authorization type is not bearer")
			return
		}

		set, err := jwk.Fetch(r.Context(), "https://token.actions.githubusercontent.com/.well-known/jwks")
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to fetch JWK")
			return
		}

		tok, err := jwt.Parse([]byte(authVal[1]), jwt.WithKeySet(set))
		if err != nil {
			utils.Logger().Warn("failed to parse JWT", slog.Any("err", err))
			respondError(w, http.StatusUnauthorized, "failed to parse JWT")
			return
		}

		repo, err := token2GitHubRepo(tok)
		if err != nil {
			utils.Logger().Warn("failed to parse JWT", slog.Any("err", err))
			respondError(w, http.StatusUnauthorized, "failed to parse JWT")
			return
		}

		ctx := model.NewContext(
			model.WithContext(r.Context()),
			model.WithGitHubRepo(repo),
		)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func token2GitHubRepo(tok jwt.Token) (*model.GitHubRepo, error) {
	var repo model.GitHubRepo

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

	return &repo, nil
}
