package server

import (
	"net/http"
	"strconv"
	"strings"

	"log/slog"

	"github.com/google/uuid"
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
		logger := utils.Logger().With("request_id", uuid.NewString())
		ctx := toVulnivoreContext(r.Context()).New(
			model.WithLogger(logger),
		)

		sw := &statusWriter{ResponseWriter: w}

		next.ServeHTTP(sw, r.WithContext(ctx))
		logger.Info("http access",
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

type validateFunc func(ctx *model.Context, token string) (*model.GitHubActionContext, error)

func authGitHubAction(validate validateFunc) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := toVulnivoreContext(r.Context())

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
			if len(authVal[1]) == 0 {
				respondError(w, http.StatusUnauthorized, "token is empty")
				return
			}

			repo, err := validate(ctx, authVal[1])
			if err != nil {
				utils.Logger().Warn("failed to parse JWT", slog.Any("err", err))
				respondError(w, http.StatusUnauthorized, "invalid GitHub ID token")
				return
			}
			ctx.Logger().Info("GitHub ID token is verified", slog.Any("repo", repo))

			ctx = ctx.New(model.WithGitHubActionContext(repo))

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func githubAppInstallationID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := toVulnivoreContext(r.Context())

		if v := r.Header.Get("X-Vulnivore-Installation-ID"); v != "" {
			id, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				respondError(w, http.StatusBadRequest, "X-Vulnivore-Installation-ID must be integer")
			}
			ctx = ctx.New(model.WithGitHubInstallationID(id))
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
