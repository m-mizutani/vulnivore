package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/m-mizutani/vulnivore/pkg/server"
)

func TestAuthGitHubAction(t *testing.T) {
	testCases := map[string]struct {
		http.Header
		resp        *model.GitHubRepo
		err         error
		expectToken string
		expectCode  int
		expectID    int64
	}{
		"valid: without install id": {
			Header: http.Header{
				"Authorization": []string{"Bearer gh_token"},
			},
			resp: &model.GitHubRepo{
				RepoID: 5,
			},
			expectToken: "gh_token",
			expectCode:  http.StatusOK,
		},
		"valid: small case header and value": {
			Header: http.Header{
				"authorization": []string{"bearer gh_token"},
			},
			resp: &model.GitHubRepo{
				RepoID: 5,
			},
			expectToken: "gh_token",
			expectCode:  http.StatusOK,
		},
		"invalid: without auth header": {
			Header:     http.Header{},
			expectCode: http.StatusUnauthorized,
		},
		"invalid: without bearer": {
			Header: http.Header{
				"Authorization": []string{"gh_token"},
			},
			expectCode: http.StatusUnauthorized,
		},
		"invalid: without token": {
			Header: http.Header{
				"Authorization": []string{"Bearer "},
			},
			expectCode: http.StatusUnauthorized,
		},
		"invalid: basic auth": {
			Header: http.Header{
				"Authorization": []string{"Basic Z2hwX2Z1c2Vyczo="},
			},
			expectCode: http.StatusUnauthorized,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			validator := func(ctx *model.Context, token string) (*model.GitHubRepo, error) {
				gt.Equal(t, tc.expectToken, token)
				return tc.resp, tc.err
			}
			var installedID int64

			route := chi.NewRouter()
			route.Use(server.AuthGitHubAction(validator))
			route.Get("/", func(w http.ResponseWriter, r *http.Request) {
				ctx := server.ToVulnivoreContext(r.Context())
				installedID = ctx.GitHubInstallID()
				gt.Equal(t, ctx.GitHubRepo(), tc.resp)
				w.WriteHeader(http.StatusOK)
			})

			req := gt.R1(http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)).NoError(t)
			for k, v := range tc.Header {
				for _, vv := range v {
					req.Header.Set(k, vv)
				}
			}

			w := httptest.NewRecorder()
			route.ServeHTTP(w, req)
			gt.Equal(t, tc.expectCode, w.Code)
			gt.Equal(t, tc.expectID, installedID)
		})
	}
}
