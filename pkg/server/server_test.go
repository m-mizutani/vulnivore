package server_test

import (
	"bytes"
	_ "embed"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/vulnivore/pkg/domain/interfaces"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/m-mizutani/vulnivore/pkg/server"
)

//go:embed testdata/ghaudit.trivy.json
var trivyGHAuditReport []byte

type useCaseMock struct {
	interfaces.UseCase
	MockHandleTrivy           func(ctx *model.Context, report *types.Report) error
	MockValidateGitHubIDToken func(ctx *model.Context, token string) (*model.GitHubRepo, error)
}

func (x *useCaseMock) HandleTrivy(ctx *model.Context, report *types.Report) error {
	return x.MockHandleTrivy(ctx, report)
}
func (x *useCaseMock) ValidateGitHubIDToken(ctx *model.Context, token string) (*model.GitHubRepo, error) {
	return x.MockValidateGitHubIDToken(ctx, token)
}

func TestServerMiddleware(t *testing.T) {
	testCases := map[string]struct {
		http.Header
		expectCalled int
		expectToken  string
		expectCode   int
		expectID     int64
	}{
		"valid: without install id": {
			Header: http.Header{
				"Authorization": []string{"Bearer gh_token"},
			},
			expectCalled: 1,
			expectToken:  "gh_token",
			expectCode:   http.StatusOK,
			expectID:     0,
		},
		"valid: with install id": {
			Header: http.Header{
				"Authorization":               []string{"Bearer gh_token"},
				"X-Vulnivore-Installation-ID": []string{"123"},
			},
			expectCalled: 1,
			expectToken:  "gh_token",
			expectCode:   http.StatusOK,
			expectID:     123,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var called int
			repo := &model.GitHubRepo{RepoID: 5}
			uc := &useCaseMock{
				MockValidateGitHubIDToken: func(ctx *model.Context, token string) (*model.GitHubRepo, error) {
					gt.Equal(t, token, "gh_token")
					return repo, nil
				},
				MockHandleTrivy: func(ctx *model.Context, report *types.Report) error {
					called++
					gt.Equal(t, ctx.GitHubRepo(), repo)
					gt.Equal(t, ctx.GitHubInstallID(), tc.expectID)
					return nil
				},
			}
			srv := server.New(uc)

			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/webhook/github/action/trivy",
				io.NopCloser(bytes.NewReader(trivyGHAuditReport)),
			)
			for k, v := range tc.Header {
				for _, vv := range v {
					r.Header.Add(k, vv)
				}
			}

			srv.ServeHTTP(w, r)
			gt.Equal(t, w.Code, http.StatusOK)
			gt.Equal(t, called, tc.expectCalled)
		})
	}
}
