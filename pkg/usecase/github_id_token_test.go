package usecase_test

import (
	"os"
	"testing"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/m-mizutani/vulnivore/pkg/infra"
	"github.com/m-mizutani/vulnivore/pkg/usecase"
)

func TestValidateGitHubIDToken(t *testing.T) {
	token, ok := os.LookupEnv("TEST_GITHUB_ID_TOKEN")
	if !ok {
		t.Skip("TEST_GITHUB_ID_TOKEN is not set")
	}
	uc := usecase.New(infra.New())
	repo := gt.R1(uc.ValidateGitHubIDToken(model.NewContext(), token)).NoError(t)
	gt.Equal(t, repo.Owner, "m-mizutani")
	gt.Equal(t, repo.Name, "vulnivore")
	gt.Equal(t, repo.RepoID, 705974143)
}
