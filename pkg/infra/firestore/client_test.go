package firestore_test

import (
	"math/rand"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/m-mizutani/vulnivore/pkg/infra/firestore"
)

func TestFirestorePutAndGet(t *testing.T) {
	if _, ok := os.LookupEnv("ENABLE_FIRESTORE_TEST"); !ok {
		t.Skip("ENABLE_FIRESTORE_TEST is not set")
	}

	projectID, ok := os.LookupEnv("TEST_FIRESTORE_PROJECT_ID")
	gt.B(t, ok).True()
	collection, ok := os.LookupEnv("TEST_FIRESTORE_COLLECTION")
	gt.B(t, ok).True()

	ctx := model.NewContext()
	client := gt.R1(firestore.New(ctx, projectID, collection)).NoError(t)

	repo1 := model.GitHubRepoID(rand.Intn(999999999))
	repo2 := model.GitHubRepoID(rand.Intn(999999999))

	records := []model.VulnRecord{
		{
			VulnRecordKey: model.VulnRecordKey{
				RepoID:   repo1,
				VulnID:   "CVE-1890-1234",
				Location: uuid.NewString(),
			},
			Owner:    "m-mizutani",
			RepoName: "zatsu",
			IssueID:  2,
		},
		{
			VulnRecordKey: model.VulnRecordKey{
				RepoID:   repo1,
				VulnID:   "CVE-1890-5678",
				Location: uuid.NewString(),
			},
			Owner:    "m-mizutani",
			RepoName: "zatsu",
			IssueID:  3,
		},
		{
			VulnRecordKey: model.VulnRecordKey{
				RepoID:   repo2,
				VulnID:   "CVE-1999-0731",
				Location: uuid.NewString(),
			},
			Owner:    "m-mizutani",
			RepoName: "zatsu",
			IssueID:  4,
		},
	}

	gt.NoError(t, client.PutVulnRecords(ctx, records))

	resp1 := gt.R1(client.GetVulnRecords(ctx, repo1)).NoError(t)
	gt.A(t, resp1).Length(2).
		Have(records[0]).
		Have(records[1]).
		NotHave(records[2])

	resp2 := gt.R1(client.GetVulnRecords(ctx, repo2)).NoError(t)
	gt.A(t, resp2).Length(1).
		NotHave(records[0]).
		NotHave(records[1]).
		Have(records[2])

	resp3 := gt.R1(client.GetVulnRecordsByIssueID(ctx, repo1, 3)).NoError(t)
	gt.A(t, resp3).Length(1).
		NotHave(records[0]).
		Have(records[1]).
		NotHave(records[2])
}
