package usecase_test

import (
	_ "embed"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/go-github/v56/github"
	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/vulnivore/pkg/domain/interfaces"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/m-mizutani/vulnivore/pkg/infra"
	"github.com/m-mizutani/vulnivore/pkg/usecase"
	"github.com/securego/gosec/v2/report/sarif"
)

//go:embed testdata/postgres.sarif.json
var sarifPostgresReport []byte

//go:embed testdata/ghaudit.sarif.json
var sarifGHAuditReport []byte

func TestResultToIssueContents(t *testing.T) {
	var report sarif.Report
	gt.NoError(t, json.Unmarshal(sarifPostgresReport, &report))
	gt.A(t, report.Runs).Length(1).At(0, func(t testing.TB, v *sarif.Run) {
		gt.Equal(t, v.Tool.Driver.Name, "Trivy")
	})

	issue := gt.R1(usecase.ResultToIssueContents(usecase.DefaultIssueBodyTmpl(), report.Runs[0].Tool, report.Runs[0].Results[0])).NoError(t)
	gt.Equal(t, issue.Title, "CVE-2011-3374: library/postgres: apt@2.2.4: It was found that apt-key in apt, all versions, do not correctly valid ...")
	gt.S(t, issue.Body).
		Contains("library/postgres: apt@2.2.4").
		Contains("https://avd.aquasec.com/nvd/cve-2011-3374")

	// for DEBUG
	gt.NoError(t, os.WriteFile("out/postgres.sarif.body.md", []byte(issue.Body), 0644))
}

func TestHandleSarif(t *testing.T) {
	testCases := map[string]struct {
		countIssueCreate    int
		putShouldContain    []model.VulnRecord
		putShouldNotContain []model.VulnRecord
		getWillReturn       []model.VulnRecord
	}{
		"first push": {
			countIssueCreate: 6,
			putShouldContain: []model.VulnRecord{
				{
					VulnRecordKey: model.VulnRecordKey{
						RepoID:   4321,
						VulnID:   "CVE-2022-28948",
						Location: "ghaudit: gopkg.in/yaml.v3@v3.0.0-20210107192922-496545a6307b",
					},
					Owner:      "m-mizutani",
					RepoName:   "vulnivore",
					IssueID:    42,
					IssueState: "open",
				},
			},
			getWillReturn: []model.VulnRecord{},
		},
		"ignore existing record": {
			countIssueCreate: 5,
			putShouldNotContain: []model.VulnRecord{
				{
					VulnRecordKey: model.VulnRecordKey{
						RepoID:   4321,
						VulnID:   "CVE-2022-28948",
						Location: "ghaudit: gopkg.in/yaml.v3@v3.0.0-20210107192922-496545a6307b",
					},
					Owner:      "m-mizutani",
					RepoName:   "vulnivore",
					IssueID:    42,
					IssueState: "open",
				},
			},
			getWillReturn: []model.VulnRecord{
				{
					VulnRecordKey: model.VulnRecordKey{
						RepoID:   4321,
						VulnID:   "CVE-2022-28948",
						Location: "ghaudit: gopkg.in/yaml.v3@v3.0.0-20210107192922-496545a6307b",
					},
					Owner:      "m-mizutani",
					RepoName:   "vulnivore",
					IssueID:    42,
					IssueState: "open",
				},
			},
		},
	}

	for title, tc := range testCases {
		t.Run(title, func(t *testing.T) {
			var calledGet, calledPut int
			foundRecords := map[model.VulnRecordKey]struct{}{}
			dbClient := &dbMock{
				getVulnRecords: func(ctx *model.Context, repoID model.GitHubRepoID) (model.VulnRecords, error) {
					calledGet++
					gt.Equal(t, repoID, 4321)
					return tc.getWillReturn, nil
				},
				putVulnRecords: func(ctx *model.Context, vulns []model.VulnRecord) error {
					calledPut++
					at := gt.A(t, vulns).Length(1)

					for _, v := range tc.putShouldContain {
						if vulns[0].VulnRecordKey == v.VulnRecordKey {
							gt.Equal(t, vulns[0], v)
							foundRecords[v.VulnRecordKey] = struct{}{}
						}
					}
					for _, v := range tc.putShouldNotContain {
						at.NotHave(v)
					}
					return nil
				},
			}

			var calledCreateIssue int
			ghApp := &ghAppMock{
				createIssue: func(ctx *model.Context, issue *model.GitHubIssue) (*github.Issue, error) {
					calledCreateIssue++
					issueID := 199
					if strings.Contains(issue.Body, "CVE-2022-28948") {
						issueID = 42
					}

					return &github.Issue{
						Number: &issueID,
					}, nil
				},
			}

			uc := usecase.New(infra.New(
				infra.WithDB(dbClient),
				infra.WithGitHubApp(ghApp),
			))

			var report sarif.Report
			gt.NoError(t, json.Unmarshal(sarifGHAuditReport, &report))

			ctx := model.NewContext(
				model.WithGitHubRepo(&model.GitHubRepo{
					RepoID: 4321,
					Owner:  "m-mizutani",
					Name:   "vulnivore",
				}),
			)

			gt.NoError(t, uc.HandleSarif(ctx, &report))
			gt.Equal(t, calledGet, 1)
			gt.Equal(t, calledPut, tc.countIssueCreate)
			gt.Equal(t, calledCreateIssue, tc.countIssueCreate)
			gt.M(t, foundRecords).Length(len(tc.putShouldContain))
		})
	}
}

type testSuite struct {
	uc       interfaces.UseCase
	dbClient *dbMock
	ghApp    *ghAppMock
}

func setupTestSuite(t *testing.T) *testSuite {
	dbClient := &dbMock{
		getVulnRecords: func(ctx *model.Context, repoID model.GitHubRepoID) (model.VulnRecords, error) {
			return nil, nil
		},
		putVulnRecords: func(ctx *model.Context, vulns []model.VulnRecord) error {
			return nil
		},
	}
	ghApp := &ghAppMock{
		createIssue: func(ctx *model.Context, issue *model.GitHubIssue) (*github.Issue, error) {
			no := rand.Intn(100000)
			return &github.Issue{
				Number: &no,
			}, nil
		},
		closeIssue: func(ctx *model.Context, repo *model.GitHubRepo, issueNo int) error {
			return nil
		},
		validateEventPayload: func(r *http.Request) ([]byte, error) {
			data, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			return data, nil
		},
	}

	uc := usecase.New(infra.New(
		infra.WithDB(dbClient),
		infra.WithGitHubApp(ghApp),
	))

	return &testSuite{
		uc:       uc,
		dbClient: dbClient,
		ghApp:    ghApp,
	}
}

func TestCloseResolvedVuln(t *testing.T) {
	ts := setupTestSuite(t)

	var report sarif.Report
	gt.NoError(t, json.Unmarshal(sarifGHAuditReport, &report))

	ctx := model.NewContext(
		model.WithGitHubRepo(&model.GitHubRepo{
			RepoID: 4321,
			Owner:  "m-mizutani",
			Name:   "ghaudit",
		}),
	)

	var targetIssueNo int
	ts.ghApp.createIssue = func(ctx *model.Context, issue *model.GitHubIssue) (*github.Issue, error) {
		no := rand.Intn(100000)
		if strings.Contains(issue.Title, "CVE-2022-28946") {
			t.Log("target issue no:", no)
			targetIssueNo = no
		}
		return &github.Issue{
			Number: &no,
		}, nil
	}

	t.Run("at first, create 6 issues", func(t *testing.T) {
		gt.NoError(t, ts.uc.HandleSarif(ctx, &report))
		gt.Equal(t, ts.ghApp.createIssueCount, 6)
		gt.Equal(t, ts.ghApp.closeIssueCount, 0)
	})

	t.Run("at second, no issue created and closed", func(t *testing.T) {
		gt.NoError(t, ts.uc.HandleSarif(ctx, &report))
		gt.Equal(t, ts.ghApp.createIssueCount, 6)
		gt.Equal(t, ts.ghApp.closeIssueCount, 0)
	})

	t.Run("at third, close 1 issues", func(t *testing.T) {
		println("[1]", report.Runs[0].Results[0].RuleID)
		report.Runs[0].Results = report.Runs[0].Results[1:]
		ts.ghApp.closeIssue = func(ctx *model.Context, repo *model.GitHubRepo, issueNo int) error {
			gt.Equal(t, repo.Owner, "m-mizutani")
			gt.Equal(t, repo.Name, "ghaudit")
			gt.Equal(t, issueNo, targetIssueNo)
			return nil
		}

		gt.NoError(t, ts.uc.HandleSarif(ctx, &report))
		gt.Equal(t, ts.ghApp.createIssueCount, 6)
		gt.Equal(t, ts.ghApp.closeIssueCount, 1)
	})
}
