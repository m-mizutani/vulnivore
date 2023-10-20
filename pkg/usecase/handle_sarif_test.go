package usecase_test

import (
	_ "embed"
	"encoding/json"
	"os"
	"testing"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/vulnivore/pkg/usecase"
	"github.com/securego/gosec/v2/report/sarif"
)

//go:embed testdata/postgres.sarif.json
var sarifPostgresReport []byte

func TestHandleSarif(t *testing.T) {
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
