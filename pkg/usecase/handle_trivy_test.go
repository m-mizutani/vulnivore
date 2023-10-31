package usecase_test

import (
	_ "embed"
	"encoding/json"
	"os"
	"testing"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/vulnivore/pkg/usecase"
)

//go:embed testdata/ghaudit.trivy.json
var trivyGHAuditReport []byte

func TestTrivyLangPkgTemplate(t *testing.T) {
	var report types.Report
	gt.NoError(t, json.Unmarshal(trivyGHAuditReport, &report))
	gt.A(t, report.Results).Length(2).At(1, func(t testing.TB, r types.Result) {
		gt.Equal(t, r.Class, "lang-pkgs")
	})

	issue := gt.R1(usecase.BuildTrivyVulnContents(
		usecase.DefaultTrivyLangPkgTmpl(),
		&report.Metadata,
		&report.Results[1],
		&report.Results[1].Vulnerabilities[0])).NoError(t)
	gt.S(t, issue.Title).Contains("CVE-2022-28946")
	gt.NoError(t, os.WriteFile("out/ghaudit.trivy.langpkg.md", []byte(issue.Body), 0644))
}

func TestTrivyOSPkgTemplate(t *testing.T) {
	var report types.Report
	gt.NoError(t, json.Unmarshal(trivyGHAuditReport, &report))
	gt.A(t, report.Results).Length(2).At(0, func(t testing.TB, r types.Result) {
		gt.Equal(t, r.Class, "os-pkgs")
	})

	issue := gt.R1(usecase.BuildTrivyVulnContents(
		usecase.DefaultTrivyLangPkgTmpl(),
		&report.Metadata,
		&report.Results[0],
		&report.Results[0].Vulnerabilities[0])).NoError(t)
	gt.S(t, issue.Title).Contains("CVE-2021-33574")
	gt.NoError(t, os.WriteFile("out/ghaudit.trivy.ospkg.md", []byte(issue.Body), 0644))
}
