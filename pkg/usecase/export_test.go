package usecase

import "text/template"

var (
	ResultSarifToIssueContents = resultSarifToIssueContents
)

func DefaultSarifIssueBodyTmpl() *template.Template {
	return defaultSarifIssueBodyTmpl
}

var (
	BuildTrivyVulnContents = buildTrivyVulnContents
)

func DefaultTrivyLangPkgTmpl() *template.Template {
	return defaultTrivyLangPkgTmpl
}
func DefaultTrivyOSPkgTmpl() *template.Template {
	return defaultTrivyOSPkgTmpl
}
