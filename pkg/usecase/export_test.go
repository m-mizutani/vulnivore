package usecase

import "text/template"

var (
	ResultSarifToIssueContents = resultSarifToIssueContents
	BuildTrivyVulnContents     = buildTrivyVulnContents
)

func DefaultSarifIssueBodyTmpl() *template.Template {
	return defaultSarifIssueBodyTmpl
}
func DefaultTrivyLangPkgTmpl() *template.Template {
	return defaultTrivyLangPkgTemplate
}
func DefaultTrivyOSPkgTmpl() *template.Template {
	return defaultTrivyOSPkgTemplate
}
