package usecase

import "text/template"

var ResultSarifToIssueContents = resultSarifToIssueContents

func DefaultIssueBodyTmpl() *template.Template {
	return defaultIssueBodyTmpl
}
