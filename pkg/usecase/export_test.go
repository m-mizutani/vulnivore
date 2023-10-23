package usecase

import "text/template"

var ResultToIssueContents = resultToIssueContents

func DefaultIssueBodyTmpl() *template.Template {
	return defaultIssueBodyTmpl
}
