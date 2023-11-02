package model

import "github.com/aquasecurity/trivy/pkg/types"

type EvalInputTrivyVuln struct {
	Metadata *types.Metadata
	Result   *types.Result
	Vuln     *types.DetectedVulnerability
}

type EvalOutput struct {
	Action    string   `json:"action"`
	Labels    []string `json:"labels"`
	Assignees []string `json:"assignees"`
}

func NewEvalInputTrivyVuln(report *types.Report, result *types.Result, vuln *types.DetectedVulnerability) *EvalInputTrivyVuln {
	tmpResult := types.Result{
		Target: result.Target,
		Class:  result.Class,
		Type:   result.Type,
	}
	return &EvalInputTrivyVuln{
		Metadata: &report.Metadata,
		Result:   &tmpResult,
		Vuln:     vuln,
	}
}
