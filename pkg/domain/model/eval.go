package model

import (
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/securego/gosec/v2/report/sarif"
)

type EvalOutput struct {
	Action    string   `json:"action"`
	Labels    []string `json:"labels"`
	Assignees []string `json:"assignees"`
}

type EvalInputTrivyVuln struct {
	Metadata *types.Metadata
	Result   *types.Result
	Vuln     *types.DetectedVulnerability
}

func NewEvalInputTrivyVuln(report types.Report, result types.Result, vuln types.DetectedVulnerability) *EvalInputTrivyVuln {
	tmpResult := types.Result{
		Target: result.Target,
		Class:  result.Class,
		Type:   result.Type,
	}
	return &EvalInputTrivyVuln{
		Metadata: &report.Metadata,
		Result:   &tmpResult,
		Vuln:     &vuln,
	}
}

type EvalInputSarif struct {
	Report   sarif.Report
	Run      sarif.Run
	Result   sarif.Result
	Location sarif.Location
}

func NewEvalInputSarif(report sarif.Report, run sarif.Run, result sarif.Result, loc sarif.Location) *EvalInputSarif {
	return &EvalInputSarif{
		Report:   report,
		Run:      run,
		Result:   result,
		Location: loc,
	}
}
