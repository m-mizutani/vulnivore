package server

import (
	"encoding/json"
	"net/http"

	"github.com/m-mizutani/goerr"
	"github.com/m-mizutani/vulnivore/pkg/domain/interfaces"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/securego/gosec/v2/report/sarif"
)

func hello(ctx *model.Context, uc interfaces.UseCase, req *http.Request) (*apiResponse, error) {
	return &apiResponse{
		data: "hello",
	}, nil
}

func recvGitHubActionSARIF(ctx *model.Context, uc interfaces.UseCase, req *http.Request) (*apiResponse, error) {
	var report sarif.Report
	if err := json.NewDecoder(req.Body).Decode(&report); err != nil {
		return nil, goerr.Wrap(err, "Failed to decode SARIF report")
	}

	if err := uc.HandleSarif(ctx, &report); err != nil {
		return nil, err
	}

	return &apiResponse{
		data: "ok",
	}, nil
}
