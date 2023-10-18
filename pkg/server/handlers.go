package server

import (
	"net/http"

	"github.com/m-mizutani/vulsink/pkg/domain/interfaces"
)

func hello(uc interfaces.UseCase, req *http.Request) (*apiResponse, error) {
	return &apiResponse{
		data: "hello",
	}, nil
}
