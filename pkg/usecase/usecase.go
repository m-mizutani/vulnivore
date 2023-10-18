package usecase

import (
	"github.com/m-mizutani/vulsink/pkg/domain/interfaces"
	"github.com/m-mizutani/vulsink/pkg/infra"
)

type useCase struct {
	clients *infra.Clients
}

func New(clients *infra.Clients) interfaces.UseCase {
	return &useCase{
		clients: clients,
	}
}
