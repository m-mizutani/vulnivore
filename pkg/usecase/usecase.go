package usecase

import (
	"github.com/m-mizutani/vulnivore/pkg/domain/interfaces"
	"github.com/m-mizutani/vulnivore/pkg/infra"
)

type useCase struct {
	clients *infra.Clients
}

func New(clients *infra.Clients) interfaces.UseCase {
	return &useCase{
		clients: clients,
	}
}
