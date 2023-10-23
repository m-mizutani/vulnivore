package usecase

import (
	"github.com/m-mizutani/vulnivore/pkg/domain/interfaces"
	"github.com/m-mizutani/vulnivore/pkg/infra"
)

type useCase struct {
	clients *infra.Clients
}

func New(clients *infra.Clients, options ...Option) interfaces.UseCase {
	uc := &useCase{
		clients: clients,
	}

	for _, opt := range options {
		opt(uc)
	}

	return uc
}

type Option func(*useCase)
