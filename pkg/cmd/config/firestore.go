package config

import (
	"github.com/m-mizutani/vulnivore/pkg/domain/interfaces"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/m-mizutani/vulnivore/pkg/infra/firestore"
	"github.com/urfave/cli/v2"
)

type Firestore struct {
	projectID  string
	collection string
}

func (x *Firestore) Flags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "firestore-project-id",
			Usage:       "Firestore project ID",
			Destination: &x.projectID,
			EnvVars:     []string{"VULNIVORE_FIRESTORE_PROJECT_ID"},
			Required:    true,
		},
		&cli.StringFlag{
			Name:        "firestore-collection",
			Usage:       "Firestore collection name",
			Destination: &x.collection,
			EnvVars:     []string{"VULNIVORE_FIRESTORE_COLLECTION"},
			Required:    true,
		},
	}
}

func (x *Firestore) NewClient(ctx *model.Context) (interfaces.Database, error) {
	return firestore.New(ctx, x.projectID, x.collection)
}
