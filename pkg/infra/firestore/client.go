package firestore

import (
	"context"
	"fmt"

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go"
	"github.com/m-mizutani/goerr"
	"github.com/m-mizutani/vulnivore/pkg/domain/interfaces"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
)

type client struct {
	client     *firestore.Client
	collection string
}

func New(ctx *model.Context, projectID string, collection string) (*client, error) {
	conf := &firebase.Config{ProjectID: projectID}
	app, err := firebase.NewApp(ctx, conf)
	if err != nil {
		return nil, goerr.Wrap(err, "Failed to initialize firebase app")
	}

	fbClient, err := app.Firestore(ctx)
	if err != nil {
		return nil, goerr.Wrap(err, "Failed to initialize firestore client")
	}

	return &client{
		client:     fbClient,
		collection: collection,
	}, nil
}

func (x *client) Close() error {
	if err := x.client.Close(); err != nil {
		return goerr.Wrap(err, "failed to close firestore client")
	}
	return nil
}

var _ interfaces.Database = &client{}

func (x *client) GetVulnRecords(ctx *model.Context, repoID model.GitHubRepoID) (model.VulnRecords, error) {
	strID := fmt.Sprintf("%d", (repoID))

	docs, err := x.client.Collection(x.collection).Doc(strID).Collection("records").Documents(ctx).GetAll()
	if err != nil {
		return nil, goerr.Wrap(err, "failed to get vuln from firestore")
	}

	var resp []model.VulnRecord
	for _, doc := range docs {
		var vuln model.VulnRecord
		if err := doc.DataTo(&vuln); err != nil {
			return nil, goerr.Wrap(err, "failed to unmarshal vuln from firestore")
		}
		resp = append(resp, vuln)
	}

	return resp, nil
}

func (x *client) PutVulnRecords(ctx *model.Context, vulns []model.VulnRecord) error {
	colRef := x.client.Collection(x.collection)
	err := x.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		for _, vuln := range vulns {
			strID := fmt.Sprintf("%d", vuln.RepoID)
			collection := colRef.Doc(strID).Collection("records")

			doc := collection.Doc(vuln.RecordID())
			if err := tx.Create(doc, vuln); err != nil {
				return goerr.Wrap(err, "failed to create vuln")
			}
		}

		return nil
	})
	if err != nil {
		return goerr.Wrap(err, "failed firestore transaction")
	}

	return nil
}
