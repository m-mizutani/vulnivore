package firebase

import (
	"cloud.google.com/go/firestore"
)

type client struct {
	client     *firestore.Client
	collection string
}

/*
func New(client *firestore.Client, collection string) model.DB {
	return &client{
		client:     client,
		collection: collection,
	}
}

func (x *client) GetVuln(ctx *model.Context, repoID int64, vulnID string) (*model.Vuln, error) {
	doc, err := x.client.Collection(x.collection).Doc(repoID).Collection("vulns").Doc(vulnID).Get(ctx)
	if err != nil {
		return nil, goerr.Wrap(err, "failed to get vuln from firestore")
	}

	var vuln model.Vuln
	if err := doc.DataTo(&vuln); err != nil {
		return nil, goerr.Wrap(err, "failed to unmarshal vuln from firestore")
	}

	return &vuln, nil
}
*/

/*
const (
	attrKeyPrefix = "attr:"
	lockKeyPrefix = "lock:"
)

func hashNamespace(input types.Namespace) string {
	hash := sha512.New()
	hash.Write([]byte(input))
	hashed := hash.Sum(nil)
	return hex.EncodeToString(hashed)
}

// GetAttrs implements interfaces.Database.
func (x *Client) GetAttrs(ctx *model.Context, ns types.Namespace) (model.Attributes, error) {
	key := attrKeyPrefix + hashNamespace(ns)
	docs, err := x.client.Collection(x.collection).Doc(key).Collection("attributes").Documents(ctx).GetAll()
	if err != nil {
		return nil, goerr.Wrap(err, "failed to get attributes from firestore")
	}

	now := time.Now().UTC()
	var attrs model.Attributes
	for _, doc := range docs {
		if !doc.Exists() {
			continue
		}

		var attr attribute
		if err := doc.DataTo(&attr); err != nil {
			return nil, goerr.Wrap(err, "failed to unmarshal attribute from firestore")
		}
		if attr.ExpiresAt.Before(now) {
			continue
		}
		attrs = append(attrs, attr.Attribute)
	}

	return attrs, nil
}

// PutAttrs implements interfaces.Database.
func (x *Client) PutAttrs(ctx *model.Context, ns types.Namespace, attrs model.Attributes) error {
	err := x.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		key := attrKeyPrefix + hashNamespace(ns)
		collection := x.client.Collection(x.collection).Doc(key).Collection("attributes")

		attrRefMap := map[types.AttrID]*firestore.DocumentRef{}
		for _, attr := range attrs {
			doc, err := collection.Doc(string(attr.ID)).Get(ctx)
			if err != nil {
				if status.Code(err) != codes.NotFound {
					return goerr.Wrap(err, "failed to get attributes from firestore")
				}
				continue
			}
			attrRefMap[attr.ID] = doc.Ref
		}

		now := time.Now().UTC()

		for _, base := range attrs {
			ttl := base.TTL
			if ttl == 0 {
				ttl = types.DefaultAttributeTTL
			}
			attr := attribute{
				Attribute: base,
				ExpiresAt: now.Add(time.Duration(ttl) * time.Second),
			}

			if ref, ok := attrRefMap[attr.ID]; ok {
				if err := tx.Set(ref, map[string]any{
					"value":      attr.Value,
					"expires_at": attr.ExpiresAt,
				}, firestore.MergeAll); err != nil {
					return goerr.Wrap(err, "failed to unmarshal attribute from firebase")
				}
			} else {
				ref := collection.Doc(string(attr.ID))
				if err := tx.Create(ref, attr); err != nil {
					return goerr.Wrap(err, "failed to create attribute")
				}
			}
		}

		return nil
	})
	if err != nil {
		return goerr.Wrap(err, "failed firestore transaction")
	}

	return nil
}
*/
