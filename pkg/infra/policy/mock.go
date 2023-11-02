package policy

import (
	"encoding/json"

	"github.com/m-mizutani/goerr"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
)

type Mock struct {
	MockQuery func(ctx *model.Context, query string, input any) (any, error)
}

func (x *Mock) Query(ctx *model.Context, query string, input any, output any) error {
	resp, err := x.MockQuery(ctx, query, input)
	if err != nil {
		return err
	}

	raw, err := json.Marshal(resp)
	if err != nil {
		return goerr.Wrap(err, "Failed to marshal response")
	}
	if err := json.Unmarshal(raw, output); err != nil {
		return goerr.Wrap(err, "Failed to unmarshal response")
	}

	return nil
}
