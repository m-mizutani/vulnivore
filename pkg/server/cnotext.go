package server

import (
	"context"

	"github.com/m-mizutani/vulnivore/pkg/domain/model"
)

func toVulnivoreContext(ctx context.Context) *model.Context {
	if ctx == nil {
		return model.NewContext()
	}
	if vctx, ok := ctx.(*model.Context); ok {
		return vctx
	}
	return model.NewContext(model.WithContext(ctx))
}
