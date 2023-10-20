package interfaces

import (
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/securego/gosec/v2/report/sarif"
)

type UseCase interface {
	HandleSarif(ctx *model.Context, report *sarif.Report) error
}
