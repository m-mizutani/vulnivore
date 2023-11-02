package memory

import (
	"github.com/m-mizutani/vulnivore/pkg/domain/interfaces"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
)

type client struct {
	records []model.VulnRecord
}

// GetVulnRecords implements interfaces.Database.
func (x *client) GetVulnRecords(ctx *model.Context, repoID model.GitHubRepoID) (model.VulnRecords, error) {
	// return records that has same repoID
	var resp []model.VulnRecord
	for _, r := range x.records {
		if r.RepoID == repoID {
			resp = append(resp, r)
		}
	}
	return resp, nil
}

// PutVulnRecords implements interfaces.Database.
func (x *client) PutVulnRecords(ctx *model.Context, vulns []model.VulnRecord) error {
	// append vulns to records
	x.records = append(x.records, vulns...)
	return nil
}

var _ interfaces.Database = &client{}

func New() *client {
	return &client{}
}
