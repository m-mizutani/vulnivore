package usecase_test

import (
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
)

type dbMock struct {
	getVulnRecordsCount int
	getVulnRecords      func(ctx *model.Context, repoID model.GitHubRepoID) (model.VulnRecords, error)

	putVulnRecordsCount int
	putVulnRecords      func(ctx *model.Context, vulns []model.VulnRecord) error

	records []model.VulnRecord
}

func (x *dbMock) GetVulnRecords(ctx *model.Context, repoID model.GitHubRepoID) (model.VulnRecords, error) {
	x.getVulnRecordsCount++

	if result, err := x.getVulnRecords(ctx, repoID); result != nil || err != nil {
		return result, err
	}

	var resp []model.VulnRecord
	for _, r := range x.records {
		if r.RepoID == repoID {
			resp = append(resp, r)
		}
	}
	return resp, nil
}

func (x *dbMock) PutVulnRecords(ctx *model.Context, vulns []model.VulnRecord) error {
	x.putVulnRecordsCount++
	x.records = append(x.records, vulns...)
	return x.putVulnRecords(ctx, vulns)
}
