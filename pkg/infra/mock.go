package infra

import "github.com/m-mizutani/vulnivore/pkg/domain/model"

type DBMock struct {
	GetVulnRecordsCount int
	getVulnRecords      func(ctx *model.Context, repoID model.GitHubRepoID) (model.VulnRecords, error)

	PutVulnRecordsCount int
	putVulnRecords      func(ctx *model.Context, vulns []model.VulnRecord) error

	records []model.VulnRecord
}

func (x *DBMock) GetVulnRecords(ctx *model.Context, repoID model.GitHubRepoID) (model.VulnRecords, error) {
	x.GetVulnRecordsCount++

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

func (x *DBMock) PutVulnRecords(ctx *model.Context, vulns []model.VulnRecord) error {
	x.PutVulnRecordsCount++
	x.records = append(x.records, vulns...)
	return x.putVulnRecords(ctx, vulns)
}
