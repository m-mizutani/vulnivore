package usecase

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/m-mizutani/goerr"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/m-mizutani/vulnivore/pkg/utils"
)

func DumpTrivyTestData(report *types.Report, baseDir string) error {
	dir := filepath.Join(filepath.Clean(baseDir), "trivy")
	if err := os.MkdirAll(dir, 0750); err != nil {
		if !os.IsExist(err) {
			return goerr.Wrap(err, "Failed to mkdir")
		}
	}

	for i, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			d := model.NewEvalInputTrivyVuln(*report, result, vuln)
			filePath := filepath.Join(
				dir,
				fmt.Sprintf("result_%d", i),
				vuln.VulnerabilityID,
				"input.json",
			)

			dirPath := filepath.Dir(filePath)
			if err := os.MkdirAll(dirPath, 0750); err != nil {
				if !os.IsExist(err) {
					return goerr.Wrap(err, "Failed to mkdir")
				}
			}

			fd, err := os.Create(filepath.Clean(filePath))
			if err != nil {
				return goerr.Wrap(err, "Failed to create file")
			}
			defer fd.Close()

			enc := json.NewEncoder(fd)
			enc.SetIndent("", "  ")
			if err := enc.Encode(d); err != nil {
				return goerr.Wrap(err, "Failed to encode json")
			}

			utils.Logger().Info("Dumped trivy test data", "path", filePath)
		}
	}

	return nil
}
