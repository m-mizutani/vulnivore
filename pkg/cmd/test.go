package cmd

import (
	"encoding/json"
	"os"

	"github.com/google/go-github/v56/github"
	"github.com/m-mizutani/goerr"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/m-mizutani/vulnivore/pkg/infra"
	"github.com/m-mizutani/vulnivore/pkg/infra/githubapp"
	"github.com/m-mizutani/vulnivore/pkg/infra/memory"
	"github.com/m-mizutani/vulnivore/pkg/infra/policy"
	"github.com/m-mizutani/vulnivore/pkg/usecase"
	"github.com/m-mizutani/vulnivore/pkg/utils"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/urfave/cli/v2"
)

func newTest() *cli.Command {
	return &cli.Command{
		Name:    "test",
		Aliases: []string{"t"},
		Flags:   []cli.Flag{},
		Subcommands: []*cli.Command{
			newTestDump(),
			newTestRun(),
		},
	}
}

func newTestDump() *cli.Command {
	var (
		inputFile string
		dumpPath  string
	)

	flags := []cli.Flag{
		&cli.StringFlag{
			Name:        "input-file",
			Aliases:     []string{"i"},
			Usage:       "Input file path",
			EnvVars:     []string{"VULNIVORE_INPUT_FILE"},
			Destination: &inputFile,
			Required:    true,
		},
		&cli.StringFlag{
			Name:        "dump-path",
			Aliases:     []string{"d"},
			Value:       "testdata",
			Usage:       "Directory path of test data dumping",
			EnvVars:     []string{"VULNIVORE_DUMP_PATH"},
			Destination: &dumpPath,
		},
	}

	return &cli.Command{
		Name:    "dump",
		Aliases: []string{"d"},
		Flags:   flags,
		Action: func(c *cli.Context) error {
			var report types.Report

			fd, err := os.Open(inputFile)
			if err != nil {
				return goerr.Wrap(err, "Failed to open input file")
			}
			defer fd.Close()

			if err := json.NewDecoder(fd).Decode(&report); err != nil {
				return goerr.Wrap(err, "Failed to decode json")
			}

			if err := usecase.DumpTrivyTestData(&report, dumpPath); err != nil {
				return err
			}
			return nil
		},
	}
}

func newTestRun() *cli.Command {
	var (
		inputFile  string
		outputFile string
		policyDir  string

		repoID    int64
		repoOwner string
		repoName  string
	)

	return &cli.Command{
		Name:    "run",
		Aliases: []string{"r"},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "input-file",
				Aliases:     []string{"i"},
				Usage:       "Input file path",
				EnvVars:     []string{"VULNIVORE_INPUT_FILE"},
				Destination: &inputFile,
				Required:    true,
			},

			&cli.StringFlag{
				Name:        "output-file",
				Aliases:     []string{"o"},
				Usage:       "Output file path ('-' for stdout))",
				EnvVars:     []string{"VULNIVORE_OUTPUT_FILE"},
				Destination: &outputFile,
				Value:       "-",
			},

			&cli.StringFlag{
				Name:        "policy-dir",
				Aliases:     []string{"p"},
				Usage:       "Policy directory path",
				EnvVars:     []string{"VULNIVORE_POLICY_DIR"},
				Destination: &policyDir,
			},

			&cli.Int64Flag{
				Name:        "repo-id",
				Category:    "Dummy GitHub repo data",
				Usage:       "GitHub repository ID",
				EnvVars:     []string{"VULNIVORE_REPO_ID"},
				Destination: &repoID,
				Value:       1234,
			},
			&cli.StringFlag{
				Name:        "repo-owner",
				Category:    "Dummy GitHub repo data",
				Usage:       "GitHub repository owner",
				EnvVars:     []string{"VULNIVORE_REPO_OWNER"},
				Destination: &repoOwner,
				Value:       "m-mizutani",
			},
			&cli.StringFlag{
				Name:        "repo-name",
				Category:    "Dummy GitHub repo data",
				Usage:       "GitHub repository name",
				EnvVars:     []string{"VULNIVORE_REPO_NAME"},
				Destination: &repoName,
				Value:       "vulnivore",
			},
		},
		Action: func(c *cli.Context) error {
			var report types.Report
			utils.Logger().Info("Start test run", "input", inputFile, "output", outputFile, "policy", policyDir)

			// Read input file (trivy scan result)
			{
				fd, err := os.Open(inputFile)
				if err != nil {
					return goerr.Wrap(err, "Failed to open input file")
				}
				defer fd.Close()

				if err := json.NewDecoder(fd).Decode(&report); err != nil {
					return goerr.Wrap(err, "Failed to decode json")
				}
			}

			var results []*model.GitHubIssue

			// Create infra client
			ghMock := githubapp.Mock{
				CreateIssueMock: func(ctx *model.Context, issue *model.GitHubIssue) (*github.Issue, error) {
					results = append(results, issue)
					number := len(results)
					return &github.Issue{
						Number: &number,
					}, nil
				},
				CloseIssueMock: func(ctx *model.Context, repo *model.GitHubRepo, issueNo int) error {
					return nil
				},
			}

			infraOpt := []infra.Option{
				infra.WithDB(memory.New()),
				infra.WithGitHubApp(&ghMock),
			}
			if policyDir != "" {
				p, err := policy.New(policy.WithDir(policyDir))
				if err != nil {
					return err
				}
				infraOpt = append(infraOpt, infra.WithPolicy(p))
			}

			uc := usecase.New(infra.New(infraOpt...))
			ctx := model.NewContext(
				model.WithContext(c.Context),
				model.WithGitHubRepo(&model.GitHubRepo{
					RepoID: model.GitHubRepoID(repoID),
					Owner:  repoOwner,
					Name:   repoName,
				}),
			)
			if err := uc.HandleTrivy(ctx, &report); err != nil {
				return err
			}

			// Output result
			{
				output := struct {
					Results []*model.GitHubIssue `json:"results"`
				}{
					Results: results,
				}

				out, err := os.Create(outputFile)
				if err != nil {
					return err
				}
				defer out.Close()

				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(&output); err != nil {
					return goerr.Wrap(err, "Failed to encode output data to json")
				}
			}

			return nil
		},
	}
}
