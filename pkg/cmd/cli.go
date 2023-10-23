package cmd

import (
	"github.com/m-mizutani/vulnivore/pkg/cmd/config"
	"github.com/urfave/cli/v2"
)

func New() *cli.App {
	var (
		loggerCfg config.Logger
	)
	baseFlags := []cli.Flag{}

	app := &cli.App{
		Name: "vulnivore",
		Flags: append(baseFlags,
			loggerCfg.Flags()...,
		),
		Before: func(ctx *cli.Context) error {
			if err := loggerCfg.Configure(); err != nil {
				return err
			}
			return nil
		},
		Commands: []*cli.Command{
			newServe(),
		},
	}

	return app
}
