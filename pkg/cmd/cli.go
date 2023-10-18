package cmd

import (
	"github.com/m-mizutani/vulsink/pkg/cmd/config"
	"github.com/urfave/cli/v2"
)

func New() *cli.App {
	var (
		loggerCfg config.Logger
	)
	baseFlags := []cli.Flag{}

	app := &cli.App{
		Name: "vulsink",
		Flags: append(baseFlags,
			loggerCfg.Flags()...,
		),
		Before: func(ctx *cli.Context) error {
			if err := loggerCfg.Setup(); err != nil {
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
