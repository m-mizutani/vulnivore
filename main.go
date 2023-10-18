package main

import (
	"os"

	"log/slog"

	"github.com/m-mizutani/vulsink/pkg/cmd"
	"github.com/m-mizutani/vulsink/pkg/utils"
)

func main() {
	if err := cmd.New().Run(os.Args); err != nil {
		utils.Logger().Error("exit with error", slog.Any("error", err))
		os.Exit(1)
	}
}
