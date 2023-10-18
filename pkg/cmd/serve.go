package cmd

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/m-mizutani/goerr"
	"github.com/m-mizutani/vulsink/pkg/infra"
	"github.com/m-mizutani/vulsink/pkg/server"
	"github.com/m-mizutani/vulsink/pkg/usecase"
	"github.com/m-mizutani/vulsink/pkg/utils"
	"github.com/urfave/cli/v2"
)

func newServe() *cli.Command {
	var (
		addr string
	)

	return &cli.Command{
		Name:    "serve",
		Aliases: []string{"s"},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "addr",
				Aliases:     []string{"a"},
				Value:       "127.0.0.1:8000",
				Usage:       "Listen address",
				Destination: &addr,
			},
		},

		Action: func(c *cli.Context) error {
			clients := infra.New()

			uc := usecase.New(clients)

			handler := server.New(uc).Handler()

			// create net listener
			listener, err := net.Listen("tcp", addr)
			if err != nil {
				return goerr.Wrap(err, "Failed to listen TCP").With("addr", addr)
			}

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt)

			server := &http.Server{
				Handler:           handler,
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       60 * time.Second,
			}

			errCh := make(chan error)
			go func() {
				utils.Logger().Info("starting server...", slog.Any("addr", addr))
				if err := server.Serve(listener); err != nil {
					errCh <- goerr.Wrap(err, "Failed to start server")
				}
			}()

			select {
			case err := <-errCh:
				return err

			case <-sigChan:
				utils.Logger().Info("shutting down server...")
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				utils.SafeShutdown(ctx, server)
			}

			return nil
		},
	}
}
