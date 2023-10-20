package config

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/m-mizutani/clog"
	"github.com/m-mizutani/goerr"
	"github.com/m-mizutani/masq"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/m-mizutani/vulnivore/pkg/utils"
	"github.com/urfave/cli/v2"
)

type Logger struct {
	level  string
	format string
	output string
}

func (x *Logger) Flags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "log-level",
			Aliases:     []string{"l"},
			Value:       "info",
			Usage:       "Log level [debug, info, warn, error]",
			Destination: &x.level,
		},

		&cli.StringFlag{
			Name:        "log-format",
			Aliases:     []string{"f"},
			Value:       "text",
			Usage:       "Log format [json, text]",
			Destination: &x.format,
		},

		&cli.StringFlag{
			Name:        "log-output",
			Aliases:     []string{"o"},
			Value:       "stdout",
			Usage:       "Log output [-, stdout, stderr, file path]",
			Destination: &x.output,
		},
	}
}

var jsonLogger, consoleLogger *slog.Logger
var filter func(groups []string, a slog.Attr) slog.Attr

func init() {
	// NOTE: You can customize log masking for sensitive data.
	// See https://github.com/m-mizutani/masq for more details.
	filter = masq.New(
		// Mask value with `masq:"secret"` tag
		masq.WithTag("secret"),
		masq.WithType[model.GitHubPrivateKey](),
		masq.WithType[model.GitHubSecret](),
	)

	jsonLogger = newJSONLogger(os.Stdout, slog.LevelInfo)
	consoleLogger = newConsoleLogger(os.Stdout, slog.LevelInfo)
}

func (x *Logger) Configure() error {
	logLevelMap := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
	}
	logLevel, ok := logLevelMap[x.level]
	if !ok {
		return goerr.New("Invalid log level").With("level", x.level)
	}

	var w io.Writer
	switch x.output {
	case "stdout", "-":
		w = os.Stdout
	case "stderr":
		w = os.Stderr
	default:
		// #nosec G302
		f, err := os.OpenFile(filepath.Clean(x.output), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return goerr.Wrap(err)
		}
		w = f
	}

	var logger *slog.Logger
	switch x.format {
	case "text":
		logger = newConsoleLogger(w, logLevel)
	case "json":
		logger = newJSONLogger(w, logLevel)

	default:
		return goerr.New("Invalid log format").With("format", x.format)
	}

	utils.ReplaceLogger(logger)

	return nil
}

func newJSONLogger(w io.Writer, level slog.Level) *slog.Logger {
	handler := slog.NewJSONHandler(w, &slog.HandlerOptions{
		AddSource:   true,
		Level:       level,
		ReplaceAttr: filter,
	})
	return slog.New(handler)
}

func newConsoleLogger(w io.Writer, level slog.Level) *slog.Logger {
	// NOTE: You can customize logging format on console.
	// See https://github.com/m-mizutani/clog/ for more details.
	handler := clog.New(
		clog.WithWriter(w),
		clog.WithLevel(level),
		clog.WithReplaceAttr(filter),
		clog.WithSource(true),
		// clog.WithTimeFmt("2006-01-02 15:04:05"),
		clog.WithColorMap(&clog.ColorMap{
			Level: map[slog.Level]*color.Color{
				slog.LevelDebug: color.New(color.FgGreen, color.Bold),
				slog.LevelInfo:  color.New(color.FgCyan, color.Bold),
				slog.LevelWarn:  color.New(color.FgYellow, color.Bold),
				slog.LevelError: color.New(color.FgRed, color.Bold),
			},
			LevelDefault: color.New(color.FgBlue, color.Bold),
			Time:         color.New(color.FgWhite),
			Message:      color.New(color.FgHiWhite),
			AttrKey:      color.New(color.FgHiCyan),
			AttrValue:    color.New(color.FgHiWhite),
		}),
	)

	return slog.New(handler)
}
