package utils

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"log/slog"
)

func SafeMarshal(w io.Writer, v interface{}) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Warn("Fail to marshal JSON", slog.Any("err", err))
	}
}

func SafeShutdown(ctx context.Context, server *http.Server) {
	if err := server.Shutdown(ctx); err != nil {
		logger.Warn("Fail to shutdown server", slog.Any("err", err))
	}
}
