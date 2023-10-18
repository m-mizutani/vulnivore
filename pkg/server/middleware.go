package server

import (
	"net/http"

	"log/slog"

	"github.com/m-mizutani/vulsink/pkg/utils"
)

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (x *statusWriter) WriteHeader(status int) {
	x.status = status
	x.ResponseWriter.WriteHeader(status)
}

func accessLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}

		next.ServeHTTP(sw, r)
		utils.Logger().Info("http access",
			slog.Int("status", sw.status),
			slog.String("method", r.Method),
			slog.String("remote", r.RemoteAddr),
			slog.Any("path", r.URL.Path),
			slog.Any("query", r.URL.Query()),
		)
	})
}
