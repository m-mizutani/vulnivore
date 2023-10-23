package utils

import (
	"sync"

	"log/slog"
)

var logger = slog.Default()
var loggerMutex sync.Mutex

func Logger() *slog.Logger {
	loggerMutex.Lock()
	defer loggerMutex.Unlock()
	return logger
}

func ReplaceLogger(newLogger *slog.Logger) {
	loggerMutex.Lock()
	defer loggerMutex.Unlock()
	logger = newLogger
}
