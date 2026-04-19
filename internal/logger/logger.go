// Package logger is a thin wrapper over log/slog that matches what every
// internal package needs: leveled structured logging, safe to hand around as
// a value, never nil.
package logger

import (
	"log/slog"
	"os"
	"strings"
)

// Logger aliases *slog.Logger so callers can import just this package.
type Logger = slog.Logger

// New returns a JSON logger emitting to stderr at the given level.
func New(level string) *Logger {
	l := parseLevel(level)
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l})
	return slog.New(h)
}

// NewText returns a human-readable logger (nice for dev).
func NewText(level string) *Logger {
	l := parseLevel(level)
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})
	return slog.New(h)
}

// Nop returns a logger that discards everything.
func Nop() *Logger {
	return slog.New(slog.NewTextHandler(discard{}, &slog.HandlerOptions{Level: slog.LevelError + 10}))
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}
