// Package audit centralizes structured logging so every decision (allow, block,
// deny, error) is emitted as JSON with consistent fields and no secrets.
package audit

import (
	"log/slog"
	"os"
)

// New returns a JSON structured logger writing to stdout.
func New() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
}
