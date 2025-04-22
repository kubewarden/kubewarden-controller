package cmd

import (
	"fmt"
	"io"
	"log/slog"
)

// string representation of custom slog.Level levels; defining them as constants is
// recommended at: https://pkg.go.dev/log/slog#example-HandlerOptions-CustomLevels.
const (
	LevelDebugString = "debug"
	LevelInfoString  = "info"
	LevelWarnString  = "warning"
	LevelErrorString = "error"
)

func SupportedLogLevels() [4]string {
	return [4]string{LevelDebugString, LevelInfoString, LevelWarnString, LevelErrorString}
}

// NewHandler takes an io.Writer and returns a new log handler of type slog.JSONHandler.
func NewHandler(out io.Writer, level string) *slog.JSONHandler {
	var slevel slog.Level
	switch level {
	case LevelDebugString:
		slevel = slog.LevelDebug
	case LevelInfoString:
		slevel = slog.LevelInfo
	case LevelWarnString:
		slevel = slog.LevelWarn
	case LevelErrorString:
		slevel = slog.LevelError
	default:
		panic(fmt.Sprintf("invalid log level: %q\n", level))
	}

	jh := slog.NewJSONHandler(out, &slog.HandlerOptions{
		Level: slevel,

		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.LevelKey {
				// Handle custom values
				level, _ := a.Value.Any().(slog.Level)

				switch {
				case level < slog.LevelInfo:
					a.Value = slog.StringValue(LevelDebugString)
				case level < slog.LevelWarn:
					a.Value = slog.StringValue(LevelInfoString)
				case level < slog.LevelError:
					a.Value = slog.StringValue(LevelWarnString)
				default:
					a.Value = slog.StringValue(LevelErrorString)
				}
			}

			if a.Key == slog.MessageKey {
				a.Key = "message"
			}
			return a
		},
	})

	return jh
}
