package log

import (
	"fmt"
	"github.com/rs/zerolog"
)

var supportedValues = [6]string{zerolog.LevelTraceValue, zerolog.LevelDebugValue, zerolog.LevelInfoValue, zerolog.LevelWarnValue, zerolog.LevelErrorValue, zerolog.LevelFatalValue}

type Level struct {
	value string
}

func (l *Level) SetZeroLogLevel() {
	level, err := zerolog.ParseLevel(l.String())
	if err != nil {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(level)
	}
}

func (l *Level) String() string {
	if l.value == "" {
		return "info"
	}
	return l.value
}

func (l *Level) Set(level string) error {
	isIncluded := false
	for _, opt := range supportedValues {
		if level == opt {
			l.value = level
			isIncluded = true
		}
	}

	if !isIncluded {
		return fmt.Errorf("supported values: %s", supportedValues)
	}

	return nil
}

func (l *Level) Type() string {
	return "string"
}
