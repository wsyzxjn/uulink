// Package logging provides the process-wide log level used by uulink.
package logging

import (
	"fmt"
	"log"
	"sync/atomic"
)

// Level is the severity of a log message.
type Level int32

const (
	// LevelDebug is used for protocol details needed to diagnose negotiation
	// and forwarding behavior.
	LevelDebug Level = iota
	// LevelInfo is the default level for connection and mapping status.
	LevelInfo
	// LevelWarn is used for recoverable or degraded conditions.
	LevelWarn
	// LevelError is used for failures that interrupt a connection or stream.
	LevelError
)

var currentLevel atomic.Int32

func init() {
	currentLevel.Store(int32(LevelInfo))
}

// SetLevel changes the process-wide log level.
func SetLevel(level Level) {
	currentLevel.Store(int32(level))
}

// CurrentLevel returns the process-wide log level.
func CurrentLevel() Level {
	return Level(currentLevel.Load())
}

// ParseLevel converts a CLI log-level name.
func ParseLevel(value string) (Level, error) {
	switch value {
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "warn":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	default:
		return LevelInfo, fmt.Errorf("invalid log level %q", value)
	}
}

func enabled(level Level) bool {
	return Level(currentLevel.Load()) <= level
}

func emit(level Level, format string, args ...any) {
	if !enabled(level) {
		return
	}
	log.Printf(level.String()+" "+format, args...)
}

// Debugf logs a debug-level message.
func Debugf(format string, args ...any) {
	emit(LevelDebug, format, args...)
}

// Infof logs an info-level message.
func Infof(format string, args ...any) {
	emit(LevelInfo, format, args...)
}

// Warnf logs a warning-level message.
func Warnf(format string, args ...any) {
	emit(LevelWarn, format, args...)
}

// Errorf logs an error-level message.
func Errorf(format string, args ...any) {
	emit(LevelError, format, args...)
}

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}
