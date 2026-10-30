package peer

import (
	"testing"

	pionlogging "github.com/pion/logging"
	"github.com/wsyzxjn/uulink/pkg/logging"
)

func clearPionLogEnv(t *testing.T) {
	t.Helper()
	for _, level := range []string{"DISABLE", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"} {
		t.Setenv("PION_LOG_"+level, "")
		t.Setenv("PIONS_LOG_"+level, "")
	}
}

func withLogLevel(t *testing.T, level logging.Level) {
	t.Helper()
	previous := logging.CurrentLevel()
	logging.SetLevel(level)
	t.Cleanup(func() { logging.SetLevel(previous) })
}

func scopeLevel(f *pionlogging.DefaultLoggerFactory, scope string) pionlogging.LogLevel {
	if level, ok := f.ScopeLevels[scope]; ok {
		return level
	}
	return f.DefaultLogLevel
}

func TestPionLoggerFactoryRaisesTURNClientToWarn(t *testing.T) {
	clearPionLogEnv(t)
	withLogLevel(t, logging.LevelInfo)
	f := newPionLoggerFactory()
	for _, scope := range pionWarnScopes {
		if got := scopeLevel(f, scope); got != pionlogging.LogLevelWarn {
			t.Errorf("scope %s level = %s, want warn", scope, got)
		}
	}
	for _, scope := range []string{"ice", "sctp"} {
		if got := scopeLevel(f, scope); got != pionlogging.LogLevelError {
			t.Errorf("scope %s level = %s, want Pion's error default", scope, got)
		}
	}
}

func TestPionLoggerFactoryKeepsEnvironmentOverrides(t *testing.T) {
	clearPionLogEnv(t)
	withLogLevel(t, logging.LevelInfo)
	t.Setenv("PION_LOG_DEBUG", "ice")
	t.Setenv("PION_LOG_ERROR", "turnc")
	f := newPionLoggerFactory()
	if got := scopeLevel(f, "ice"); got != pionlogging.LogLevelDebug {
		t.Errorf("ice level = %s, want debug from PION_LOG_DEBUG", got)
	}
	if got := scopeLevel(f, "turnc"); got != pionlogging.LogLevelError {
		t.Errorf("turnc level = %s, want error from PION_LOG_ERROR", got)
	}
}

func TestPionLoggerFactoryHonorsQuietLogLevel(t *testing.T) {
	clearPionLogEnv(t)
	withLogLevel(t, logging.LevelError)
	f := newPionLoggerFactory()
	for _, scope := range pionWarnScopes {
		if got := scopeLevel(f, scope); got != pionlogging.LogLevelError {
			t.Errorf("scope %s level = %s with -log-level error, want error", scope, got)
		}
	}
}
