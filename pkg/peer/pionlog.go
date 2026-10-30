package peer

import (
	"log"

	pionlogging "github.com/pion/logging"
	"github.com/wsyzxjn/uulink/pkg/logging"
)

// pionWarnScopes are the Pion loggers raised from Pion's default (errors
// only) to warnings. "turnc" is the TURN client: its warnings report rejected
// allocation refreshes, failed channel binds and a full relay receive buffer,
// which otherwise stay silent until the relayed connection drops. "ice" is
// left at the default because it warns on every connectivity check made
// before the first remote candidate arrives.
var pionWarnScopes = []string{"turnc"}

// newPionLoggerFactory reuses Pion's default logger factory, so the
// PION_LOG_<LEVEL>=<scopes|all> variables keep working and override the
// levels chosen here. Pion's output goes to the standard logger's writer,
// like uulink's own log lines. A -log-level above warn keeps Pion at its
// errors-only default.
func newPionLoggerFactory() *pionlogging.DefaultLoggerFactory {
	factory := pionlogging.NewDefaultLoggerFactory()
	factory.Writer = stdLogWriter{}
	if logging.CurrentLevel() > logging.LevelWarn || factory.DefaultLogLevel >= pionlogging.LogLevelWarn {
		return factory
	}
	for _, scope := range pionWarnScopes {
		if _, set := factory.ScopeLevels[scope]; !set {
			factory.ScopeLevels[scope] = pionlogging.LogLevelWarn
		}
	}
	return factory
}

// stdLogWriter looks up the standard logger's output on every write, so a
// later log.SetOutput redirects Pion's messages as well.
type stdLogWriter struct{}

func (stdLogWriter) Write(p []byte) (int, error) { return log.Writer().Write(p) }
