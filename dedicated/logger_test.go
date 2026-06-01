package dedicated_test

import (
	"fmt"
	"testing"

	"github.com/IBM/go-sdk-core/v5/core"
)

// TestLogger implements core.Logger and bridges to testing.T
type TestLogger struct {
	t        *testing.T
	logLevel core.LogLevel
}

// NewTestLogger creates a logger that outputs to testing.T
func NewTestLogger(t *testing.T, level core.LogLevel) *TestLogger {
	return &TestLogger{
		t:        t,
		logLevel: level,
	}
}

// Log implements core.Logger.Log
func (l *TestLogger) Log(level core.LogLevel, format string, inserts ...interface{}) {
	if l.IsLogLevelEnabled(level) {
		msg := fmt.Sprintf(format, inserts...)
		l.t.Logf("[%s] %s", l.levelString(level), msg)
	}
}

// Error implements core.Logger.Error
func (l *TestLogger) Error(format string, inserts ...interface{}) {
	l.Log(core.LevelError, "[Error] "+format, inserts...)
}

// Warn implements core.Logger.Warn
func (l *TestLogger) Warn(format string, inserts ...interface{}) {
	l.Log(core.LevelWarn, "[Warn] "+format, inserts...)
}

// Info implements core.Logger.Info
func (l *TestLogger) Info(format string, inserts ...interface{}) {
	l.Log(core.LevelInfo, "[Info] "+format, inserts...)
}

// Debug implements core.Logger.Debug
func (l *TestLogger) Debug(format string, inserts ...interface{}) {
	l.Log(core.LevelDebug, "[Debug] "+format, inserts...)
}

// SetLogLevel implements core.Logger.SetLogLevel
func (l *TestLogger) SetLogLevel(level core.LogLevel) {
	l.logLevel = level
}

// GetLogLevel implements core.Logger.GetLogLevel
func (l *TestLogger) GetLogLevel() core.LogLevel {
	return l.logLevel
}

// IsLogLevelEnabled implements core.Logger.IsLogLevelEnabled
func (l *TestLogger) IsLogLevelEnabled(level core.LogLevel) bool {
	return l.logLevel >= level
}

// levelString converts LogLevel to string
func (l *TestLogger) levelString(level core.LogLevel) string {
	switch level {
	case core.LevelError:
		return "ERROR"
	case core.LevelWarn:
		return "WARN"
	case core.LevelInfo:
		return "INFO"
	case core.LevelDebug:
		return "DEBUG"
	default:
		return "NONE"
	}
}
