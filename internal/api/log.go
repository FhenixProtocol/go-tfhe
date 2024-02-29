package api

import "C"
import "github.com/sirupsen/logrus"

type Logger interface {
	Trace(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Crit(msg string, args ...interface{})
}

var logger Logger = DefaultLogger{logger: logrus.New()}

func SetLogger(loggerToSet Logger) {
	logger = loggerToSet
	C.init_logger()
}

// DefaultLogger is a default logger to allow someone to use the lib without setting the logger it from outside.
// It matches the above logger interface, which is go-ethereum's interface, but doesn't import it as a dependency
type DefaultLogger struct {
	logger *logrus.Logger
}

func (defaultLogger DefaultLogger) Trace(msg string, args ...interface{}) {
	defaultLogger.logger.Trace(msg, args)
}

func (defaultLogger DefaultLogger) Debug(msg string, args ...interface{}) {
	defaultLogger.logger.Debug(msg, args)
}

func (defaultLogger DefaultLogger) Info(msg string, args ...interface{}) {
	defaultLogger.logger.Info(msg, args)
}

func (defaultLogger DefaultLogger) Warn(msg string, args ...interface{}) {
	defaultLogger.logger.Warn(msg, args)
}

func (defaultLogger DefaultLogger) Error(msg string, args ...interface{}) {
	defaultLogger.logger.Error(msg, args)
}

func (defaultLogger DefaultLogger) Crit(msg string, args ...interface{}) {
	defaultLogger.logger.Error(msg, args)
}
