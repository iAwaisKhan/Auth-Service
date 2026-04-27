package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	*zap.Logger
}

func New(env string) *Logger {
	var (
		zapLogger *zap.Logger
		err       error
	)

	if env == "production" {
		cfg := zap.NewProductionConfig()
		cfg.EncoderConfig.TimeKey = "timestamp"
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		zapLogger, err = cfg.Build()
	} else {
		cfg := zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		zapLogger, err = cfg.Build()
	}

	if err != nil {
		// Logger is a startup-time invariant — panic is intentional here.
		panic("failed to build logger: " + err.Error())
	}

	return &Logger{zapLogger}
}

// Field helpers — thin wrappers so callers don't need to import zap directly
func String(key, value string) zap.Field  { return zap.String(key, value) }
func Error(err error) zap.Field           { return zap.Error(err) }
func Int(key string, val int) zap.Field   { return zap.Int(key, val) }
func Any(key string, val any) zap.Field   { return zap.Any(key, val) }
func Bool(key string, val bool) zap.Field { return zap.Bool(key, val) }
