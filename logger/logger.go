package logger

import (
	"bytes"
	"fmt"

	"github.com/sirupsen/logrus"
)

var logger *logrus.Logger

type logFormatter struct{}

func (f *logFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	b := &bytes.Buffer{}
	timestamp := entry.Time.Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf("[%s] [%s] %s\n", timestamp, entry.Level, entry.Message)
	b.WriteString(msg)
	return b.Bytes(), nil
}

func init() {
	logger = logrus.New()
	logger.SetReportCaller(true)
	logger.SetFormatter(&logFormatter{})
	logger.SetLevel(logrus.DebugLevel)
}

func Fatal(args ...interface{}) {
	logger.Fatal(args...)
}

func Debug(args ...interface{}) {
	logger.Debug(args...)
}

func Debugf(format string, args ...interface{}) {
	logger.Debugf(format, args...)
}
