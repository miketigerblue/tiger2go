package logger

import (
	"fmt"
	"log"
	"os"
)

// Logger provides structured logging
type Logger struct {
	infoLog  *log.Logger
	errorLog *log.Logger
	debugLog *log.Logger
	debug    bool
}

// New creates a new logger
func New(debug bool) *Logger {
	return &Logger{
		infoLog:  log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime),
		errorLog: log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile),
		debugLog: log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile),
		debug:    debug,
	}
}

// Info logs an informational message
func (l *Logger) Info(format string, v ...interface{}) {
	l.infoLog.Printf(format, v...)
}

// Error logs an error message
func (l *Logger) Error(format string, v ...interface{}) {
	l.errorLog.Printf(format, v...)
}

// Debug logs a debug message (only if debug mode is enabled)
func (l *Logger) Debug(format string, v ...interface{}) {
	if l.debug {
		l.debugLog.Printf(format, v...)
	}
}

// Fatal logs an error message and exits
func (l *Logger) Fatal(format string, v ...interface{}) {
	l.errorLog.Fatalf(format, v...)
}

// Printf implements a simple printf interface
func (l *Logger) Printf(format string, v ...interface{}) {
	fmt.Printf(format, v...)
}
