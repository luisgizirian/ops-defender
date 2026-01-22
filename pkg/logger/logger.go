package logger

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrorLogger provides file-based error logging for critical issues
type ErrorLogger struct {
	mu       sync.Mutex
	file     *os.File
	filepath string
}

var (
	errorLogger *ErrorLogger
	once        sync.Once
)

// InitErrorLogger initializes the error logger singleton
func InitErrorLogger(logDir string) (*ErrorLogger, error) {
	var err error
	once.Do(func() {
		// Ensure log directory exists
		if logDir == "" {
			logDir = "/var/log/ops-defender"
		}
		
		// Try to create log directory, fall back to /tmp if permission denied
		if err = os.MkdirAll(logDir, 0755); err != nil {
			log.Printf("WARNING: Cannot create log directory %s: %v, falling back to /tmp", logDir, err)
			logDir = "/tmp/ops-defender"
			if err = os.MkdirAll(logDir, 0755); err != nil {
				return
			}
		}

		filepath := filepath.Join(logDir, "errors.log")
		file, openErr := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if openErr != nil {
			err = fmt.Errorf("failed to open error log file %s: %w", filepath, openErr)
			return
		}

		errorLogger = &ErrorLogger{
			file:     file,
			filepath: filepath,
		}

		log.Printf("Error logging initialized: %s", filepath)
	})

	return errorLogger, err
}

// GetErrorLogger returns the initialized error logger singleton
func GetErrorLogger() *ErrorLogger {
	return errorLogger
}

// LogError writes an error to the error log file with timestamp
func (el *ErrorLogger) LogError(category, message string, err error) {
	if el == nil {
		// Fallback to stdout if logger not initialized
		log.Printf("ERROR [%s]: %s: %v", category, message, err)
		return
	}

	el.mu.Lock()
	defer el.mu.Unlock()

	timestamp := time.Now().Format(time.RFC3339)
	logMessage := fmt.Sprintf("[%s] ERROR [%s]: %s", timestamp, category, message)
	if err != nil {
		logMessage += fmt.Sprintf(": %v", err)
	}
	logMessage += "\n"

	// Write to file
	if _, writeErr := el.file.WriteString(logMessage); writeErr != nil {
		// If file write fails, log to stdout as fallback
		log.Printf("Failed to write to error log: %v", writeErr)
		log.Print(logMessage)
	}

	// Also log to stdout for immediate visibility
	log.Print(logMessage)
}

// LogCritical logs a critical error that might indicate system instability
func (el *ErrorLogger) LogCritical(category, message string, err error) {
	if el == nil {
		log.Printf("CRITICAL [%s]: %s: %v", category, message, err)
		return
	}

	el.mu.Lock()
	defer el.mu.Unlock()

	timestamp := time.Now().Format(time.RFC3339)
	logMessage := fmt.Sprintf("[%s] CRITICAL [%s]: %s", timestamp, category, message)
	if err != nil {
		logMessage += fmt.Sprintf(": %v", err)
	}
	logMessage += "\n"

	// Write to file
	if _, writeErr := el.file.WriteString(logMessage); writeErr != nil {
		log.Printf("Failed to write to error log: %v", writeErr)
		log.Print(logMessage)
	}

	// Also log to stdout
	log.Print(logMessage)
}

// Close closes the error log file
func (el *ErrorLogger) Close() error {
	if el == nil || el.file == nil {
		return nil
	}

	el.mu.Lock()
	defer el.mu.Unlock()

	return el.file.Close()
}

// GetFilePath returns the path to the error log file
func (el *ErrorLogger) GetFilePath() string {
	if el == nil {
		return ""
	}
	return el.filepath
}
