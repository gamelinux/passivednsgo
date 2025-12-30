package logger

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"passivednsgo/internal/config"
	"passivednsgo/internal/dnsparser"
)

var (
	logFile  *os.File
	fileSize int64
)

// Logger now accepts channels and waitgroups
func Logger(wg *sync.WaitGroup, logChan <-chan dnsparser.PDNS) error {
	defer wg.Done()
	slog.Info("Logger Routine Started...")
	defer closeLogFile()

	var err error
	logFile, err = openLogFile()
	if err != nil {
		return err
	}
	defer logFile.Close()

	// Range loop exits when logChan is closed
	for pdnsEntry := range logChan {
		logEntry(pdnsEntry)
	}

	slog.Info("Logger Routine Stopped")
	return nil
}

func logEntry(pdnsEntry dnsparser.PDNS) {
	entry, err := json.Marshal(pdnsEntry)
	if err != nil {
		slog.Error("Failed to marshal PDNS entry", "error", err)
		return
	}
	entry = append(entry, '\n')
	n, err := logFile.Write(entry)
	if err != nil {
		slog.Error("Failed to write log entry", "error", err)
		return
	}
	fileSize += int64(n)

	if fileSize >= parseSize(config.C.Rollover) {
		rolloverLogFile(*pdnsEntry.Lts)
	}
}

func openLogFile() (*os.File, error) {
	filename := config.C.Logfile
	err := os.MkdirAll(filepath.Dir(filename), 0755)
	if err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get log file size: %w", err)
	}
	fileSize = stat.Size()
	return file, nil
}

func closeLogFile() {
	if logFile != nil {
		logFile.Close()
		logFile = nil
	}
}

func rolloverLogFile(ts time.Time) {
	if logFile != nil {
		logFile.Close()
	}

	timestamp := ts.Format("20060102-150405")
	backupFile := fmt.Sprintf("%s.%s", config.C.Logfile, timestamp)
	if err := os.Rename(config.C.Logfile, backupFile); err != nil {
		slog.Error("Failed to rename log file", "error", err)
		return
	}

	newLogFile, err := openLogFile()
	if err != nil {
		slog.Error("Failed to open new log file", "error", err)
		return
	}
	logFile = newLogFile
}

func parseSize(sizeStr string) int64 {
	sizeStr = strings.ToUpper(strings.TrimSpace(sizeStr))
	if len(sizeStr) < 2 {
		return 0
	}
	sizeValue, err := strconv.Atoi(sizeStr[:len(sizeStr)-1])
	if err != nil {
		return 0
	}
	unit := sizeStr[len(sizeStr)-1:]

	switch unit {
	case "G":
		return int64(sizeValue) * 1024 * 1024 * 1024
	case "M":
		return int64(sizeValue) * 1024 * 1024
	case "T":
		return int64(sizeValue) * 1024 * 1024 * 1024 * 1024
	default:
		return 0
	}
}
