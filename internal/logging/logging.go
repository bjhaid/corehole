package logging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Level int32

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

type Format int32

const (
	FormatText Format = iota
	FormatJSON
)

var (
	current       atomic.Int32
	currentFormat atomic.Int32
	outputMu      sync.Mutex
	output        io.Writer
	outputWrapped bool
)

func init() {
	current.Store(int32(LevelInfo))
	currentFormat.Store(int32(FormatText))
	output = log.Writer()
}

func Configure(level string, format string) {
	SetLevel(level)
	SetFormat(format)
}

func SetLevel(level string) {
	parsed, ok := ParseLevel(level)
	if !ok {
		parsed = LevelInfo
	}
	current.Store(int32(parsed))
}

func SetFormat(format string) {
	parsed, ok := ParseFormat(format)
	if !ok {
		parsed = FormatText
	}
	currentFormat.Store(int32(parsed))
	configureOutput(parsed)
}

func ParseLevel(level string) (Level, bool) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return LevelDebug, true
	case "", "info":
		return LevelInfo, true
	case "warn", "warning":
		return LevelWarn, true
	case "error":
		return LevelError, true
	default:
		return LevelInfo, false
	}
}

func ParseFormat(format string) (Format, bool) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
		return FormatText, true
	case "json":
		return FormatJSON, true
	default:
		return FormatText, false
	}
}

func Enabled(level Level) bool {
	return level >= Level(current.Load())
}

func Debug(msg string, attrs ...any) {
	write(LevelDebug, "DEBUG", msg, attrs...)
}

func Debugf(format string, args ...any) {
	Debug(fmt.Sprintf(format, args...))
}

func Info(msg string, attrs ...any) {
	write(LevelInfo, "INFO", msg, attrs...)
}

func Infof(format string, args ...any) {
	Info(fmt.Sprintf(format, args...))
}

func Warn(msg string, attrs ...any) {
	write(LevelWarn, "WARN", msg, attrs...)
}

func Warnf(format string, args ...any) {
	Warn(fmt.Sprintf(format, args...))
}

func Error(msg string, attrs ...any) {
	write(LevelError, "ERROR", msg, attrs...)
}

func Errorf(format string, args ...any) {
	Error(fmt.Sprintf(format, args...))
}

func write(level Level, levelName string, msg string, attrs ...any) {
	if !Enabled(level) {
		return
	}
	if Format(currentFormat.Load()) == FormatJSON {
		writeJSON(strings.ToLower(levelName), msg, attrs...)
		return
	}
	log.Output(3, fmt.Sprintf("[%s] %s%s", levelName, msg, formatTextAttrs(attrs...)))
}

func writeJSON(level string, msg string, attrs ...any) {
	record := map[string]any{
		"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		"level": level,
		"msg":   msg,
	}
	for key, value := range attrsMap(attrs...) {
		record[key] = value
	}
	data, err := json.Marshal(record)
	if err != nil {
		log.Output(3, fmt.Sprintf("[ERROR] logging_encode_failed error=%q msg=%q", err.Error(), msg))
		return
	}
	fmt.Fprintln(outputWriter(), string(data))
}

type stdJSONWriter struct{}

func (stdJSONWriter) Write(data []byte) (int, error) {
	for _, line := range bytes.SplitAfter(data, []byte("\n")) {
		trimmed := bytes.TrimRight(line, "\r\n")
		if len(trimmed) == 0 {
			continue
		}
		if _, err := fmt.Fprintln(outputWriter(), stdLogLineToJSON(string(trimmed))); err != nil {
			return len(data), err
		}
	}
	return len(data), nil
}

func configureOutput(format Format) {
	outputMu.Lock()
	defer outputMu.Unlock()
	if format == FormatJSON {
		if !outputWrapped {
			output = log.Writer()
			log.SetOutput(stdJSONWriter{})
			outputWrapped = true
		}
		return
	}
	if outputWrapped {
		log.SetOutput(output)
		outputWrapped = false
		return
	}
	output = log.Writer()
}

func outputWriter() io.Writer {
	outputMu.Lock()
	defer outputMu.Unlock()
	return output
}

func stdLogLineToJSON(line string) string {
	level, msg := splitStdLogLevel(line)
	record := map[string]any{
		"ts":        time.Now().UTC().Format(time.RFC3339Nano),
		"level":     level,
		"component": "coredns",
		"msg":       msg,
	}
	if strings.HasPrefix(strings.TrimSpace(msg), "{") {
		var payload map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(msg)), &payload); err == nil {
			for key, value := range payload {
				record[key] = value
			}
			if _, ok := record["level"]; !ok {
				record["level"] = level
			}
			if _, ok := record["component"]; !ok {
				record["component"] = "coredns"
			}
			if _, ok := record["ts"]; !ok {
				record["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
			}
			data, err := json.Marshal(record)
			if err == nil {
				return string(data)
			}
		}
	}
	if plugin, remaining, ok := strings.Cut(msg, ": "); ok && strings.HasPrefix(plugin, "plugin/") {
		record["plugin"] = strings.TrimPrefix(plugin, "plugin/")
		record["msg"] = remaining
	}
	data, err := json.Marshal(record)
	if err != nil {
		return `{"level":"error","msg":"logging_encode_failed"}`
	}
	return string(data)
}

func splitStdLogLevel(line string) (string, string) {
	levels := []struct {
		token string
		level string
	}{
		{token: "[DEBUG] ", level: "debug"},
		{token: "[INFO] ", level: "info"},
		{token: "[WARNING] ", level: "warn"},
		{token: "[ERROR] ", level: "error"},
		{token: "[FATAL] ", level: "fatal"},
	}
	bestIndex := -1
	best := levels[1]
	for _, candidate := range levels {
		idx := strings.Index(line, candidate.token)
		if idx >= 0 && (bestIndex < 0 || idx < bestIndex) {
			bestIndex = idx
			best = candidate
		}
	}
	if bestIndex < 0 {
		return "info", strings.TrimSpace(line)
	}
	return best.level, strings.TrimSpace(line[bestIndex+len(best.token):])
}

func formatTextAttrs(attrs ...any) string {
	fields := attrsMap(attrs...)
	if len(fields) == 0 {
		return ""
	}
	var b strings.Builder
	for _, attr := range attrs {
		key, ok := attr.(string)
		if !ok {
			continue
		}
		value, exists := fields[key]
		if !exists {
			continue
		}
		b.WriteByte(' ')
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(formatTextValue(value))
		delete(fields, key)
	}
	return b.String()
}

func formatTextValue(value any) string {
	switch v := value.(type) {
	case string:
		if v == "" || strings.ContainsAny(v, " \t\n\r\"") {
			encoded, err := json.Marshal(v)
			if err == nil {
				return string(encoded)
			}
		}
		return v
	case fmt.Stringer:
		return formatTextValue(v.String())
	default:
		return fmt.Sprint(v)
	}
}

func attrsMap(attrs ...any) map[string]any {
	fields := make(map[string]any, len(attrs)/2)
	for i := 0; i+1 < len(attrs); i += 2 {
		key, ok := attrs[i].(string)
		if !ok || strings.TrimSpace(key) == "" {
			continue
		}
		fields[key] = attrs[i+1]
	}
	return fields
}
