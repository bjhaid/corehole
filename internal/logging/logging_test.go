package logging

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"
)

func TestJSONFormatEmitsStructuredFields(t *testing.T) {
	var buf bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(oldOutput)
	defer Configure("info", "text")

	Configure("debug", "json")
	Debug("admin_request", "method", "GET", "path", "/api/status", "status", 200)

	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record); err != nil {
		t.Fatalf("unmarshal log record: %v\n%s", err, buf.String())
	}
	if record["level"] != "debug" ||
		record["msg"] != "admin_request" ||
		record["method"] != "GET" ||
		record["path"] != "/api/status" ||
		record["status"] != float64(200) {
		t.Fatalf("record = %#v, want structured fields", record)
	}
}

func TestJSONFormatWrapsCoreDNSPluginLogs(t *testing.T) {
	var buf bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(oldOutput)
	defer Configure("info", "text")

	Configure("debug", "json")
	log.Print("[ERROR] plugin/errors: read udp 127.0.0.1:12345->1.1.1.1:53: i/o timeout")

	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record); err != nil {
		t.Fatalf("unmarshal log record: %v\n%s", err, buf.String())
	}
	if record["level"] != "error" ||
		record["component"] != "coredns" ||
		record["plugin"] != "errors" ||
		record["msg"] != "read udp 127.0.0.1:12345->1.1.1.1:53: i/o timeout" {
		t.Fatalf("record = %#v, want wrapped CoreDNS error fields", record)
	}
}

func TestJSONFormatPassesCoreDNSQueryJSON(t *testing.T) {
	var buf bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(oldOutput)
	defer Configure("info", "text")

	Configure("debug", "json")
	log.Print(`[INFO] {"component":"coredns","msg":"dns_query","name":"example.org.","type":"A","rcode":"NOERROR"}`)

	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record); err != nil {
		t.Fatalf("unmarshal log record: %v\n%s", err, buf.String())
	}
	if record["level"] != "info" ||
		record["component"] != "coredns" ||
		record["msg"] != "dns_query" ||
		record["name"] != "example.org." ||
		record["type"] != "A" ||
		record["rcode"] != "NOERROR" {
		t.Fatalf("record = %#v, want CoreDNS query fields", record)
	}
}

func TestTextFormatKeepsKeyValueFields(t *testing.T) {
	var buf bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(oldOutput)
	defer Configure("info", "text")

	Configure("debug", "text")
	Debug("admin_request", "method", "GET", "path", "/api/status", "status", 200)

	got := buf.String()
	for _, want := range []string{"[DEBUG] admin_request", "method=GET", "path=/api/status", "status=200"} {
		if !strings.Contains(got, want) {
			t.Fatalf("text log missing %q in %q", want, got)
		}
	}
}
