package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/bjhaid/corehole/internal/app"
)

func TestRunVersionPrintsInjectedVersion(t *testing.T) {
	oldStdout := os.Stdout
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = write
	t.Cleanup(func() {
		os.Stdout = oldStdout
		_ = read.Close()
	})

	if err := run([]string{"version"}); err != nil {
		t.Fatalf("run version error = %v", err)
	}
	if err := write.Close(); err != nil {
		t.Fatalf("close stdout pipe: %v", err)
	}
	var out bytes.Buffer
	if _, err := io.Copy(&out, read); err != nil {
		t.Fatalf("read stdout pipe: %v", err)
	}

	if got, want := strings.TrimSpace(out.String()), app.Version(); got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}

func TestRunWithoutCommandPrintsUsage(t *testing.T) {
	oldStdout := os.Stdout
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = write
	t.Cleanup(func() {
		os.Stdout = oldStdout
		_ = read.Close()
	})

	if err := run(nil); err != nil {
		t.Fatalf("run nil args error = %v", err)
	}
	if err := write.Close(); err != nil {
		t.Fatalf("close stdout pipe: %v", err)
	}
	var out bytes.Buffer
	if _, err := io.Copy(&out, read); err != nil {
		t.Fatalf("read stdout pipe: %v", err)
	}

	if !strings.Contains(out.String(), "usage: corehole <serve|version> [options]") {
		t.Fatalf("usage output = %q", out.String())
	}
}
