package main

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func TestRun_RequiresLogparserURL(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	getenv := func(k string) string { return "" }

	var stderr safeBuffer
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"flock"}, getenv, io.Discard, &stderr)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error when LOGPARSER_URL is unset")
		}
		if !strings.Contains(err.Error(), "LOGPARSER_URL") {
			t.Fatalf("error = %v, want mention of LOGPARSER_URL", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return promptly on missing env")
	}
}

func TestRun_ParsesLogLevel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	getenv := func(k string) string {
		switch k {
		case "HTTP_ADDR":
			return "127.0.0.1:0"
		case "LOGPARSER_URL":
			return "http://127.0.0.1:1"
		case "LOG_LEVEL":
			return "debug"
		}
		return ""
	}

	var stderr safeBuffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"flock"}, getenv, io.Discard, &stderr) }()

	_ = waitForAddr(t, &stderr, 2*time.Second)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run err: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run hung")
	}

	if !strings.Contains(stderr.String(), `"level":"DEBUG"`) && !strings.Contains(stderr.String(), `"level":"INFO"`) {
		t.Fatalf("stderr lacks level field: %q", stderr.String())
	}
}
