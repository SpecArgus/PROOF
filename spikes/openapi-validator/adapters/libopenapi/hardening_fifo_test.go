//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestFIFOEntrypointRejectedWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	entrypoint := filepath.Join(root, "openapi.yaml")
	if err := syscall.Mkfifo(entrypoint, 0o600); err != nil {
		t.Fatalf("create FIFO: %v", err)
	}

	type evaluation struct {
		result      result
		internalErr error
	}
	done := make(chan evaluation, 1)
	go func() {
		got, internalErr := evaluate(testOptions(entrypoint, root))
		done <- evaluation{result: got, internalErr: internalErr}
	}()

	var completed evaluation
	select {
	case completed = <-done:
	case <-time.After(2 * time.Second):
		// If the regression returns, release a reader blocked in open(2) before
		// failing so the test process does not retain a stuck goroutine.
		writer, _ := os.OpenFile(entrypoint, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if writer != nil {
			_ = writer.Close()
		}
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("evaluation blocked while opening a FIFO")
	}

	if completed.internalErr != nil {
		t.Fatalf("evaluate returned internal error: %v", completed.internalErr)
	}
	if completed.result.Outcome != outcomeInvalid {
		t.Fatalf("outcome = %q, want %q", completed.result.Outcome, outcomeInvalid)
	}
	if len(completed.result.Diagnostics) != 1 ||
		completed.result.Diagnostics[0].Code != "reference.not-regular-file" {
		t.Fatalf("unexpected diagnostics: %#v", completed.result.Diagnostics)
	}
	if completed.result.Stats.FilesRead != 0 {
		t.Fatalf("filesRead = %d, want 0", completed.result.Stats.FilesRead)
	}
}
