package main

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

const validTestDocument = `openapi: 3.1.0
info:
  title: Hardening
  version: 1.0.0
paths: {}
`

func TestRelativeEntrypointUsesCanonicalRepositoryRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "openapi.yaml"), validTestDocument)

	got, internalErr := evaluate(testOptions("openapi.yaml", root))
	if internalErr != nil {
		t.Fatalf("evaluate returned internal error: %v", internalErr)
	}
	if got.Outcome != outcomeValid {
		t.Fatalf("outcome = %q, want %q; diagnostics=%#v", got.Outcome, outcomeValid, got.Diagnostics)
	}
}

func TestAbsoluteEntrypointAcceptsFilesystemAliasIntoRepository(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "openapi.yaml"), validTestDocument)

	aliasParent := t.TempDir()
	aliasRoot := filepath.Join(aliasParent, "repository-alias")
	if err := os.Symlink(root, aliasRoot); err != nil {
		t.Skipf("filesystem aliases are unavailable: %v", err)
	}

	got, internalErr := evaluate(testOptions(filepath.Join(aliasRoot, "openapi.yaml"), root))
	if internalErr != nil {
		t.Fatalf("evaluate returned internal error: %v", internalErr)
	}
	if got.Outcome != outcomeValid {
		t.Fatalf("outcome = %q, want %q; diagnostics=%#v", got.Outcome, outcomeValid, got.Diagnostics)
	}
}

func TestEntrypointSymlinkEscapeRemainsDenied(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	outsideEntrypoint := filepath.Join(outside, "openapi.yaml")
	writeTestFile(t, outsideEntrypoint, validTestDocument)

	entrypoint := filepath.Join(root, "openapi.yaml")
	if err := os.Symlink(outsideEntrypoint, entrypoint); err != nil {
		t.Skipf("filesystem links are unavailable: %v", err)
	}

	got, internalErr := evaluate(testOptions(entrypoint, root))
	if internalErr != nil {
		t.Fatalf("evaluate returned internal error: %v", internalErr)
	}
	if got.Outcome != outcomePolicyDenied {
		t.Fatalf("outcome = %q, want %q; diagnostics=%#v", got.Outcome, outcomePolicyDenied, got.Diagnostics)
	}
	if len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "ref.path-outside-root" {
		t.Fatalf("unexpected diagnostics: %#v", got.Diagnostics)
	}
}

func TestYAMLMultiDocumentStreamRejected(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	entrypoint := filepath.Join(root, "openapi.yaml")
	writeTestFile(t, entrypoint, validTestDocument+"---\nopenapi: 3.1.0\n")

	got, internalErr := evaluate(testOptions(entrypoint, root))
	if internalErr != nil {
		t.Fatalf("evaluate returned internal error: %v", internalErr)
	}
	if got.Outcome != outcomeParseError {
		t.Fatalf("outcome = %q, want %q", got.Outcome, outcomeParseError)
	}
	if len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "parse.multiple-documents" {
		t.Fatalf("unexpected diagnostics: %#v", got.Diagnostics)
	}
}

func TestInvalidUTF8Rejected(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	entrypoint := filepath.Join(root, "openapi.yaml")
	data := append([]byte("openapi: 3.1.0\ninfo:\n  title: "), 0xff)
	data = append(data, []byte("\n  version: 1.0.0\npaths: {}\n")...)
	if err := os.WriteFile(entrypoint, data, 0o600); err != nil {
		t.Fatal(err)
	}

	got, internalErr := evaluate(testOptions(entrypoint, root))
	if internalErr != nil {
		t.Fatalf("evaluate returned internal error: %v", internalErr)
	}
	if got.Outcome != outcomeParseError {
		t.Fatalf("outcome = %q, want %q", got.Outcome, outcomeParseError)
	}
	if len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "parse.invalid-utf8" {
		t.Fatalf("unexpected diagnostics: %#v", got.Diagnostics)
	}
	if got.Diagnostics[0].Line != 3 || got.Diagnostics[0].Column != 10 {
		t.Fatalf("unexpected UTF-8 location: %#v", got.Diagnostics[0])
	}
}

func TestYAMLCyclicAliasRejected(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	entrypoint := filepath.Join(root, "openapi.yaml")
	writeTestFile(t, entrypoint, validTestDocument+"x-cycle: &cycle [*cycle]\n")

	got, internalErr := evaluate(testOptions(entrypoint, root))
	if internalErr != nil {
		t.Fatalf("evaluate returned internal error: %v", internalErr)
	}
	if got.Outcome != outcomeParseError {
		t.Fatalf("outcome = %q, want %q", got.Outcome, outcomeParseError)
	}
	if len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "parse.cyclic-alias" {
		t.Fatalf("unexpected diagnostics: %#v", got.Diagnostics)
	}
	if got.Diagnostics[0].Line != 6 || got.Diagnostics[0].Column != 18 {
		t.Fatalf("unexpected cyclic alias location: %#v", got.Diagnostics[0])
	}
	if got.Diagnostics[0].Pointer != "/x-cycle/0" {
		t.Fatalf("pointer = %q, want %q", got.Diagnostics[0].Pointer, "/x-cycle/0")
	}
}

func TestYAMLAcyclicAliasAccepted(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	entrypoint := filepath.Join(root, "openapi.yaml")
	writeTestFile(t, entrypoint, validTestDocument+`x-template: &template
  enabled: true
x-copy: *template
`)

	got, internalErr := evaluate(testOptions(entrypoint, root))
	if internalErr != nil {
		t.Fatalf("evaluate returned internal error: %v", internalErr)
	}
	if got.Outcome != outcomeValid {
		t.Fatalf("outcome = %q, want %q; diagnostics=%#v", got.Outcome, outcomeValid, got.Diagnostics)
	}
}

func TestMaxInt64AggregateLimitDoesNotOverflowReadLimit(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	entrypoint := filepath.Join(root, "openapi.yaml")
	writeTestFile(t, entrypoint, validTestDocument)
	opts := testOptions(entrypoint, root)
	opts.MaxTotalBytes = math.MaxInt64

	got, internalErr := evaluate(opts)
	if internalErr != nil {
		t.Fatalf("evaluate returned internal error: %v", internalErr)
	}
	if got.Outcome != outcomeValid {
		t.Fatalf("outcome = %q, want %q; diagnostics=%#v", got.Outcome, outcomeValid, got.Diagnostics)
	}
	if got.Stats.EntrypointBytes != int64(len(validTestDocument)) {
		t.Fatalf("entrypointBytes = %d, want %d", got.Stats.EntrypointBytes, len(validTestDocument))
	}
}

func TestContractFailureExitAndStats(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	exitCode := run([]string{"--unknown", "value"}, &stdout)
	if exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}

	var got result
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("output is not one JSON object: %v\n%s", err, stdout.String())
	}
	if got.Outcome != outcomeInvalid || len(got.Diagnostics) != 1 {
		t.Fatalf("unexpected result: %#v", got)
	}
	if got.Diagnostics[0].Kind != "contract" || got.Diagnostics[0].Code != "adapter-contract-error" {
		t.Fatalf("unexpected contract diagnostic: %#v", got.Diagnostics[0])
	}
	assertDiagnosticStats(t, got, 1, 1, 0)
}

func TestInternalFailureExitAndStats(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "missing")
	var stdout bytes.Buffer
	exitCode := run([]string{
		"--entrypoint", "openapi.yaml",
		"--repository-root", root,
	}, &stdout)
	if exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}

	var got result
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("output is not one JSON object: %v\n%s", err, stdout.String())
	}
	if got.Outcome != outcomeInvalid || len(got.Diagnostics) != 1 {
		t.Fatalf("unexpected result: %#v", got)
	}
	if got.Diagnostics[0].Kind != "internal" || got.Diagnostics[0].Code != "adapter-internal-error" {
		t.Fatalf("unexpected internal diagnostic: %#v", got.Diagnostics[0])
	}
	assertDiagnosticStats(t, got, 1, 1, 0)
}

func TestZeroDiagnosticLimitReportsExactTruncation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	entrypoint := filepath.Join(root, "invalid.yaml")
	writeTestFile(t, entrypoint, "not: [valid\n")
	opts := testOptions(entrypoint, root)
	opts.MaxDiagnostics = 0

	got, internalErr := evaluate(opts)
	if internalErr != nil {
		t.Fatalf("evaluate returned internal error: %v", internalErr)
	}
	if got.Outcome != outcomeLimitExceeded {
		t.Fatalf("outcome = %q, want %q", got.Outcome, outcomeLimitExceeded)
	}
	assertDiagnosticStats(t, got, 1, 0, 1)
	if got.Stats.LimitCode != "diagnostics.limit-exceeded" {
		t.Fatalf("limitCode = %q", got.Stats.LimitCode)
	}
}

func assertDiagnosticStats(t *testing.T, got result, raw int, emitted int, truncated int) {
	t.Helper()
	if got.Stats.DiagnosticsRaw != raw ||
		got.Stats.DiagnosticsEmitted != emitted ||
		got.Stats.DiagnosticsTruncated != truncated {
		t.Fatalf(
			"diagnostic stats = raw:%d emitted:%d truncated:%d, want raw:%d emitted:%d truncated:%d",
			got.Stats.DiagnosticsRaw,
			got.Stats.DiagnosticsEmitted,
			got.Stats.DiagnosticsTruncated,
			raw,
			emitted,
			truncated,
		)
	}
}
