package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCorpusBehavior(t *testing.T) {
	t.Parallel()
	corpusRoot := mustAbsolute(t, filepath.Join("..", "..", "corpus"))
	tests := []struct {
		name             string
		entrypoint       string
		expectedOutcome  string
		expectedCodePart string
		expectedPointer  string
	}{
		{
			name:            "OAS 3.0 valid",
			entrypoint:      "cases/oas30-valid.yaml",
			expectedOutcome: outcomeValid,
		},
		{
			name:            "OAS 3.1 valid",
			entrypoint:      "cases/oas31-valid.json",
			expectedOutcome: outcomeValid,
		},
		{
			name:            "OAS 3.0 invalid structure",
			entrypoint:      "cases/oas30-invalid-structure.yaml",
			expectedOutcome: outcomeInvalid,
			expectedPointer: "/paths/~1pets/get",
		},
		{
			name:            "OAS 3.1 invalid structure",
			entrypoint:      "cases/oas31-invalid-structure.json",
			expectedOutcome: outcomeInvalid,
			expectedPointer: "/info/version",
		},
		{
			name:             "malformed YAML",
			entrypoint:       "cases/malformed.yaml",
			expectedOutcome:  outcomeParseError,
			expectedCodePart: "parse",
		},
		{
			name:            "local reference valid",
			entrypoint:      "cases/local-ref/root.yaml",
			expectedOutcome: outcomeValid,
		},
		{
			name:            "local reference invalid",
			entrypoint:      "cases/local-ref-invalid/root.yaml",
			expectedOutcome: outcomeInvalid,
			expectedPointer: "/components/schemas/PetList/type",
		},
		{
			name:             "local reference missing",
			entrypoint:       "cases/missing-ref.yaml",
			expectedOutcome:  outcomeInvalid,
			expectedCodePart: "reference.not-found",
		},
		{
			name:             "remote reference denied",
			entrypoint:       "templates/remote-ref.yaml",
			expectedOutcome:  outcomePolicyDenied,
			expectedCodePart: "ref.scheme-denied",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			opts := testOptions(filepath.Join(corpusRoot, filepath.FromSlash(test.entrypoint)), corpusRoot)
			got, internalErr := evaluate(opts)
			if internalErr != nil {
				t.Fatalf("evaluate returned internal error: %v", internalErr)
			}
			if got.Outcome != test.expectedOutcome {
				t.Fatalf("outcome = %q, want %q; diagnostics: %#v", got.Outcome, test.expectedOutcome, got.Diagnostics)
			}
			if test.expectedOutcome == outcomeValid && len(got.Diagnostics) != 0 {
				t.Fatalf("valid result returned diagnostics: %#v", got.Diagnostics)
			}
			if test.expectedCodePart != "" && !anyDiagnostic(got.Diagnostics, func(diag diagnostic) bool {
				return strings.Contains(diag.Code, test.expectedCodePart)
			}) {
				t.Fatalf("no diagnostic code contains %q: %#v", test.expectedCodePart, got.Diagnostics)
			}
			if test.expectedPointer != "" && !anyDiagnostic(got.Diagnostics, func(diag diagnostic) bool {
				return strings.HasPrefix(diag.Pointer, test.expectedPointer)
			}) {
				t.Fatalf("no diagnostic pointer starts with %q: %#v", test.expectedPointer, got.Diagnostics)
			}
			for _, diag := range got.Diagnostics {
				if diag.Line < 1 || diag.Column < 1 {
					t.Fatalf("diagnostic has no usable location: %#v", diag)
				}
			}
		})
	}
}

func TestDeterministicResult(t *testing.T) {
	t.Parallel()
	corpusRoot := mustAbsolute(t, filepath.Join("..", "..", "corpus"))
	opts := testOptions(filepath.Join(corpusRoot, "cases", "oas30-invalid-structure.yaml"), corpusRoot)

	first, firstErr := evaluate(opts)
	second, secondErr := evaluate(opts)
	if firstErr != nil || secondErr != nil {
		t.Fatalf("evaluate errors: first=%v second=%v", firstErr, secondErr)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("results differ:\nfirst: %#v\nsecond: %#v", first, second)
	}
}

func TestLimitsAndPathPolicy(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	entrypoint := filepath.Join(root, "openapi.yaml")
	writeTestFile(t, entrypoint, `openapi: 3.1.0
info:
  title: Limits
  version: 1.0.0
paths: {}
`)

	tests := []struct {
		name            string
		mutate          func(options) options
		expectedOutcome string
		expectedCode    string
	}{
		{
			name: "byte limit",
			mutate: func(opts options) options {
				opts.MaxTotalBytes = 1
				return opts
			},
			expectedOutcome: outcomeLimitExceeded,
			expectedCode:    "ref.aggregate-bytes-exceeded",
		},
		{
			name: "file limit",
			mutate: func(opts options) options {
				opts.MaxFiles = 0
				return opts
			},
			expectedOutcome: outcomeLimitExceeded,
			expectedCode:    "ref.file-count-exceeded",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			opts := test.mutate(testOptions(entrypoint, root))
			got, internalErr := evaluate(opts)
			if internalErr != nil {
				t.Fatalf("evaluate returned internal error: %v", internalErr)
			}
			if got.Outcome != test.expectedOutcome {
				t.Fatalf("outcome = %q, want %q", got.Outcome, test.expectedOutcome)
			}
			if len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != test.expectedCode {
				t.Fatalf("unexpected diagnostics: %#v", got.Diagnostics)
			}
		})
	}
}

func TestReferenceEscapeDenied(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(parent, "outside.yaml"), "type: string\n")
	entrypoint := filepath.Join(root, "openapi.yaml")
	writeTestFile(t, entrypoint, `openapi: 3.1.0
info:
  title: Escape
  version: 1.0.0
paths: {}
components:
  schemas:
    Escape:
      $ref: ../outside.yaml
`)

	got, internalErr := evaluate(testOptions(entrypoint, root))
	if internalErr != nil {
		t.Fatalf("evaluate returned internal error: %v", internalErr)
	}
	if got.Outcome != outcomePolicyDenied {
		t.Fatalf("outcome = %q, want %q", got.Outcome, outcomePolicyDenied)
	}
	if len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "ref.path-outside-root" {
		t.Fatalf("unexpected diagnostics: %#v", got.Diagnostics)
	}
}

func TestJSONCommandContract(t *testing.T) {
	t.Parallel()
	corpusRoot := mustAbsolute(t, filepath.Join("..", "..", "corpus"))
	entrypoint := filepath.Join(corpusRoot, "cases", "oas30-valid.yaml")
	var stdout bytes.Buffer
	exitCode := run([]string{
		"--entrypoint", entrypoint,
		"--repository-root", corpusRoot,
		"--max-files", "16",
		"--max-total-bytes", "1048576",
		"--max-depth", "8",
		"--max-diagnostics", "10",
	}, &stdout)
	if exitCode != 0 {
		t.Fatalf("exit code = %d; output: %s", exitCode, stdout.String())
	}

	var got result
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("output is not one JSON object: %v\n%s", err, stdout.String())
	}
	if got.SchemaVersion != 1 || got.Adapter != adapterName || got.Outcome != outcomeValid {
		t.Fatalf("unexpected result: %#v", got)
	}
}

func TestAcceptanceCorpusControls(t *testing.T) {
	t.Parallel()
	acceptanceRoot := mustAbsolute(t, filepath.Join("..", "..", "corpus", "adapter-cases"))
	tests := []struct {
		name            string
		root            string
		entrypoint      string
		mutate          func(*options)
		expectedOutcome string
		expectedCode    string
		expectedFiles   int
		expectedDepth   int
		expectedLine    int
		expectedColumn  int
		expectedPointer string
	}{
		{
			name:            "duplicate YAML key",
			root:            "parse",
			entrypoint:      "parse/duplicate-key.yaml",
			expectedOutcome: outcomeParseError,
			expectedCode:    "parse.duplicate-key",
			expectedFiles:   0,
			expectedLine:    5,
			expectedColumn:  3,
		},
		{
			name:            "malformed JSON",
			root:            "parse",
			entrypoint:      "parse/malformed.json",
			expectedOutcome: outcomeParseError,
			expectedCode:    "parse.invalid-json",
			expectedFiles:   0,
			expectedLine:    5,
		},
		{
			name:            "canonical cycle terminates",
			root:            "cycles",
			entrypoint:      "cycles/root.json",
			expectedOutcome: outcomeValid,
			expectedFiles:   3,
			expectedDepth:   2,
		},
		{
			name:       "depth over limit",
			root:       "depth/over-limit",
			entrypoint: "depth/over-limit/root.yaml",
			mutate: func(opts *options) {
				opts.MaxDepth = 3
			},
			expectedOutcome: outcomeLimitExceeded,
			expectedCode:    "ref.depth-exceeded",
			expectedFiles:   4,
			expectedDepth:   3,
			expectedLine:    1,
			expectedColumn:  1,
			expectedPointer: "/$ref",
		},
		{
			name:       "file count over limit",
			root:       "limits/reference-closure",
			entrypoint: "limits/reference-closure/root.yaml",
			mutate: func(opts *options) {
				opts.MaxFiles = 3
			},
			expectedOutcome: outcomeLimitExceeded,
			expectedCode:    "ref.file-count-exceeded",
			expectedFiles:   3,
			expectedLine:    1,
			expectedColumn:  1,
			expectedPointer: "/$ref",
		},
		{
			name:       "aggregate bytes over limit",
			root:       "limits/reference-closure",
			entrypoint: "limits/reference-closure/root.yaml",
			mutate: func(opts *options) {
				opts.MaxTotalBytes = 378
			},
			expectedOutcome: outcomeLimitExceeded,
			expectedCode:    "ref.aggregate-bytes-exceeded",
			expectedFiles:   3,
			expectedLine:    1,
			expectedColumn:  1,
			expectedPointer: "/$ref",
		},
		{
			name:            "parent path denied at ref key",
			root:            "security/path-escape/repository",
			entrypoint:      "security/path-escape/repository/root.yaml",
			expectedOutcome: outcomePolicyDenied,
			expectedCode:    "ref.path-outside-root",
			expectedFiles:   1,
			expectedLine:    14,
			expectedColumn:  17,
			expectedPointer: "/paths/~1pets/get/responses/200/content/application~1json/schema/$ref",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := filepath.Join(acceptanceRoot, filepath.FromSlash(test.root))
			entrypoint := filepath.Join(acceptanceRoot, filepath.FromSlash(test.entrypoint))
			opts := testOptions(entrypoint, root)
			if test.mutate != nil {
				test.mutate(&opts)
			}
			got, internalErr := evaluate(opts)
			if internalErr != nil {
				t.Fatalf("evaluate returned internal error: %v", internalErr)
			}
			if got.Outcome != test.expectedOutcome {
				t.Fatalf("outcome = %q, want %q; diagnostics=%#v", got.Outcome, test.expectedOutcome, got.Diagnostics)
			}
			if got.Stats.FilesRead != test.expectedFiles {
				t.Fatalf("filesRead = %d, want %d", got.Stats.FilesRead, test.expectedFiles)
			}
			if test.expectedDepth > 0 && got.Stats.MaxDepthObserved != test.expectedDepth {
				t.Fatalf("maxDepthObserved = %d, want %d", got.Stats.MaxDepthObserved, test.expectedDepth)
			}
			if test.expectedCode == "" {
				return
			}
			if len(got.Diagnostics) != 1 {
				t.Fatalf("diagnostics = %d, want 1: %#v", len(got.Diagnostics), got.Diagnostics)
			}
			diag := got.Diagnostics[0]
			if diag.Code != test.expectedCode {
				t.Fatalf("code = %q, want %q", diag.Code, test.expectedCode)
			}
			if test.expectedLine > 0 && diag.Line != test.expectedLine {
				t.Fatalf("line = %d, want %d", diag.Line, test.expectedLine)
			}
			if test.expectedColumn > 0 && diag.Column != test.expectedColumn {
				t.Fatalf("column = %d, want %d", diag.Column, test.expectedColumn)
			}
			if test.expectedPointer != "" && diag.Pointer != test.expectedPointer {
				t.Fatalf("pointer = %q, want %q", diag.Pointer, test.expectedPointer)
			}
		})
	}
}

func testOptions(entrypoint string, root string) options {
	return options{
		Entrypoint:     entrypoint,
		RepositoryRoot: root,
		MaxFiles:       defaultMaxFiles,
		MaxTotalBytes:  defaultMaxTotalBytes,
		MaxDepth:       defaultMaxDepth,
		MaxDiagnostics: defaultMaxDiagnostics,
	}
}

func mustAbsolute(t *testing.T, path string) string {
	t.Helper()
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return absolute
}

func writeTestFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func anyDiagnostic(diagnostics []diagnostic, predicate func(diagnostic) bool) bool {
	for _, diag := range diagnostics {
		if predicate(diag) {
			return true
		}
	}
	return false
}
