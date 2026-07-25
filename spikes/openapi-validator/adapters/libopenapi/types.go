package main

const (
	adapterName = "libopenapi"

	outcomeValid         = "valid"
	outcomeInvalid       = "invalid"
	outcomeParseError    = "parse-error"
	outcomePolicyDenied  = "policy-denied"
	outcomeLimitExceeded = "limit-exceeded"
)

type diagnostic struct {
	Source   string `json:"source"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Pointer  string `json:"pointer"`
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Kind     string `json:"kind"`
	Message  string `json:"message"`
}

type statistics struct {
	FilesRead            int    `json:"filesRead"`
	EntrypointBytes      int64  `json:"entrypointBytes"`
	TotalBytes           int64  `json:"totalBytes"`
	ReferencesSeen       int    `json:"referencesSeen"`
	MaxDepthObserved     int    `json:"maxDepthObserved"`
	DiagnosticsRaw       int    `json:"diagnosticsRaw"`
	DiagnosticsEmitted   int    `json:"diagnosticsEmitted"`
	DiagnosticsTruncated int    `json:"diagnosticsTruncated"`
	LimitCode            string `json:"limitCode"`
}

type result struct {
	SchemaVersion int          `json:"schemaVersion"`
	Adapter       string       `json:"adapter"`
	Outcome       string       `json:"outcome"`
	Diagnostics   []diagnostic `json:"diagnostics"`
	Stats         statistics   `json:"stats"`
}

type options struct {
	Entrypoint         string
	RepositoryRoot     string
	MaxEntrypointBytes int64
	MaxFiles           int
	MaxTotalBytes      int64
	MaxDepth           int
	MaxDiagnostics     int
}

func emptyResult(outcome string) result {
	return result{
		SchemaVersion: 1,
		Adapter:       adapterName,
		Outcome:       outcome,
		Diagnostics:   make([]diagnostic, 0),
	}
}
