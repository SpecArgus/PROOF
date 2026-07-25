package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const (
	defaultMaxFiles       = 256
	defaultMaxTotalBytes  = 64 * 1024 * 1024
	defaultMaxDepth       = 32
	defaultMaxDiagnostics = 100
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

func run(args []string, stdout io.Writer) int {
	opts, err := parseOptions(args)
	if err != nil {
		res := failureResult(
			"adapter-contract-error",
			"contract",
			err.Error(),
		)
		_ = writeResult(stdout, res)
		return 2
	}

	res, internalErr := evaluate(opts)
	exitCode := 0
	if internalErr != nil {
		res = failureResult(
			"adapter-internal-error",
			"internal",
			"the adapter encountered an unexpected internal error",
		)
		exitCode = 2
	}

	if err := writeResult(stdout, res); err != nil {
		return 2
	}
	return exitCode
}

func parseOptions(args []string) (options, error) {
	var opts options
	flags := flag.NewFlagSet("proof-libopenapi-adapter", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.Entrypoint, "entrypoint", "", "OpenAPI entrypoint file")
	flags.StringVar(&opts.RepositoryRoot, "repository-root", "", "root directory containing all permitted files")
	flags.Int64Var(&opts.MaxEntrypointBytes, "max-entrypoint-bytes", 0,
		"maximum entrypoint bytes (zero disables the separate limit)")
	flags.IntVar(&opts.MaxFiles, "max-files", defaultMaxFiles, "maximum number of files in the reference closure")
	flags.Int64Var(&opts.MaxTotalBytes, "max-total-bytes", defaultMaxTotalBytes, "maximum bytes in the reference closure")
	flags.IntVar(&opts.MaxDepth, "max-depth", defaultMaxDepth, "maximum external-reference depth")
	flags.IntVar(&opts.MaxDiagnostics, "max-diagnostics", defaultMaxDiagnostics, "maximum emitted diagnostics")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return options{}, errors.New("help is not available on the JSON adapter interface")
		}
		return options{}, fmt.Errorf("invalid arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return options{}, errors.New("positional arguments are not supported")
	}
	if opts.Entrypoint == "" {
		return options{}, errors.New("--entrypoint is required")
	}
	if opts.RepositoryRoot == "" {
		return options{}, errors.New("--repository-root is required")
	}
	if opts.MaxFiles < 0 {
		return options{}, errors.New("--max-files must not be negative")
	}
	if opts.MaxEntrypointBytes < 0 {
		return options{}, errors.New("--max-entrypoint-bytes must not be negative")
	}
	if opts.MaxTotalBytes < 0 {
		return options{}, errors.New("--max-total-bytes must not be negative")
	}
	if opts.MaxDepth < 0 {
		return options{}, errors.New("--max-depth must not be negative")
	}
	if opts.MaxDiagnostics < 0 {
		return options{}, errors.New("--max-diagnostics must not be negative")
	}
	return opts, nil
}

func failureResult(code string, kind string, message string) result {
	res := emptyResult(outcomeInvalid)
	res.Diagnostics = append(res.Diagnostics, diagnostic{
		Line:     1,
		Column:   1,
		Code:     code,
		Severity: "error",
		Kind:     kind,
		Message:  message,
	})
	res.Stats.DiagnosticsRaw = 1
	res.Stats.DiagnosticsEmitted = 1
	return res
}

func writeResult(w io.Writer, res result) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(res)
}
