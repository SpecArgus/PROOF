package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing/fstest"

	"github.com/pb33f/libopenapi"
	validator "github.com/pb33f/libopenapi-validator"
	validatorerrors "github.com/pb33f/libopenapi-validator/errors"
	"github.com/pb33f/libopenapi/bundler"
	"github.com/pb33f/libopenapi/datamodel"
	"github.com/pb33f/libopenapi/index"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

var bracketLocationPattern = regexp.MustCompile(`\[(\d+):(\d+)\]`)

func evaluate(opts options) (res result, internalErr error) {
	res = emptyResult(outcomeInvalid)
	defer func() {
		if recovered := recover(); recovered != nil {
			internalErr = fmt.Errorf("libopenapi panic: %v", recovered)
		}
	}()

	scanner, issue, err := scanClosure(opts)
	if scanner != nil {
		defer scanner.close()
	}
	if err != nil {
		return res, err
	}
	if scanner != nil {
		res.Stats = scanner.stats
	}
	if issue != nil {
		res.Outcome = issue.Outcome
		res.Diagnostics = []diagnostic{issue.Diagnostic}
		if issue.Outcome == outcomeLimitExceeded {
			res.Stats.LimitCode = issue.Diagnostic.Code
		}
		finalizeResult(&res, opts.MaxDiagnostics)
		return res, nil
	}
	if scanner == nil || len(scanner.visitOrder) == 0 {
		return res, errors.New("reference closure was unexpectedly empty")
	}

	entrySnapshot := scanner.visitOrder[0]

	memoryFS := make(fstest.MapFS, len(scanner.visitOrder))
	fileFilter := make([]string, 0, len(scanner.visitOrder))
	for _, snapshot := range scanner.visitOrder {
		key := filepath.ToSlash(snapshot.Relative)
		memoryFS[key] = &fstest.MapFile{Data: snapshot.Data, Mode: 0o444}
		fileFilter = append(fileFilter, key)
	}
	sort.Strings(fileFilter)

	newDocumentConfig := func() *datamodel.DocumentConfiguration {
		config := datamodel.NewDocumentConfiguration()
		config.AllowFileReferences = true
		config.AllowRemoteReferences = false
		config.BasePath = scanner.root
		config.SpecFilePath = entrySnapshot.Absolute
		config.FileFilter = fileFilter
		config.LocalFS = memoryFS
		config.ExtractRefsSequentially = true
		config.ResolveNestedRefsWithDocumentContext = true
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
		return config
	}

	rawDocument, err := libopenapi.NewDocumentWithConfiguration(entrySnapshot.Data, newDocumentConfig())
	if err != nil {
		res.Diagnostics = diagnosticsFromErrors(scanner, entrySnapshot.Relative, "oas.schema", []error{err})
		res.Outcome = outcomeInvalid
		finalizeResult(&res, opts.MaxDiagnostics)
		return res, nil
	}
	rawValidator, rawBuildErrors := validator.NewValidator(rawDocument)
	if len(rawBuildErrors) > 0 {
		rawDocument.Release()
		res.Diagnostics = diagnosticsFromErrors(scanner, entrySnapshot.Relative, "oas.schema", rawBuildErrors)
		res.Outcome = outcomeInvalid
		finalizeResult(&res, opts.MaxDiagnostics)
		return res, nil
	}
	if rawValidator == nil {
		rawDocument.Release()
		return res, errors.New("raw validator construction returned nil without an error")
	}
	rawValid, rawValidationErrors := rawValidator.ValidateDocument()
	rawValidator.Release()
	rawDocument.Release()
	if !rawValid || len(rawValidationErrors) > 0 {
		res.Outcome = outcomeInvalid
		res.Diagnostics = diagnosticsFromValidation(scanner, entrySnapshot.Relative, nil, rawValidationErrors)
		finalizeResult(&res, opts.MaxDiagnostics)
		return res, nil
	}

	bundleResult, err := bundler.BundleBytesComposedWithOrigins(
		entrySnapshot.Data,
		newDocumentConfig(),
		&bundler.BundleCompositionConfig{Delimiter: "__"},
	)
	if err != nil || bundleResult == nil {
		var bundleErrors []error
		if err != nil {
			bundleErrors = append(bundleErrors, err)
		} else {
			bundleErrors = append(bundleErrors, errors.New("bundler returned no result"))
		}
		res.Diagnostics = diagnosticsFromErrors(scanner, entrySnapshot.Relative, "oas.schema", bundleErrors)
		res.Outcome = outcomeInvalid
		finalizeResult(&res, opts.MaxDiagnostics)
		return res, nil
	}

	document, err := libopenapi.NewDocument(bundleResult.Bytes)
	if err != nil {
		res.Diagnostics = diagnosticsFromErrors(scanner, entrySnapshot.Relative, "oas.schema", []error{err})
		res.Outcome = outcomeInvalid
		finalizeResult(&res, opts.MaxDiagnostics)
		return res, nil
	}
	defer document.Release()

	documentValidator, buildErrors := validator.NewValidator(document)
	if len(buildErrors) > 0 {
		res.Diagnostics = diagnosticsFromErrors(scanner, entrySnapshot.Relative, "oas.schema", buildErrors)
		res.Outcome = outcomeInvalid
		finalizeResult(&res, opts.MaxDiagnostics)
		return res, nil
	}
	if documentValidator == nil {
		return res, errors.New("validator construction returned nil without an error")
	}
	defer documentValidator.Release()

	valid, validationErrors := documentValidator.ValidateDocument()
	if valid && len(validationErrors) == 0 {
		res.Outcome = outcomeValid
		res.Diagnostics = make([]diagnostic, 0)
		finalizeResult(&res, opts.MaxDiagnostics)
		return res, nil
	}
	res.Outcome = outcomeInvalid
	res.Diagnostics = diagnosticsFromValidation(scanner, entrySnapshot.Relative, bundleResult.Origins, validationErrors)
	if len(res.Diagnostics) == 0 {
		res.Diagnostics = []diagnostic{{
			Source:   entrySnapshot.Relative,
			Line:     1,
			Column:   1,
			Code:     "oas.schema",
			Severity: "error",
			Kind:     "validation",
			Message:  "document validation failed without a structured diagnostic",
		}}
	}
	finalizeResult(&res, opts.MaxDiagnostics)
	return res, nil
}

func diagnosticsFromValidation(
	scanner *closureScanner,
	defaultSource string,
	origins bundler.ComponentOriginMap,
	validationErrors []*validatorerrors.ValidationError,
) []diagnostic {
	var diagnostics []diagnostic
	for _, validationError := range validationErrors {
		if validationError == nil {
			continue
		}
		if len(validationError.SchemaValidationErrors) == 0 {
			message := firstNonEmpty(validationError.Reason, validationError.Message, "document validation failed")
			diagnostics = append(diagnostics, diagnostic{
				Source:   defaultSource,
				Line:     positiveOr(validationError.SpecLine, 1),
				Column:   positiveOr(validationError.SpecCol, 1),
				Code:     validationCode(validationError, ""),
				Severity: "error",
				Kind:     "validation",
				Message:  sanitizeMessage(scanner.root, message),
			})
			continue
		}

		for _, failure := range validationError.SchemaValidationErrors {
			if failure == nil {
				continue
			}
			for _, leaf := range expandValidationFailure(failure) {
				pointer := leaf.Pointer
				source := defaultSource
				line := positiveOr(failure.Line, positiveOr(validationError.SpecLine, 1))
				column := positiveOr(failure.Column, positiveOr(validationError.SpecCol, 1))
				if locatedSource, locatedPointer, locatedPosition, ok := scanner.locateBundled(pointer, origins); ok {
					source = locatedSource
					pointer = locatedPointer
					line = locatedPosition.Line
					column = locatedPosition.Column
				}
				diagnostics = append(diagnostics, diagnostic{
					Source:   source,
					Line:     positiveOr(line, 1),
					Column:   positiveOr(column, 1),
					Pointer:  pointer,
					Code:     "oas.schema",
					Severity: "error",
					Kind:     "validation",
					Message: sanitizeMessage(scanner.root, firstNonEmpty(
						leaf.Message,
						failure.Reason,
						validationError.Reason,
						validationError.Message,
						"document validation failed",
					)),
				})
			}
		}
	}
	sortDiagnostics(diagnostics)
	return deduplicateDiagnostics(diagnostics)
}

type validationLeaf struct {
	Pointer string
	Message string
}

func expandValidationFailure(failure *validatorerrors.SchemaValidationFailure) []validationLeaf {
	var leaves []validationLeaf
	var visit func(*jsonschema.ValidationError)
	printer := message.NewPrinter(language.English)
	visit = func(validationError *jsonschema.ValidationError) {
		if validationError == nil {
			return
		}
		if len(validationError.Causes) > 0 {
			for _, cause := range validationError.Causes {
				visit(cause)
			}
			return
		}
		if validationError.ErrorKind == nil {
			return
		}
		leaves = append(leaves, validationLeaf{
			Pointer: rawSegmentsToPointer(validationError.InstanceLocation),
			Message: validationError.ErrorKind.LocalizedString(printer),
		})
	}
	visit(failure.OriginalJsonSchemaError)
	if len(leaves) == 0 {
		leaves = append(leaves, validationLeaf{
			Pointer: segmentsToPointer(failure.InstancePath),
			Message: failure.Reason,
		})
	}
	return leaves
}

func diagnosticsFromErrors(
	scanner *closureScanner,
	defaultSource string,
	code string,
	input []error,
) []diagnostic {
	flattened := flattenErrors(input)
	diagnostics := make([]diagnostic, 0, len(flattened))
	for _, err := range flattened {
		if err == nil {
			continue
		}
		diag := diagnostic{
			Source:   defaultSource,
			Line:     1,
			Column:   1,
			Code:     code,
			Severity: "error",
			Kind:     "validation",
			Message:  sanitizeMessage(scanner.root, err.Error()),
		}

		var indexingError *index.IndexingError
		if errors.As(err, &indexingError) {
			if indexingError.Node != nil {
				diag.Line = positiveOr(indexingError.Node.Line, 1)
				diag.Column = positiveOr(indexingError.Node.Column, 1)
			}
			diag.Pointer = normalizePotentialPointer(indexingError.Path)
			if source, position, ok := scanner.locate(diag.Pointer); ok {
				diag.Source = source
				diag.Line = position.Line
				diag.Column = position.Column
			}
		} else if match := bracketLocationPattern.FindStringSubmatch(err.Error()); len(match) == 3 {
			if line, parseErr := strconv.Atoi(match[1]); parseErr == nil {
				diag.Line = positiveOr(line, 1)
			}
			if column, parseErr := strconv.Atoi(match[2]); parseErr == nil {
				diag.Column = positiveOr(column, 1)
			}
		}
		diagnostics = append(diagnostics, diag)
	}
	if len(diagnostics) == 0 {
		diagnostics = append(diagnostics, diagnostic{
			Source:   defaultSource,
			Line:     1,
			Column:   1,
			Code:     code,
			Severity: "error",
			Kind:     "validation",
			Message:  "document processing failed",
		})
	}
	sortDiagnostics(diagnostics)
	return deduplicateDiagnostics(diagnostics)
}

func (s *closureScanner) locate(pointer string) (string, position, bool) {
	if pointer == "" {
		return "", position{}, false
	}
	snapshots := append([]*fileSnapshot(nil), s.visitOrder...)
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Relative < snapshots[j].Relative
	})
	for _, snapshot := range snapshots {
		if found, ok := snapshot.Locations[pointer]; ok {
			return snapshot.Relative, found, true
		}
	}
	return "", position{}, false
}

func (s *closureScanner) locateBundled(
	pointer string,
	origins bundler.ComponentOriginMap,
) (string, string, position, bool) {
	type originMatch struct {
		prefix string
		origin *bundler.ComponentOrigin
	}
	matches := make([]originMatch, 0, len(origins))
	for bundledRef, origin := range origins {
		if origin == nil {
			continue
		}
		prefix := strings.TrimPrefix(bundledRef, "#")
		if pointer == prefix || strings.HasPrefix(pointer, prefix+"/") {
			matches = append(matches, originMatch{prefix: prefix, origin: origin})
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if len(matches[i].prefix) != len(matches[j].prefix) {
			return len(matches[i].prefix) > len(matches[j].prefix)
		}
		return matches[i].prefix < matches[j].prefix
	})

	for _, match := range matches {
		snapshot := s.snapshotForOrigin(match.origin.OriginalFile)
		if snapshot == nil {
			continue
		}
		originalPointer := strings.TrimPrefix(match.origin.OriginalRef, "#")
		originalPointer += strings.TrimPrefix(pointer, match.prefix)
		located := position{
			Line:   positiveOr(match.origin.Line, 1),
			Column: positiveOr(match.origin.Column, 1),
		}
		if exact, ok := snapshot.Locations[originalPointer]; ok {
			located = exact
		}
		return snapshot.Relative, originalPointer, located, true
	}

	if source, located, ok := s.locate(pointer); ok {
		return source, pointer, located, true
	}
	return "", pointer, position{}, false
}

func (s *closureScanner) snapshotForOrigin(originalFile string) *fileSnapshot {
	if originalFile == "" {
		return nil
	}
	candidate := filepath.FromSlash(originalFile)
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(s.root, candidate)
	}
	if snapshot := s.files[canonicalKey(candidate)]; snapshot != nil {
		return snapshot
	}
	normalized := filepath.ToSlash(filepath.Clean(originalFile))
	for _, snapshot := range s.visitOrder {
		if snapshot.Relative == normalized ||
			strings.HasSuffix(filepath.ToSlash(snapshot.Absolute), "/"+strings.TrimPrefix(normalized, "/")) {
			return snapshot
		}
	}
	return nil
}

func finalizeResult(res *result, maxDiagnostics int) {
	if res.Diagnostics == nil {
		res.Diagnostics = make([]diagnostic, 0)
	}
	sortDiagnostics(res.Diagnostics)
	res.Diagnostics = deduplicateDiagnostics(res.Diagnostics)
	res.Stats.DiagnosticsRaw = len(res.Diagnostics)
	if len(res.Diagnostics) > maxDiagnostics {
		res.Stats.DiagnosticsTruncated = len(res.Diagnostics) - maxDiagnostics
		res.Diagnostics = res.Diagnostics[:maxDiagnostics]
		res.Outcome = outcomeLimitExceeded
		res.Stats.LimitCode = "diagnostics.limit-exceeded"
	}
	res.Stats.DiagnosticsEmitted = len(res.Diagnostics)
}

func sortDiagnostics(diagnostics []diagnostic) {
	sort.SliceStable(diagnostics, func(i, j int) bool {
		left := diagnostics[i]
		right := diagnostics[j]
		switch {
		case left.Source != right.Source:
			return left.Source < right.Source
		case left.Line != right.Line:
			return left.Line < right.Line
		case left.Column != right.Column:
			return left.Column < right.Column
		case left.Pointer != right.Pointer:
			return left.Pointer < right.Pointer
		case left.Code != right.Code:
			return left.Code < right.Code
		case left.Severity != right.Severity:
			return left.Severity < right.Severity
		case left.Kind != right.Kind:
			return left.Kind < right.Kind
		default:
			return left.Message < right.Message
		}
	})
}

func deduplicateDiagnostics(input []diagnostic) []diagnostic {
	if len(input) < 2 {
		return input
	}
	output := input[:0]
	var previous diagnostic
	for i, current := range input {
		if i == 0 || current != previous {
			output = append(output, current)
			previous = current
		}
	}
	return output
}

func flattenErrors(input []error) []error {
	var output []error
	var visit func(error)
	visit = func(err error) {
		if err == nil {
			return
		}
		if multi, ok := err.(interface{ Unwrap() []error }); ok {
			children := multi.Unwrap()
			if len(children) > 0 {
				for _, child := range children {
					visit(child)
				}
				return
			}
		}
		output = append(output, err)
	}
	for _, err := range input {
		visit(err)
	}
	return output
}

func segmentsToPointer(segments []string) string {
	if len(segments) == 0 {
		return ""
	}
	var builder strings.Builder
	for _, segment := range segments {
		builder.WriteByte('/')
		decoded := strings.ReplaceAll(strings.ReplaceAll(segment, "~1", "/"), "~0", "~")
		builder.WriteString(escapePointerSegment(decoded))
	}
	return builder.String()
}

func rawSegmentsToPointer(segments []string) string {
	if len(segments) == 0 {
		return ""
	}
	var builder strings.Builder
	for _, segment := range segments {
		builder.WriteByte('/')
		builder.WriteString(escapePointerSegment(segment))
	}
	return builder.String()
}

func validationCode(validationError *validatorerrors.ValidationError, keywordLocation string) string {
	return "oas.schema"
}

func normalizePotentialPointer(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "/") {
		return value
	}
	if strings.HasPrefix(value, "$.") {
		segments := strings.Split(strings.TrimPrefix(value, "$."), ".")
		return segmentsToPointer(segments)
	}
	return ""
}

func sanitizeMessage(root string, message string) string {
	message = strings.ReplaceAll(message, root, "<repository>")
	message = strings.ReplaceAll(message, filepath.ToSlash(root), "<repository>")
	return normalizeWhitespace(message)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
