package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

var yamlLinePattern = regexp.MustCompile(`(?i)\bline\s+(\d+)`)

type position struct {
	Line   int
	Column int
}

type fileSnapshot struct {
	Absolute  string
	Relative  string
	Data      []byte
	Locations map[string]position
}

type referenceOccurrence struct {
	Value   string
	Source  string
	Line    int
	Column  int
	Pointer string
}

type classifiedIssue struct {
	Outcome    string
	Diagnostic diagnostic
}

type closureScanner struct {
	root       string
	rootFS     *os.Root
	opts       options
	files      map[string]*fileSnapshot
	visitOrder []*fileSnapshot
	stats      statistics
}

func scanClosure(opts options) (*closureScanner, *classifiedIssue, error) {
	root, err := canonicalDirectory(opts.RepositoryRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve repository root: %w", err)
	}
	rootFS, err := os.OpenRoot(root)
	if err != nil {
		return nil, nil, fmt.Errorf("open repository root: %w", err)
	}
	scanner := &closureScanner{
		root:   root,
		rootFS: rootFS,
		opts:   opts,
		files:  make(map[string]*fileSnapshot),
	}

	entryPath := opts.Entrypoint
	if !filepath.IsAbs(entryPath) && filepath.VolumeName(entryPath) == "" {
		entryPath = filepath.Join(root, entryPath)
	}
	entryAbs, err := filepath.Abs(entryPath)
	if err != nil {
		return scanner, nil, fmt.Errorf("resolve entrypoint: %w", err)
	}
	entryAbs = filepath.Clean(entryAbs)
	if !isWithin(root, entryAbs) {
		return scanner, &classifiedIssue{
			Outcome: outcomePolicyDenied,
			Diagnostic: diagnostic{
				Code:     "ref.path-outside-root",
				Severity: "error",
				Kind:     "policy",
				Message:  "entrypoint is outside the repository root",
			},
		}, nil
	}

	entryCanonical, err := canonicalExistingPath(entryAbs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return scanner, &classifiedIssue{
				Outcome: outcomeInvalid,
				Diagnostic: diagnostic{
					Source:   relativeSource(root, entryAbs),
					Line:     1,
					Column:   1,
					Code:     "ref.not-found",
					Severity: "error",
					Kind:     "parse",
					Message:  "entrypoint does not exist",
				},
			}, nil
		}
		return scanner, nil, fmt.Errorf("resolve entrypoint symlinks: %w", err)
	}
	entryCanonical, err = filepath.Abs(entryCanonical)
	if err != nil {
		return scanner, nil, fmt.Errorf("resolve canonical entrypoint: %w", err)
	}
	if !isWithin(root, entryCanonical) {
		return scanner, &classifiedIssue{
			Outcome: outcomePolicyDenied,
			Diagnostic: diagnostic{
				Source:   relativeSource(root, entryAbs),
				Line:     1,
				Column:   1,
				Code:     "ref.path-outside-root",
				Severity: "error",
				Kind:     "policy",
				Message:  "entrypoint resolves outside the repository root",
			},
		}, nil
	}

	issue, err := scanner.load(entryCanonical, 0, &referenceOccurrence{
		Source: relativeSource(root, entryCanonical),
		Line:   1,
		Column: 1,
	})
	return scanner, issue, err
}

func (s *closureScanner) close() {
	if s.rootFS != nil {
		_ = s.rootFS.Close()
	}
}

func canonicalDirectory(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	canonical, err := canonicalExistingPath(absolute)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("path is not a directory")
	}
	return filepath.Clean(canonical), nil
}

func (s *closureScanner) load(path string, depth int, origin *referenceOccurrence) (*classifiedIssue, error) {
	key := canonicalKey(path)
	if _, ok := s.files[key]; ok {
		return nil, nil
	}
	if depth > s.opts.MaxDepth {
		return s.issueFromOrigin(origin, outcomeLimitExceeded, "ref.depth-exceeded", "limit",
			fmt.Sprintf("external reference depth exceeds %d", s.opts.MaxDepth)), nil
	}
	if depth > s.stats.MaxDepthObserved {
		s.stats.MaxDepthObserved = depth
	}

	if len(s.files) >= s.opts.MaxFiles {
		return s.issueFromOrigin(origin, outcomeLimitExceeded, "ref.file-count-exceeded", "limit",
			fmt.Sprintf("reference closure exceeds %d files", s.opts.MaxFiles)), nil
	}

	relative, err := filepath.Rel(s.root, path)
	if err != nil || !filepath.IsLocal(relative) {
		return s.issueFromOrigin(origin, outcomePolicyDenied, "ref.path-outside-root", "policy",
			"local reference escapes the repository root"), nil
	}
	file, err := openRootFileForRead(s.rootFS, relative)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return s.issueFromOrigin(origin, outcomeInvalid, "reference.not-found", "reference",
				"local reference does not exist"), nil
		}
		return s.issueFromOrigin(origin, outcomeInvalid, "reference.unreadable", "reference",
			"local reference cannot be read"), nil
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return s.issueFromOrigin(origin, outcomeInvalid, "reference.unreadable", "reference",
			"local reference cannot be inspected"), nil
	}
	if !info.Mode().IsRegular() {
		return s.issueFromOrigin(origin, outcomeInvalid, "reference.not-regular-file", "reference",
			"local reference is not a regular file"), nil
	}
	if !supportedDocumentExtension(path) {
		return s.issueFromOrigin(origin, outcomePolicyDenied, "policy.unsupported-file-type", "policy",
			"only JSON and YAML reference files are permitted"), nil
	}
	if depth == 0 && s.opts.MaxEntrypointBytes > 0 && info.Size() > s.opts.MaxEntrypointBytes {
		return s.issueFromOrigin(origin, outcomeLimitExceeded, "input.entrypoint-bytes-exceeded", "limit",
			fmt.Sprintf("entrypoint exceeds %d bytes", s.opts.MaxEntrypointBytes)), nil
	}
	remaining := s.opts.MaxTotalBytes - s.stats.TotalBytes
	if remaining < 0 || info.Size() > remaining {
		return s.issueFromOrigin(origin, outcomeLimitExceeded, "ref.aggregate-bytes-exceeded", "limit",
			fmt.Sprintf("reference closure exceeds %d bytes", s.opts.MaxTotalBytes)), nil
	}

	readLimit := remaining
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	data, err := io.ReadAll(io.LimitReader(file, readLimit))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", relativeSource(s.root, path), err)
	}
	if depth == 0 && s.opts.MaxEntrypointBytes > 0 && int64(len(data)) > s.opts.MaxEntrypointBytes {
		return s.issueFromOrigin(origin, outcomeLimitExceeded, "input.entrypoint-bytes-exceeded", "limit",
			fmt.Sprintf("entrypoint exceeds %d bytes", s.opts.MaxEntrypointBytes)), nil
	}
	if int64(len(data)) > remaining {
		return s.issueFromOrigin(origin, outcomeLimitExceeded, "ref.aggregate-bytes-exceeded", "limit",
			fmt.Sprintf("reference closure exceeds %d bytes", s.opts.MaxTotalBytes)), nil
	}

	rootNode, parseDiagnostic := parseDocument(path, relativeSource(s.root, path), data)
	if parseDiagnostic != nil {
		return &classifiedIssue{Outcome: outcomeParseError, Diagnostic: *parseDiagnostic}, nil
	}

	snapshot := &fileSnapshot{
		Absolute:  path,
		Relative:  relativeSource(s.root, path),
		Data:      data,
		Locations: make(map[string]position),
	}
	indexLocations(rootNode, "", snapshot.Locations, make(map[*yaml.Node]bool))
	s.files[key] = snapshot
	s.visitOrder = append(s.visitOrder, snapshot)
	s.stats.FilesRead++
	if depth == 0 {
		s.stats.EntrypointBytes = int64(len(data))
	}
	s.stats.TotalBytes += int64(len(data))

	refs := collectReferences(rootNode, snapshot.Relative)
	s.stats.ReferencesSeen += len(refs)
	for i := range refs {
		ref := refs[i]
		target, issue := s.resolveReference(path, &ref)
		if issue != nil {
			return issue, nil
		}
		if target == "" {
			continue
		}
		issue, err := s.load(target, depth+1, &ref)
		if issue != nil || err != nil {
			return issue, err
		}
	}
	return nil, nil
}

func (s *closureScanner) resolveReference(currentFile string, ref *referenceOccurrence) (string, *classifiedIssue) {
	value := strings.TrimSpace(ref.Value)
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(value, "//") {
		return "", s.issueFromOrigin(ref, outcomePolicyDenied, "ref.scheme-denied", "policy",
			"remote references are not permitted")
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return "", s.issueFromOrigin(ref, outcomeInvalid, "reference.invalid-uri", "reference",
			"reference URI is invalid")
	}
	if parsed.Scheme != "" || parsed.Host != "" || parsed.User != nil || parsed.Opaque != "" {
		return "", s.issueFromOrigin(ref, outcomePolicyDenied, "ref.scheme-denied", "policy",
			"non-file references are not permitted")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return "", s.issueFromOrigin(ref, outcomePolicyDenied, "policy.reference-query", "policy",
			"queries in local references are not permitted")
	}

	rawPath, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil {
		return "", s.issueFromOrigin(ref, outcomeInvalid, "reference.invalid-uri", "reference",
			"reference URI contains invalid escaping")
	}
	if rawPath == "" {
		return "", nil
	}
	if strings.Contains(rawPath, `\`) {
		return "", s.issueFromOrigin(ref, outcomePolicyDenied, "policy.non-portable-path", "policy",
			"backslashes in local references are not permitted")
	}
	localPath := filepath.FromSlash(rawPath)
	if filepath.IsAbs(localPath) || filepath.VolumeName(localPath) != "" {
		return "", s.issueFromOrigin(ref, outcomePolicyDenied, "ref.path-outside-root", "policy",
			"absolute local references are not permitted")
	}

	target := filepath.Clean(filepath.Join(filepath.Dir(currentFile), localPath))
	if !isWithin(s.root, target) {
		return "", s.issueFromOrigin(ref, outcomePolicyDenied, "ref.path-outside-root", "policy",
			"local reference escapes the repository root")
	}
	canonical, err := canonicalExistingPath(target)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", s.issueFromOrigin(ref, outcomeInvalid, "reference.not-found", "reference",
				"local reference does not exist")
		}
		return "", s.issueFromOrigin(ref, outcomeInvalid, "reference.unreadable", "reference",
			"local reference cannot be resolved")
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return "", s.issueFromOrigin(ref, outcomeInvalid, "reference.invalid-path", "reference",
			"local reference path is invalid")
	}
	canonical = filepath.Clean(canonical)
	if !isWithin(s.root, canonical) {
		return "", s.issueFromOrigin(ref, outcomePolicyDenied, "ref.path-outside-root", "policy",
			"local reference resolves outside the repository root")
	}
	return canonical, nil
}

func (s *closureScanner) issueFromOrigin(
	origin *referenceOccurrence,
	outcome string,
	code string,
	kind string,
	message string,
) *classifiedIssue {
	diag := diagnostic{
		Line:     1,
		Column:   1,
		Code:     code,
		Severity: "error",
		Kind:     kind,
		Message:  message,
	}
	if origin != nil {
		diag.Source = origin.Source
		diag.Line = positiveOr(origin.Line, 1)
		diag.Column = positiveOr(origin.Column, 1)
		diag.Pointer = origin.Pointer
	}
	return &classifiedIssue{Outcome: outcome, Diagnostic: diag}
}

func parseDocument(path string, source string, data []byte) (*yaml.Node, *diagnostic) {
	if !utf8.Valid(data) {
		line, column := invalidUTF8Location(data)
		return nil, &diagnostic{
			Source:   source,
			Line:     line,
			Column:   column,
			Code:     "parse.invalid-utf8",
			Severity: "error",
			Kind:     "parse",
			Message:  "document is not valid UTF-8",
		}
	}

	if strings.EqualFold(filepath.Ext(path), ".json") {
		var value any
		if err := json.Unmarshal(data, &value); err != nil {
			line, column := jsonErrorLocation(data, err)
			return nil, &diagnostic{
				Source:   source,
				Line:     line,
				Column:   column,
				Code:     "parse.invalid-json",
				Severity: "error",
				Kind:     "parse",
				Message:  normalizeWhitespace(err.Error()),
			}
		}
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var node yaml.Node
	if err := decoder.Decode(&node); err != nil {
		code := "parse.invalid-yaml"
		if strings.Contains(strings.ToLower(err.Error()), "already defined") {
			code = "parse.duplicate-key"
		}
		line := 1
		if match := yamlLinePattern.FindStringSubmatch(err.Error()); len(match) == 2 {
			if parsed, parseErr := strconv.Atoi(match[1]); parseErr == nil {
				line = positiveOr(parsed, 1)
			}
		}
		column := firstContentColumn(data, line)
		return nil, &diagnostic{
			Source:   source,
			Line:     line,
			Column:   column,
			Code:     code,
			Severity: "error",
			Kind:     "parse",
			Message:  normalizeWhitespace(err.Error()),
		}
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err == nil {
		return nil, &diagnostic{
			Source:   source,
			Line:     positiveOr(trailing.Line, 1),
			Column:   positiveOr(trailing.Column, 1),
			Code:     "parse.multiple-documents",
			Severity: "error",
			Kind:     "parse",
			Message:  "YAML streams must contain exactly one document",
		}
	} else if !errors.Is(err, io.EOF) {
		line := 1
		if match := yamlLinePattern.FindStringSubmatch(err.Error()); len(match) == 2 {
			if parsed, parseErr := strconv.Atoi(match[1]); parseErr == nil {
				line = positiveOr(parsed, 1)
			}
		}
		return nil, &diagnostic{
			Source:   source,
			Line:     line,
			Column:   firstContentColumn(data, line),
			Code:     "parse.invalid-yaml",
			Severity: "error",
			Kind:     "parse",
			Message:  normalizeWhitespace(err.Error()),
		}
	}
	if cycle := findCyclicAlias(&node, ""); cycle != nil {
		return nil, &diagnostic{
			Source:   source,
			Line:     positiveOr(cycle.Line, 1),
			Column:   positiveOr(cycle.Column, 1),
			Pointer:  cycle.Pointer,
			Code:     "parse.cyclic-alias",
			Severity: "error",
			Kind:     "parse",
			Message:  "YAML aliases must not form an object cycle",
		}
	}
	if duplicate := findDuplicateKey(&node, ""); duplicate != nil {
		return nil, &diagnostic{
			Source:   source,
			Line:     positiveOr(duplicate.Line, 1),
			Column:   positiveOr(duplicate.Column, 1),
			Pointer:  duplicate.Pointer,
			Code:     "parse.duplicate-key",
			Severity: "error",
			Kind:     "parse",
			Message:  fmt.Sprintf("duplicate mapping key %q", duplicate.Key),
		}
	}
	return &node, nil
}

type cyclicAlias struct {
	Line    int
	Column  int
	Pointer string
}

func findCyclicAlias(root *yaml.Node, pointer string) *cyclicAlias {
	const (
		visiting = 1
		verified = 2
	)
	states := make(map[*yaml.Node]uint8)
	var walk func(*yaml.Node, string) *cyclicAlias
	walk = func(node *yaml.Node, currentPointer string) *cyclicAlias {
		if node == nil {
			return nil
		}
		if states[node] == verified {
			return nil
		}
		if node.Kind == yaml.AliasNode {
			if node.Alias != nil && states[node.Alias] == visiting {
				return &cyclicAlias{
					Line:    node.Line,
					Column:  node.Column,
					Pointer: currentPointer,
				}
			}
			if states[node] == visiting {
				return &cyclicAlias{
					Line:    node.Line,
					Column:  node.Column,
					Pointer: currentPointer,
				}
			}
			states[node] = visiting
			cycle := walk(node.Alias, currentPointer)
			states[node] = verified
			return cycle
		}
		if states[node] == visiting {
			return nil
		}
		states[node] = visiting
		defer func() {
			states[node] = verified
		}()

		switch node.Kind {
		case yaml.DocumentNode:
			for _, child := range node.Content {
				if cycle := walk(child, currentPointer); cycle != nil {
					return cycle
				}
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(node.Content); i += 2 {
				keyNode := node.Content[i]
				valueNode := node.Content[i+1]
				childPointer := currentPointer + "/" + escapePointerSegment(keyNode.Value)
				if cycle := walk(keyNode, childPointer); cycle != nil {
					return cycle
				}
				if cycle := walk(valueNode, childPointer); cycle != nil {
					return cycle
				}
			}
		case yaml.SequenceNode:
			for i, child := range node.Content {
				childPointer := currentPointer + "/" + strconv.Itoa(i)
				if cycle := walk(child, childPointer); cycle != nil {
					return cycle
				}
			}
		}
		return nil
	}
	return walk(root, pointer)
}

func invalidUTF8Location(data []byte) (int, int) {
	line, column := 1, 1
	for len(data) > 0 {
		value, size := utf8.DecodeRune(data)
		if value == utf8.RuneError && size == 1 {
			return line, column
		}
		if value == '\n' {
			line++
			column = 1
		} else {
			column++
		}
		data = data[size:]
	}
	return line, column
}

type duplicateKey struct {
	Key     string
	Line    int
	Column  int
	Pointer string
}

func findDuplicateKey(root *yaml.Node, pointer string) *duplicateKey {
	var walk func(*yaml.Node, string, map[*yaml.Node]bool) *duplicateKey
	walk = func(node *yaml.Node, currentPointer string, ancestors map[*yaml.Node]bool) *duplicateKey {
		if node == nil || ancestors[node] {
			return nil
		}
		ancestors[node] = true
		defer delete(ancestors, node)

		switch node.Kind {
		case yaml.DocumentNode:
			for _, child := range node.Content {
				if duplicate := walk(child, currentPointer, ancestors); duplicate != nil {
					return duplicate
				}
			}
		case yaml.MappingNode:
			seen := make(map[string]struct{}, len(node.Content)/2)
			for i := 0; i+1 < len(node.Content); i += 2 {
				keyNode := node.Content[i]
				valueNode := node.Content[i+1]
				childPointer := currentPointer + "/" + escapePointerSegment(keyNode.Value)
				keyIdentity := keyNode.Tag + "\x00" + keyNode.Value
				if _, exists := seen[keyIdentity]; exists {
					return &duplicateKey{
						Key:     keyNode.Value,
						Line:    keyNode.Line,
						Column:  keyNode.Column,
						Pointer: childPointer,
					}
				}
				seen[keyIdentity] = struct{}{}
				if duplicate := walk(valueNode, childPointer, ancestors); duplicate != nil {
					return duplicate
				}
			}
		case yaml.SequenceNode:
			for i, child := range node.Content {
				if duplicate := walk(child, currentPointer+"/"+strconv.Itoa(i), ancestors); duplicate != nil {
					return duplicate
				}
			}
		case yaml.AliasNode:
			return walk(node.Alias, currentPointer, ancestors)
		}
		return nil
	}
	return walk(root, pointer, make(map[*yaml.Node]bool))
}

func firstContentColumn(data []byte, targetLine int) int {
	if targetLine < 1 {
		return 1
	}
	line := 1
	start := 0
	for i, value := range data {
		if line == targetLine {
			start = i
			break
		}
		if value == '\n' {
			line++
			start = i + 1
		}
	}
	if line != targetLine {
		return 1
	}

	column := 1
	for i := start; i < len(data) && data[i] != '\n' && data[i] != '\r'; i++ {
		switch data[i] {
		case ' ':
			column++
		case '\t':
			column += 8 - ((column - 1) % 8)
		default:
			return column
		}
	}
	return 1
}

func collectReferences(root *yaml.Node, source string) []referenceOccurrence {
	var refs []referenceOccurrence
	var walk func(*yaml.Node, string, map[*yaml.Node]bool)
	walk = func(node *yaml.Node, pointer string, ancestors map[*yaml.Node]bool) {
		if node == nil || ancestors[node] {
			return
		}
		ancestors[node] = true
		defer delete(ancestors, node)

		switch node.Kind {
		case yaml.DocumentNode:
			for _, child := range node.Content {
				walk(child, pointer, ancestors)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(node.Content); i += 2 {
				keyNode := node.Content[i]
				valueNode := node.Content[i+1]
				childPointer := pointer + "/" + escapePointerSegment(keyNode.Value)
				if keyNode.Value == "$ref" && valueNode.Kind == yaml.ScalarNode {
					refs = append(refs, referenceOccurrence{
						Value:   valueNode.Value,
						Source:  source,
						Line:    keyNode.Line,
						Column:  keyNode.Column,
						Pointer: childPointer,
					})
				}
				walk(valueNode, childPointer, ancestors)
			}
		case yaml.SequenceNode:
			for i, child := range node.Content {
				walk(child, pointer+"/"+strconv.Itoa(i), ancestors)
			}
		case yaml.AliasNode:
			walk(node.Alias, pointer, ancestors)
		}
	}
	walk(root, "", make(map[*yaml.Node]bool))
	return refs
}

func indexLocations(node *yaml.Node, pointer string, locations map[string]position, ancestors map[*yaml.Node]bool) {
	if node == nil || ancestors[node] {
		return
	}
	ancestors[node] = true
	defer delete(ancestors, node)

	if _, exists := locations[pointer]; !exists {
		locations[pointer] = position{Line: positiveOr(node.Line, 1), Column: positiveOr(node.Column, 1)}
	}
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			indexLocations(child, pointer, locations, ancestors)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]
			childPointer := pointer + "/" + escapePointerSegment(keyNode.Value)
			locations[childPointer] = position{
				Line:   positiveOr(valueNode.Line, positiveOr(keyNode.Line, 1)),
				Column: positiveOr(valueNode.Column, positiveOr(keyNode.Column, 1)),
			}
			indexLocations(valueNode, childPointer, locations, ancestors)
		}
	case yaml.SequenceNode:
		for i, child := range node.Content {
			childPointer := pointer + "/" + strconv.Itoa(i)
			locations[childPointer] = position{
				Line:   positiveOr(child.Line, 1),
				Column: positiveOr(child.Column, 1),
			}
			indexLocations(child, childPointer, locations, ancestors)
		}
	case yaml.AliasNode:
		indexLocations(node.Alias, pointer, locations, ancestors)
	}
}

func jsonErrorLocation(data []byte, err error) (int, int) {
	var offset int64
	var syntaxError *json.SyntaxError
	var typeError *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntaxError):
		offset = syntaxError.Offset
	case errors.As(err, &typeError):
		offset = typeError.Offset
	default:
		return 1, 1
	}
	if offset < 1 {
		return 1, 1
	}
	line, column := 1, 1
	limit := int(offset - 1)
	if limit > len(data) {
		limit = len(data)
	}
	for _, b := range data[:limit] {
		if b == '\n' {
			line++
			column = 1
		} else {
			column++
		}
	}
	return line, column
}

func supportedDocumentExtension(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json", ".yaml", ".yml":
		return true
	default:
		return false
	}
}

func canonicalKey(path string) string {
	clean := filepath.Clean(path)
	if filepath.Separator == '\\' {
		return strings.ToLower(clean)
	}
	return clean
}

func canonicalExistingPath(input string) (string, error) {
	absolute, err := filepath.Abs(input)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	if runtime.GOOS != "windows" {
		resolved, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			return "", err
		}
		return filepath.Abs(resolved)
	}
	return resolveWindowsReparsePoints(absolute, 0)
}

func resolveWindowsReparsePoints(absolute string, followed int) (string, error) {
	const maxLinks = 255
	if followed > maxLinks {
		return "", errors.New("too many filesystem links")
	}

	volume := filepath.VolumeName(absolute)
	if volume == "" {
		return "", errors.New("absolute Windows path has no volume")
	}
	root := volume + string(filepath.Separator)
	remaining := strings.TrimPrefix(absolute, root)
	parts := strings.FieldsFunc(remaining, func(r rune) bool {
		return r == '\\' || r == '/'
	})
	current := root

	for index, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}

		linkTarget, readlinkErr := os.Readlink(current)
		if readlinkErr != nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return "", readlinkErr
			}
			continue
		}
		if !filepath.IsAbs(linkTarget) {
			linkTarget = filepath.Join(filepath.Dir(current), linkTarget)
		}
		if index+1 < len(parts) {
			linkTarget = filepath.Join(
				linkTarget,
				filepath.Join(parts[index+1:]...),
			)
		}
		next, err := filepath.Abs(linkTarget)
		if err != nil {
			return "", err
		}
		return resolveWindowsReparsePoints(filepath.Clean(next), followed+1)
	}
	return filepath.Clean(current), nil
}

func isWithin(root string, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func relativeSource(root string, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(filepath.Base(path))
	}
	return filepath.ToSlash(relative)
}

func escapePointerSegment(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func positiveOr(value int, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func normalizeWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
