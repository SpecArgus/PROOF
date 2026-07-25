# libopenapi adapter prototype

This disposable prototype evaluates direct integration with:

- `github.com/pb33f/libopenapi` `v0.38.7`
- `github.com/pb33f/libopenapi-validator` `v0.14.0`
- Go toolchain `go1.25.12`

It is not a production sandbox. The parent process remains responsible for
wall-clock, memory, CPU, and stdout limits.

## Contract

```text
go run . \
  --entrypoint <spec.yaml> \
  --repository-root <allowed-root> \
  [--max-entrypoint-bytes 0] \
  [--max-files 256] \
  [--max-total-bytes 67108864] \
  [--max-depth 32] \
  [--max-diagnostics 100]
```

Stdout contains one JSON object with `schemaVersion`, `adapter`, `outcome`,
`diagnostics`, and `stats`. Expected document and policy outcomes exit zero:

- `valid`
- `invalid`
- `parse-error`
- `policy-denied`
- `limit-exceeded`

Argument-contract failures, internal panics, and unexpected adapter failures
exit `2`.

Each diagnostic contains `source`, `line`, `column`, `pointer`, `code`,
`severity`, `kind`, and `message`. Paths are repository-relative and
diagnostics are sorted and deduplicated before emission.

## Security prototype

Before invoking libopenapi, the adapter:

1. resolves the entrypoint and every external file reference;
2. denies HTTP(S), other URI schemes, absolute paths, path escapes, and symlink
   escapes;
3. enforces file-count, aggregate-byte, and external-reference-depth limits;
4. parses the complete local reference closure; and
5. copies only the approved closure into an in-memory `fstest.MapFS`.

`AllowRemoteReferences` remains false. libopenapi receives only the in-memory
allowlist, so validation cannot discover a new operating-system file or make a
remote request through its configured rolodex.

There is deliberately no claim that this replaces worker isolation. Resource
limits other than the closure limits above must be enforced by the caller.

## Reproduce

From this directory:

```text
go mod download
go test ./...
go build ./...
go run . --entrypoint ../../corpus/cases/oas30-valid.yaml --repository-root ../..
```

The upstream APIs used are:

- `libopenapi.NewDocumentWithConfiguration`
- `bundler.BundleBytesComposedWithOrigins`
- `datamodel.DocumentConfiguration` with file references enabled, remote
  references disabled, a root `BasePath`, an absolute `SpecFilePath`, and an
  in-memory `LocalFS`
- `validator.NewValidator`
- `Validator.ValidateDocument`

## API caveats

- `libopenapi-validator v0.14.0` declares `libopenapi v0.38.6`; this module's
  direct `v0.38.7` requirement wins Go minimal-version selection.
- Validator schema-failure coordinates may be relative to a rendered schema.
  The adapter therefore maps the validator's `InstancePath` back to the
  pre-parsed source documents when possible.
- `Validator.ValidateDocument` validates only the root document's original JSON
  view and does not inspect schemas held in external files. This prototype uses
  the official `BundleBytesComposedWithOrigins` path before its second
  validation pass. That bundler builds a typed high-level model and can
  normalize away some malformed external scalar values; for example, an
  external Schema Object containing numeric `type: 7` is rendered without that
  invalid value and passes the bundled validation. The common acceptance corpus
  records this as a hard correctness gap rather than adding an ad hoc keyword
  checker. Focused inspection also found no error from `BuildV3Model` or
  `SchemaProxy.BuildSchema`; the proxy exposes an empty type and both composed
  and inline `BundleBytes` paths render the schema as `{}`.
- Reference-closure parsing is intentionally stricter than generic URI
  resolution: only repository-contained JSON and YAML files are admitted.
- The closure scan and in-memory handoff avoid a filesystem time-of-check /
  time-of-use gap during libopenapi validation, but process-level resource
  isolation is still out of scope.
