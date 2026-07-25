# Redocly OpenAPI Core adapter prototype

This disposable adapter evaluates `@redocly/openapi-core@2.40.0` without invoking
the Redocly CLI. It uses the public package entrypoint and the `spec` ruleset.

```powershell
node ./adapters/redocly-core/index.mjs `
  --entrypoint ./corpus/cases/oas30-valid.yaml `
  --repository-root ../.. `
  --max-entrypoint-bytes 1048576 `
  --max-files 100 `
  --max-total-bytes 20971520 `
  --max-depth 32 `
  --max-diagnostics 100
```

The process writes one JSON object to stdout with `adapter: "redocly-core"` and
an outcome of `valid`, `invalid`, `parse-error`, `policy-denied`, or
`limit-exceeded`. Controlled validation failures, policy denials, and
configured limit breaches use exit code `0`. Adapter contract or internal
failures use exit code `2`.

Security boundaries:

- only repository-confined relative references are allowed;
- HTTP(S), `file:`, other URI schemes, absolute paths, UNC paths,
  protocol-relative paths, query-bearing paths, path escapes (including
  percent-encoded traversal), and symlink escapes are denied;
- invalid UTF-8, strict-JSON failures, duplicate keys, multi-document YAML, and
  cyclic YAML aliases are controlled parse failures;
- every input is checked as a regular file before and after opening, regular
  files are read through the checked handle, and POSIX nonblocking open flags
  prevent special-file opens from waiting for a writer;
- entrypoint bytes, referenced-file count, aggregate bytes, reference depth,
  local file attempts, and emitted diagnostics are bounded.

This is not a production sandbox. Filesystem checks cannot eliminate every
time-of-check/time-of-use race, Redocly builds all diagnostics before the
adapter truncates output, and depth tracking is constrained by Redocly's
resolver callback model. A production worker still needs OS-level isolation,
wall-clock and memory limits, and adversarial testing.

The adapter is intentionally pinned to `@redocly/openapi-core@2.40.0`. Its
imports are present in the package's public export and TypeScript declaration
surface, but resolver subclass hooks and normalized diagnostic details are not
documented as a long-term compatibility contract in the Redocly CLI user
documentation. Any dependency update must rerun these contract tests and
review the resolver implementation.

Known evaluation gap: Redocly's `spec`/`struct` validation reports only the
first invalid sibling `responses` value in the shared diagnostic-flood fixture.
The adapter therefore observes one finding rather than the acceptance corpus
minimum of twelve. Output truncation itself is implemented and tested, but this
candidate does not pass that diagnostic-volume acceptance case without an
independent exhaustive schema-validation pass.

Run the focused tests from `spikes/openapi-validator`:

```powershell
node ./adapters/redocly-core/test.mjs
```
