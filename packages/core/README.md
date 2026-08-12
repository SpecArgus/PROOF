# PROOF core

This workspace member contains the deterministic analysis core shared by the
future CLI and hosted scan worker.

## Repository-confined input closure

`proof_core.build_input_closure` reads one or more repository-relative JSON or
YAML OpenAPI entrypoints and follows their local `$ref` values without network
access. It returns:

- immutable bytes for every consumed file;
- a sorted manifest of repository-relative POSIX paths, sizes, and SHA-256
  digests; and
- a deterministic digest of the complete manifest.

The loader rejects remote, absolute, escaping, symlink, junction, device, and
unsupported references. It applies exact entrypoint-size, aggregate-size,
file-count, and reference-depth limits and rejects a file if its identity or
content metadata changes while it is being read.

The input closure does not execute repository content. The supervised validator
worker consumes this closed byte set without reopening repository files.

`proof_core.validate_openapi(closure)` sends that snapshot through a bounded
subprocess protocol to the pinned OpenAPI validator. Timeouts, output overflow,
malformed responses, missing dependencies, and worker crashes raise
`WorkerFailure` and cannot be reported as a valid document.

After generic validation, `proof_core.normalize_operations(closure)` produces
one immutable OpenAPI 3.0/3.1 operation contract with effective parameters,
responses, security, Agent policy metadata, and deterministic risk evidence.
The v1 classifier uses only method, exact path and operationId tokens, and
explicit policy risks; descriptions never influence classification.

`proof_core.load_scan_configuration` strictly parses one repository-relative
JSON or YAML configuration without following `$ref`. It resolves deterministic
defaults and explicit local overrides into an immutable effective policy whose
RFC 8785 SHA-256 digest is shared by local and future hosted workers.
`proof_core.match_specifications` expands its bounded POSIX selectors with
case-sensitive, cross-platform semantics and never traverses repository links
or version-control metadata.

`proof_core.assemble_input_closure_run` derives validation, normalization, and
rule evaluation directly from one immutable input closure, then combines their
diagnostics and findings into the immutable normalized result-v1 contract. It
independently recomputes finding fingerprints, checks
configuration/input/rule-pack provenance joins, derives summary and gate state,
and computes the RFC 8785 result digest. Incomplete validator output and
configuration, input, or worker failures are emitted only as not-evaluated
terminal runs; they cannot become a pass.

## Validation

From the repository root:

```text
uv sync --all-packages --locked
uv run --locked pytest tests/core
uv run --locked ruff check .
```
