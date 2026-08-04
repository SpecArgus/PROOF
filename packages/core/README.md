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

The input closure does not perform OpenAPI semantic validation or execute any
repository content. The supervised validator worker consumes this closed byte
set in a later package.

## Validation

From the repository root:

```text
uv sync --all-packages --locked
uv run --locked pytest tests/core
uv run --locked ruff check .
```
