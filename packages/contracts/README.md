# PROOF contracts

This workspace member contains language-neutral, versioned contracts shared by
the local CLI, hosted workers, persistence, and report consumers. It does not
contain a second result model or presentation-specific fields.

## Result schema v1

The canonical source files are packaged below
`src/proof_contracts/schemas/result/v1`:

- `finding.schema.json` defines evidence-based normalized findings.
- `gate.schema.json` defines pass, advisory, blocked, and not-evaluated policy
  outcomes.
- `provenance.schema.json` identifies the exact core, validator, rule pack,
  runtime, configuration, and input artifacts.
- `run.schema.json` combines terminal execution state, findings, errors,
  summary counts, gate outcome, and provenance.
- `common.schema.json` contains shared strict definitions.

Repository examples are under `examples/result/v1`. Files in `valid` must pass
their matching schema. Files in `invalid` are regression cases that must be
rejected.

The compatibility, canonical ordering, fingerprint, and deterministic digest
rules are documented in
[`docs/contracts/result-schema-v1.md`](../../docs/contracts/result-schema-v1.md).

## Validation

From the repository root:

```text
uv sync --locked
uv run --locked pytest
uv run --locked ruff check .
```

Schema references are resolved from the checked-out package registry during
tests. Validation must not retrieve a schema or any other content over the
network.
