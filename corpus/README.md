# PROOF Benchmark Corpus

This directory contains the labeled OpenAPI operation corpus used to evaluate
the correctness of PROOF engine implementations against the five P0
agent-contract rules.

## Purpose

The conformance fixtures in `rulepacks/agent-contract/v1/fixtures/` verify that
rule specifications are unambiguous. This corpus serves a different purpose: it
provides a deterministic evaluation baseline that the PROOF engine is run against
to measure accuracy.

## Structure

```
corpus/
  manifest.json           Labeled cases; validates against manifest.schema.json
  manifest.schema.json    JSON Schema (Draft 2020-12) for the manifest
  coverage-summary.json   Aggregate coverage counts
  fixtures/
    synthetic/            Hand-authored OAS documents with known outcomes
```

## Pilot status

This directory contains 81 labeled synthetic operations (61 JSON, 20 YAML).
Issue #11 remains open until at least 100 operations are labeled and the full
acceptance criteria are met.

## Adding cases

1. Create or extend a fixture file under `fixtures/synthetic/` in JSON or YAML.
   YAML fixtures are parsed with the same strict loader the engine uses: merge
   keys and duplicate keys are rejected, and aliases are allowed only up to the
   engine's count limit.
2. Add one manifest entry per operation with all required fields.
3. Update `coverage-summary.json` totals.
4. Run `uv run --locked pytest tests/corpus/` to verify all checks pass.

The coverage test derives rule, dialect, format, source-type, and risk counts
from the manifest and requires the summary to match exactly. Public-source
cases must provide a source URL, license, and immutable source reference;
synthetic cases must keep `provenance` set to `null`.

Pilot cases must keep `reviewStatus: "pending"`. Two-reviewer approval policy
is not enforced until the full corpus stage.

## Pilot test suite behavior

The corpus test runs every fixture through the closure-only OpenAPI validator,
normalizer, risk classifier, and agent-contract rule evaluator. It requires a
one-to-one mapping between fixture operations and manifest cases, then compares
the engine's risks and projected findings with each labeled expectation. Results
are cached once per fixture for the pytest session so the check remains bounded
as the corpus grows.

YAML fixtures are supported: the locked workspace provides the approved YAML
parser (pyyaml), and the corpus test loader parses every fixture through
`read_repository_document` with limits mirroring the engine's closure limits.
Each YAML case mirrors a labeled JSON scenario: same-dialect pairs assert
format-invariant engine behavior directly, and cross-dialect pairs assert the
same expectations across both format and dialect.
