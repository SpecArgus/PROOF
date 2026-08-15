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
  MAINTENANCE.md          Review, labeling, licensing, and maintenance conventions
  fixtures/
    synthetic/            Hand-authored OAS documents with known outcomes
```

## Pilot status

This directory contains the 61-operation synthetic pilot. Issue #11 remains open
until at least 100 operations are labeled and the full acceptance criteria are met.

## Adding cases

1. Create or extend a fixture file under `fixtures/synthetic/` (JSON only until
   an approved YAML parser dependency is added).
2. Add one manifest entry per operation with all required fields.
3. Update `coverage-summary.json` totals.
4. Run `uv run --locked pytest tests/corpus/` to verify all checks pass.

The coverage test derives rule, dialect, format, source-type, and risk counts
from the manifest and requires the summary to match exactly. Public-source
cases must provide a source URL, license, and immutable source reference;
synthetic cases must keep `provenance` set to `null`.

Pilot cases must keep `reviewStatus: "pending"`. Two-reviewer approval policy
is not enforced until the full corpus stage. The recording format and the
label-change, false-positive-regression, and licensing conventions are
defined in [MAINTENANCE.md](MAINTENANCE.md).

## Known limitations of the pilot test suite

The corpus test runs every fixture through the closure-only OpenAPI validator,
normalizer, risk classifier, and agent-contract rule evaluator. It requires a
one-to-one mapping between fixture operations and manifest cases, then compares
the engine's risks and projected findings with each labeled expectation. Results
are cached once per fixture for the pytest session so the check remains bounded
as the corpus grows.

**YAML fixtures are not supported in the pilot.**

No approved YAML parser is present in the current lockfile. The manifest schema
permits `format: "yaml"` for forward compatibility, but the pilot test loader
will fail with a clear error message if a YAML case is introduced before a YAML
dependency is approved and added.
