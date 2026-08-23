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
  SOURCES.md              Upstream provenance for public-source fixtures
  fixtures/
    synthetic/            Hand-authored OAS documents (JSON and YAML)
    public/               Extracted subsets of public APIs (JSON and YAML)
```

## Current status

113 labeled operations across 5 P0 rules. The quantitative and format/source
coverage expansion tracked by Issue #11 is satisfied by this corpus state.
Issue #11 remains open pending its remaining acceptance criteria.

| Rule | Total | Positive | Negative |
|------|-------|----------|----------|
| AGT-CTX-001 | 24 | 11 | 13 |
| AGT-PARAM-001 | 24 | 11 | 13 |
| AGT-RESP-001 | 23 | 13 | 10 |
| AGT-POL-001 | 23 | 16 | 7 |
| AGT-POL-002 | 19 | 11 | 8 |

Coverage spans OAS 3.0.x (61 cases) and 3.1.x (52 cases), JSON (79) and YAML
(34) formats, and synthetic (98) and public (15) sources. See
`coverage-summary.json` for full breakdown.

## Adding cases

1. Create or extend a fixture file under `fixtures/synthetic/` or `fixtures/public/`.
   Both JSON and YAML formats are supported; YAML files are loaded with `pyyaml`.
2. Add one manifest entry per operation with all required fields.
3. Update `coverage-summary.json` totals.
4. Run `uv run --locked pytest tests/corpus/` to verify all checks pass.

The coverage test derives rule, dialect, format, source-type, and risk counts
from the manifest and requires the summary to match exactly. Public-source
cases must provide a source URL, license, and immutable source reference;
synthetic cases must keep `provenance` set to `null`.

Cases must keep `reviewStatus: "pending"`. Two-reviewer approval policy
is not enforced until a formal review stage is initiated.

### Local `$ref` rules for corpus fixtures

Corpus fixture files may reference other fixture files via relative `$ref` values.
These refs must comply with the following stricter-than-production rules:

- No `..` path traversal in any segment.
- No Windows device names (NUL, CON, PRN, AUX, COM0–COM9, LPT0–LPT9) as
  any segment stem.
- Target file extension must be `.json`, `.yaml`, or `.yml`.
- The resolved target must remain inside `corpus/fixtures/`.
- Fragments (e.g., `schemas.yaml#/MySchema`) must resolve within the target file.

Shared schema definitions for the `ref-cases.yaml` fixture live in
`fixtures/synthetic/schemas.yaml`. That file is not an OAS document; it contains
raw schema objects referenced by name (e.g., `$ref: "schemas.yaml#/Item"`).

## Test suite behavior

The corpus test runs every fixture through the closure-only OpenAPI validator,
normalizer, risk classifier, and agent-contract rule evaluator. It requires a
one-to-one mapping between fixture operations and manifest cases, then compares
the engine's risks and projected findings with each labeled expectation. Results
are cached once per fixture for the pytest session so the check remains bounded
as the corpus grows.

YAML fixtures are supported: the locked workspace provides the approved YAML
parser (pyyaml), and the corpus test loader parses every fixture through
`read_repository_document` with limits mirroring the engine's closure limits.
The `test_no_unsafe_refs` test validates all `$ref` values using a permissive
secondary loader so the safety assertions remain independent of the engine's own
reference guards.
