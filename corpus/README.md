# PROOF Benchmark Corpus

This directory contains the labeled OpenAPI operation corpus used to evaluate
the correctness of PROOF engine implementations against the five P0
agent-contract rules.

## Purpose

The conformance fixtures in `rulepacks/agent-contract/v1/fixtures/` verify that
rule specifications are unambiguous. This corpus serves a different purpose: it
provides a deterministic evaluation baseline that a future engine implementation
can be run against to measure accuracy.

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

This directory contains the 10-operation synthetic pilot. Issue #11 remains open
until at least 100 operations are labeled and the full acceptance criteria are met.

## Adding cases

1. Create or extend a fixture file under `fixtures/synthetic/` (JSON only until
   an approved YAML parser dependency is added).
2. Add one manifest entry per operation with all required fields.
3. Update `coverage-summary.json` totals.
4. Run `uv run --locked pytest tests/corpus/` to verify all checks pass.

Pilot cases must keep `reviewStatus: "pending"`. Two-reviewer approval policy
is not enforced until the full corpus stage.

## Known limitations of the pilot test suite

**`classify_operation` validation is deferred.**

`tests/corpus/test_corpus_manifest.py` validates that `expectedRisks` and
`expectedNonRisks` are exhaustive and internally consistent, and that each
finding's `riskCategories` is a subset of `expectedRisks`. It does not execute
the deterministic risk classifier against fixtures and compare the output to
`expectedRisks`.

Automated classifier execution requires either a canonical shared helper
extracted from `tests/rulepack/test_p0_rule_specifications.py` or the actual
PROOF engine. Extracting the shared helper requires adding `pythonpath` to
`pyproject.toml` and touching `test_p0_rule_specifications.py`; both changes
are deferred to a follow-up issue.

Until that follow-up is resolved, `expectedRisks` values in this corpus are
validated by manual review only. The conformance tests in
`tests/rulepack/test_p0_rule_specifications.py` remain the authoritative
regression guard for the classifier algorithm.

**YAML fixtures are not supported in the pilot.**

No approved YAML parser is present in the current lockfile. The manifest schema
permits `format: "yaml"` for forward compatibility, but the pilot test loader
will fail with a clear error message if a YAML case is introduced before a YAML
dependency is approved and added.
