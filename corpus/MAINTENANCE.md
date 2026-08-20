# Corpus maintenance and review conventions

These conventions govern every change to `corpus/`: the manifest, the
fixtures, and the coverage summary. They implement the review, labeling,
licensing, and maintenance documentation required by issue #11.

## Case lifecycle

- A new case enters the manifest with `reviewStatus: "pending"` and an empty
  `reviewers` list on each expected finding.
- A case becomes `approved` when at least two reviewers have recorded
  agreement with its expectations. The case author counts as the first
  reviewer; at least one other maintainer must agree independently.
- Agreement covers the whole labeled expectation: `caseLabels`,
  `expectedRisks` and `expectedNonRisks`, every field of each
  `expectedFindings` entry, `expectedNonFindings`, and the `rationale`.
- During the pilot stage every case keeps `reviewStatus: "pending"`, as stated
  in the README. The recording format below applies from the first review
  sweep onward; the sweep that flips cases to `approved` marks the end of the
  pilot policy.

## Recording review

- Each `reviewers` entry records one reviewer's agreement with one expected
  finding:

  ```json
  {"id": "<github-login>", "approvedAt": "<UTC ISO 8601 date-time>"}
  ```

  `name` is optional and free-form. `id` is the reviewer's GitHub login and is
  required by convention even though the schema leaves it optional.
- A case with no expected findings has nowhere to attach `reviewers`; for such
  cases the approving pull-request review on the change that sets
  `reviewStatus: "approved"` is the agreement record.
- `reviewStatus` flips to `approved` in the pull request that records the
  second reviewer — either the PR introducing the case or a dedicated review
  sweep. The PR description must state which cases it approves.
- Reviewers must not approve expectations they cannot verify: run
  `uv run --locked pytest tests/corpus/` and read the fixture operation before
  recording agreement.

## Changing labels

- Any change to an approved case's `caseLabels`, `expectedRisks`,
  `expectedNonRisks`, `expectedFindings`, or `expectedNonFindings` resets
  `reviewStatus` to `"pending"` and clears the affected `reviewers` records.
  Re-review follows the lifecycle above.
- Update `rationale` to describe the new expectation. Git history records what
  changed; the rationale records only why the current labels are correct.
- A label change that disagrees with the engine has exactly two resolutions:
  fix the label, or open an issue against the engine and fix the engine in a
  separate PR. Corpus tests are never skipped or weakened to make a
  disagreement pass.
- Case IDs are stable. Never reuse, renumber, or delete a case ID; correct a
  wrong case in place under its existing ID.

## False-positive regressions

- When a false positive is reported against the engine, add a case labeled
  `["negative", "false-positive"]` that reproduces the triggering input, with
  a `rationale` referencing the report (issue or PR number).
- False-positive regression cases pin the fix permanently and are never
  removed. If the rule's specification later changes so the finding becomes
  correct, relabel the case through the label-change process instead of
  deleting it.

## Public-source cases

- Use only specifications whose license permits redistribution in this
  repository (for example Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, or
  CC0-1.0). Record the exact SPDX identifier in `provenance.license`.
- `provenance.sourceUrl` is the canonical upstream location.
  `provenance.sourceRef` is an immutable reference — a commit SHA, an
  immutable tag, or a content digest — never a branch name.
- Vendor the trimmed document into `fixtures/public/` so the corpus stays
  self-contained and requires no network access.
- `provenance.modifications` lists every change from upstream (trimming,
  renaming, de-identification) so the fixture can be re-derived from the
  source reference.
- Synthetic cases keep `provenance: null`; the manifest schema enforces this.

## Maintenance

- `coverage-summary.json` is derived from the manifest. Regenerate it in the
  same change that adds, removes, or relabels cases, and set `generated` to
  the change date. The corpus test recomputes every count and fails on any
  mismatch, so a stale summary cannot merge.
- Fixture files are immutable inputs to labeled expectations. Every operation
  in every fixture must have exactly one manifest case; the bijection test
  enforces this, so adding an operation to an existing fixture requires a
  matching manifest entry in the same change.
- Fixture format support (JSON and YAML dialect coverage, parser
  restrictions) is documented in the README and enforced by the corpus test
  loader.
