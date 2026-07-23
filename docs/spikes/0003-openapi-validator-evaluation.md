# OpenAPI validator evaluation

- Issue: [#3](https://github.com/SpecArgus/PROOF/issues/3)
- Evaluation date: 2026-07-23
- Status: complete
- Decision status: provisional recommendation, not a runtime selection
- Reproduction harness: [`spikes/openapi-validator`](../../spikes/openapi-validator/README.md)

## Recommendation

Do not adopt any evaluated stock CLI as PROOF's production validation
authority.

The preferred direction is a thin adapter over
[`pb33f/libopenapi`](https://github.com/pb33f/libopenapi) and
[`pb33f/libopenapi-validator`](https://github.com/pb33f/libopenapi-validator).
Vacuum remains the baseline reference candidate because its targeted rules
detected errors in both dialects, traversed local references, and denied the
remote canary natively. Before selection, compare two disposable Go probes:
Vacuum's minimal conformance profile and a direct `libopenapi-validator` call.

The fallback direction to investigate is
[`@redocly/openapi-core`](https://github.com/Redocly/redocly-cli/tree/main/packages/core)
if a Node runtime is selected. Its documented lint and external-resolver
interfaces are promising, and its CLI correctly found structural and
external-reference failures, but its JSON formatter omitted line and column.
`getLineColLocation` is exported but is not listed as a supported interface in
the core README. A proof must therefore confirm a supported coordinate API or
isolate that unstable helper behind the adapter before Redocly can be selected.

Do not use Spectral as the authoritative generic validator. It remains viable
as a policy and style-rule engine. Its stock OAS schema rule did not validate
the invalid schema reached through an external local `$ref`; fixing that would
require a second structural-validation pass and source-map reconstruction.

This recommendation narrows the next experiment. It does not select Go, Node,
a process boundary, or a production dependency.

## Evaluation method

The harness pins and executes three black-box candidates:

| Candidate | Version | Profile |
| --- | --- | --- |
| Vacuum | `0.29.10` | `oas3-schema` and `resolving-references`, `--resolve-all-refs`, `--remote=false` |
| Stoplight Spectral | `6.16.2` | `oas3-schema` only |
| Redocly CLI | `2.40.0` | `spec` ruleset |

The common corpus covers OAS 3.0 YAML, OAS 3.1 JSON, malformed YAML,
structural errors, valid and invalid multi-file local references, missing
references, a loopback remote-reference canary, and four exact byte-boundary
cases. Normalized findings use repository-relative slash paths, one-based
coordinates, RFC 6901 pointers where candidates expose them, stable sorting,
and SHA-256 comparison.

Normal cases run five times from relocated workspaces. Remote and large-input
cases run once and are marked `not-assessed` rather than being treated as
deterministic. Native behavior is recorded before the harness applies remote
or input-size preflights.

The JavaScript runner is disposable evaluation tooling, not a production
runtime decision.

## Results

The latest completed run recorded 39 candidate cases. Thirty-two meet the
fixture contract after explicit adapter controls; seven expose candidate
surface gaps. All 24 repeated cases produced one normalized hash. The
single-run remote and size cases are not included in that determinism claim.

| Capability | Vacuum | Spectral | Redocly CLI |
| --- | --- | --- | --- |
| Valid OAS 3.0 / 3.1 | Pass | Pass | Pass |
| Invalid OAS 3.0 | Pass with structured file, line, column, and path | Pass with structured file, line, column, and path | Detects error; JSON output has file and pointer but no line/column |
| Invalid OAS 3.1 | Detects error and coordinates; emitted path is an internal schema path | Pass with document pointer and coordinates | Detects error; JSON output has pointer but no line/column |
| Malformed YAML | Controlled parse failure, no line/column | Structured parser finding with line/column | Controlled parse failure with line/column parsed from CLI output |
| Valid local multi-file `$ref` | Pass | Pass | Pass |
| Invalid external referenced schema | Detects after `--resolve-all-refs`; location points at the referring root | **Missed; returned valid** | Detects target file and pointer; JSON output has no line/column |
| Missing local reference | Pass with coordinates | Pass with coordinates | Detects reference; JSON output has no line/column |
| Native remote-reference behavior | Zero canary requests and controlled error | One canary request; returned valid | One canary request; returned valid |
| Harness remote preflight | Zero requests; pass | Zero requests; pass with adapter | Zero requests; pass with adapter |
| Exact `10,000,000` and `10,485,760` bytes | Both accepted within timeout | Both accepted within timeout | Both accepted within timeout |
| One byte above either boundary, native | Accepted | Accepted | Accepted |
| One byte above either boundary, preflight | Rejected before candidate execution | Rejected before candidate execution | Rejected before candidate execution |

The harness summary deliberately labels all three candidate dispositions
`has-gaps`. “Most cases passed” is not used as a selection score; correctness,
no-egress behavior, and evidence location are gates.

### Location fidelity

Vacuum's Spectral report uses one-based coordinates, while Spectral uses
zero-based ranges. The adapter normalizes these independently. Redocly's CLI
codeframe contains coordinates, but its JSON formatter only preserved source
and pointer for structural findings. A production Redocly adapter would need
a supported core source-location contract rather than parsing codeframes. The
currently exported `getLineColLocation` helper is explicitly treated as
unstable until Redocly documents it.

Vacuum's OAS 3.1 structural finding reported the correct source coordinates
but an internal JSON Schema pointer. Its invalid external schema finding
reported the root reference site rather than the defining file. A direct
libopenapi probe must verify whether low-level YAML nodes can provide the
document pointer and defining-file coordinates without message parsing.

### Native and adapter controls

Vacuum denied the remote canary natively. Spectral and Redocly each made one
HTTP request under their default CLI resolver. The harness then demonstrated
an entrypoint preflight that returned a controlled diagnostic without running
the candidate.

That preflight is not a production security boundary. It only recognizes the
fixture's HTTP(S) `$ref` in the entrypoint and does not prove safety for
transitive references, `$id` rebasing, file URIs, path traversal, symlinks, or
junctions. Production requires both a root-confined resolver with no HTTP(S)
handler and worker-level no-egress.

## Resource protection

| Control | Spike evidence | Production requirement |
| --- | --- | --- |
| Entrypoint bytes | Exact decimal and binary boundaries tested; one byte over rejected | Choose and publish one inclusive raw-byte limit |
| Wall time | Five-second candidate limit; supervisor kill self-test passes | Enforce outside the validator process |
| Captured output | One MiB combined stdout/stderr cap; overflow self-test passes | Keep a bounded tail or structured truncation marker |
| Diagnostic volume | 100-finding cap; 150-finding normalization self-test records truncation | Preserve raw, deduplicated, emitted, and truncated counts |
| Reference depth | No common CLI limit | Enforce in the root-confined resolver |
| Referenced files and aggregate bytes | Not enforced by candidate CLIs | Limit each file, file count, aggregate bytes, and cycles |
| Memory | No portable CLI hard limit | Use worker/container/job-object memory limits |
| Filesystem | Candidates are not sandboxed in this spike | Canonicalize real paths and reject repository-root escapes |
| Network | Canary measures candidate behavior | Omit remote resolvers and enforce no-egress independently |

`10 MB` remains intentionally unresolved. The corpus tests both
`10,000,000` and `10,485,760` bytes so the eventual product decision can be
made explicitly without changing the evidence harness.

## Supply-chain review

All direct candidate licenses are compatible with PROOF's Apache-2.0 license:
Vacuum and Redocly are MIT; Spectral is Apache-2.0.

| Candidate | Installed inventory | License result | Notable risk |
| --- | --- | --- | --- |
| Vacuum | 90,458,624-byte Windows binary; 95 linked Go modules | 55 MIT, 19 Apache-2.0, 18 BSD-3-Clause, 3 BSD-2-Clause; zero unresolved by local heuristic | Large CLI surface; 95 modules include UI, docs, language-server, and plugin code |
| Spectral CLI | 240 CycloneDX components | Zero components without declared licenses | Archived JSON ref-resolver dependency, Scarf analytics package, and three deprecated Rollup-path dependencies |
| Redocly CLI | One bundled npm component plus 108 packages disclosed in `THIRD_PARTY_NOTICES` | Direct MIT license; bundled notices require reconciliation | npm SBOM does not expand the bundled packages, so component-level SBOM coverage is incomplete |

`npm audit` reported zero known vulnerabilities for the locked installation on
the evaluation date. That result is time-bound and must be rerun in CI.

The harness generates:

- npm CycloneDX 1.5 JSON;
- `go version -m -json` for the exact Vacuum binary;
- the Vacuum binary SHA-256;
- per-candidate dependency summaries; and
- a local-cache license heuristic for linked Go modules.

The Go license heuristic and Redocly notices are evidence, not legal
conclusions. A production dependency change requires automated license policy
checks and a complete SPDX or CycloneDX artifact.

The 95-module Vacuum inventory contains
`libopenapi-validator v0.13.13`. The proposed direct follow-up uses
`v0.14.0`, which was not installed or inventoried in this spike. Its exact
module graph, licenses, and SBOM are a follow-up gate rather than evidence
claimed by this report.

## Required adapter boundary

Any selected implementation must fit a runtime-neutral boundary:

```text
validate(entrypoint, repositoryRoot, limits) -> normalized findings
```

The boundary must:

1. read raw bytes and enforce entrypoint and reference-closure limits before
   parsing;
2. allow only repository-contained local references;
3. omit HTTP(S), `file://`, absolute-drive, UNC, and protocol-relative
   resolvers;
4. reject canonical-path, symlink, and junction escapes;
5. return relative source, one-based line and column, RFC 6901 pointer, stable
   code, severity, and message;
6. distinguish validation findings, parse failures, policy denials, timeouts,
   output limits, and internal errors;
7. sort and deduplicate findings deterministically;
8. cap time, memory, output, reference depth, file count, aggregate bytes, and
   diagnostic volume outside the candidate where necessary; and
9. run in a no-egress worker with a locked dependency graph and generated SBOM.

## Next gate

Open a follow-up implementation issue for two small, disposable adapters:

1. `libopenapi v0.38.7` plus `libopenapi-validator v0.14.0`, configured with
   local references allowed, remote references denied, and a root-confined
   filesystem; and
2. Redocly OpenAPI Core `2.40.0` with a custom local-only resolver and
   a supported coordinate API. If the exported but undocumented
   `getLineColLocation` helper is the only option, pin and isolate it while
   treating API stability as an explicit risk.

Run the same corpus plus path-escape, symlink/junction, transitive remote
reference, deep-reference, aggregate-byte, cycle, duplicate-key, malformed
JSON, and diagnostic-flood fixtures. Select a production validator only after
one adapter passes every correctness and security gate.

The byte-limit convention, production runtime, and worker isolation mechanism
remain explicit decisions for that follow-up work.

## Reproduce

From [`spikes/openapi-validator`](../../spikes/openapi-validator/README.md):

```text
npm ci --ignore-scripts
npm run bootstrap
npm test
npm run inventory
npm run snapshot
```

Generated raw evidence stays in the ignored `.cache/evidence` directory.
Reviewed, normalized evidence is committed as
[`evaluation-summary.json`](../../spikes/openapi-validator/evidence/evaluation-summary.json),
[`inventory-summary.json`](../../spikes/openapi-validator/evidence/inventory-summary.json),
and
[`vacuum-modules.json`](../../spikes/openapi-validator/evidence/vacuum-modules.json).
These snapshots omit raw candidate output and timing noise; their environment
metadata and Vacuum binary hash remain platform-specific.
