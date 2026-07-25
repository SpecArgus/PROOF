# OpenAPI validator evaluation spike

This directory contains the reproducible evidence harness for issue
[#3](https://github.com/SpecArgus/PROOF/issues/3). It first screens stock
validator CLIs as black-box processes, then evaluates three direct library
adapters against a stricter common contract.

Both stages are implemented. Three disposable direct adapters are now
evaluated. `openapi-spec-validator` passes every required gate on the reviewed
Linux x64, macOS arm64, and Windows x64 runs. The final recommendation still
requires explicit maintainer approval before it becomes a product selection.
The full findings are recorded in the
[evaluation report](../../docs/spikes/0003-openapi-validator-evaluation.md).

The JavaScript runners are disposable Phase 0 tooling. Their presence is not a
runtime decision.

## Stage 1: stock CLI screening

| Candidate | Pinned version | Evaluation surface |
| --- | --- | --- |
| Vacuum | `0.29.10` | Go CLI backed by the libopenapi ecosystem |
| Stoplight Spectral | `6.16.2` | Node CLI and official OAS ruleset |
| Redocly CLI | `2.40.0` | Node CLI and `spec` ruleset |

Candidate-native behavior and protections supplied by the runner are reported
separately so a harness preflight is not mistaken for a native capability.
The CLI results are screening evidence, not a commitment to embed a CLI in the
production core.

The Stage 1 corpus covers:

- OAS 3.0 and 3.1, YAML and JSON;
- valid, malformed, structurally invalid, and unresolved-reference inputs;
- repository-local multi-file references;
- a remote-reference canary that counts actual loopback HTTP requests;
- deterministic normalized diagnostics across relocated workspaces;
- exact decimal `10 MB` and binary `10 MiB` input boundaries; and
- supervisor self-tests for time, captured output, and diagnostic volume.

## Stage 2: direct adapter evaluation

| Adapter | Pinned libraries | Reviewed cross-platform result |
| --- | --- | --- |
| libopenapi | `libopenapi v0.38.7`, `libopenapi-validator v0.14.0` | Same gap on all three OSes: invalid bare-file schemas reached through external local references can be returned as valid |
| Redocly Core | `@redocly/openapi-core 2.40.0`, `jsonc-parser 3.3.1` | Same gap on all three OSes: the structural validator exposes only the first of twelve independent errors in the diagnostic-flood fixture |
| openapi-spec-validator | `openapi-spec-validator 0.9.0`, CPython `3.14.2` | Passes all nine required gates on Linux, macOS, and Windows |

All three adapters implement the same process contract:

```text
validate(entrypoint, repositoryRoot, limits) -> normalized JSON result
```

The contract distinguishes valid, invalid, parse-error, policy-denied,
limit-exceeded, and internal outcomes. Diagnostics use a relative source,
one-based line and column, RFC 6901 pointer where available, stable code,
severity, kind, and message.

The common corpus has 26 cases grouped into nine required gates:

1. dialect and local-reference correctness;
2. strict JSON/YAML parsing, including duplicate keys, invalid UTF-8,
   multiple YAML documents, and cyclic aliases;
3. a root-confined filesystem, including path, encoded-path, symlink, and
   junction escapes;
4. transitive no-egress;
5. reference depth, file-count, and aggregate-byte limits;
6. exact decimal and binary entrypoint byte boundaries;
7. cycle termination;
8. deterministic defining-file diagnostics; and
9. diagnostic volume and truncation accounting.

Each reviewed platform run evaluated 78 candidate-case combinations.
Seventy-five were applicable: 73 passed, two exposed the isolated gaps above,
and three cases for the other platform's link mechanism were skipped. The
Windows junction combinations and the Ubuntu/macOS POSIX symlink combinations
passed.

The libopenapi case assigned to the deterministic-diagnostics gate is stable,
but wrong: all repetitions returned `valid` with no diagnostic for two invalid
external schemas. The failure is validation correctness, not
nondeterminism. Redocly's output cap works in focused tests, but the underlying
validator provides only one raw finding for the twelve-error flood fixture, so
the required emitted and truncated counts cannot be demonstrated.

The Python adapter rejected remote and escaping references before exposing the
closed in-memory resource set to the validator, produced defining-file
locations, and emitted deterministic capped diagnostics for the multi-file and
diagnostic-flood cases. This is a cross-platform-qualified experimental
result, not a production selection.

## Result semantics

- `PASS` means the candidate plus explicitly recorded adapter controls met the
  fixture contract.
- `GAP` means the candidate surface did not meet that contract.
- A completed evaluation exits zero even when it finds candidate gaps.
- A strict evaluation exits non-zero while any required gap remains.
- Harness integrity failures use `runStatus: incomplete` and exit code `2`.
- Repeated cases must produce one canonical SHA-256 after path and diagnostic
  normalization. Single-run cases are marked `not-assessed` for determinism.

`npm run assert:adapters` keeps CI green only when the two reviewed gaps remain
exactly isolated to
`libopenapi/multi-file-deterministic-invalid` and
`redocly-core/diagnostic-flood`. A new gap, a missing expected gap, or a harness
error fails the baseline assertion and requires review. It also requires
`openapi-spec-validator` to pass every required case applicable to the current
platform. Passing this assertion does not mean a candidate has been selected.

## Reproduce

Requirements:

- Node.js `24.13.0`;
- npm `11.6.2`;
- Go `1.25.12` with toolchain download support; and
- CPython `3.14.2`.

From this directory:

```text
npm ci --ignore-scripts
npm run bootstrap
npm test
npm run audit:go
npm run inventory
npm run audit:node
npm run audit:python
npm run snapshot
```

Useful focused commands:

```text
npm run evaluate
npm run evaluate:strict
npm run test:adapters:unit
npm run evaluate:adapters
npm run evaluate:adapters:strict
npm run assert:adapters
npm run test:adapters
```

`npm test` runs both stages and the reviewed adapter-gap assertion.
`npm run evaluate:adapters` succeeds when the harness is healthy even when
candidate gaps are present; `npm run evaluate:adapters:strict` fails while
any adapter has a required gap.

`--ignore-scripts` prevents dependency install hooks from running. Bootstrap
installs pinned Go tools, builds the Go candidates, creates a clean Python
virtual environment, and installs only hash-locked wheels. Generated artifacts
live in this directory's ignored `.cache` directory. Raw evaluation and
supply-chain evidence is also written below `.cache`; only reviewed, stable
summaries belong in the repository.

`npm run inventory` writes:

- an npm CycloneDX 1.5 SBOM;
- `go version -m -json` build inventories and binary hashes;
- candidate dependency and declared-license summaries;
- an exact Python lock-to-environment comparison; and
- heuristic license inventories for linked Go modules.

`npm run audit:go` runs the pinned `govulncheck` against the exact libopenapi
adapter binary and records a compact time-bound summary. `npm run audit:node`
uses npm `11.6.2` and the official registry, then attributes findings to the
candidate closures recorded by the inventory. The reviewed run reports twelve
high-severity package findings, all confined to the already rejected Spectral
CLI closure; the Redocly Core direct-adapter closure contains none of those
packages. `npm run audit:python` queries release-specific PyPI JSON for each
exactly locked runtime package.

These audits are time-bound known-vulnerability checks. They do not prove that
undisclosed vulnerabilities are absent, establish reachability for Node or
Python findings, or provide a legal license-compatibility conclusion.

`npm run snapshot` strips raw output, timing noise, and temporary paths from
completed runs and refreshes the reviewed files in
[`evidence`](evidence/README.md). Run it only when intentionally updating the
issue #3 baseline.

The path-filtered `openapi-validator-evaluation` workflow is configured to run
the locked installation, bootstrap, unit tests, both evaluation stages, the
reviewed gap assertion, vulnerability checks, inventory generation, and
reviewed snapshots on Ubuntu 24.04, Windows Server 2022, and macOS 15. Reviewed
and raw artifacts are uploaded separately. The successful three-platform
reviewed snapshots have been imported into
[`evidence/platforms`](evidence/platforms/README.md) with their Actions and
file digests because Actions retention is temporary.

## Security boundary

The direct adapters implement and exercise root-confined local resolution,
scheme denial, canonical-path containment, reference-closure accounting, and
deterministic diagnostic normalization. The harness observes controlled
denials and reported closure statistics; it does not independently trace every
operating-system file read. These controls are adapter evidence, not a complete
production sandbox.

Memory enforcement and an independent OS- or worker-level no-egress boundary
remain production responsibilities even when an adapter exposes no remote
resolver. Wall time, memory, process-tree termination, captured-output limits,
and defenses against parser-complexity attacks must remain supervisor controls.
Production hardening must also close file-resolution time-of-check/time-of-use
gaps rather than treating this disposable adapter as the sandbox boundary.

The size corpus preserves evidence for both `10,000,000` and `10,485,760`
bytes. Choosing the product's one inclusive raw-byte limit remains a separate
policy decision.
