# OpenAPI validator evaluation spike

This directory contains the reproducible evidence harness for issue
[#3](https://github.com/SpecArgus/PROOF/issues/3). It compares validator
candidates as black-box processes before PROOF selects a production runtime or
validator.

The JavaScript runner is disposable Phase 0 tooling. Its presence is not a
runtime decision. Candidate-native behavior and protections supplied by the
runner are reported separately so adapter work is not mistaken for a native
capability.

## Candidates

| Candidate | Pinned version | Evaluation surface |
| --- | --- | --- |
| Vacuum | `0.29.10` | Go CLI backed by the libopenapi ecosystem |
| Stoplight Spectral | `6.16.2` | Node CLI and official OAS ruleset |
| Redocly CLI | `2.40.0` | Node CLI and `spec` ruleset |

The report also reviews lower-level library APIs and rejected alternatives.
CLI results are evidence about observable behavior, not a commitment to embed
the CLI in the production core.

## Evaluation profile

- OAS 3.0 and 3.1, YAML and JSON
- valid, malformed, structurally invalid, and unresolved-reference inputs
- repository-local multi-file references
- remote-reference canary that counts actual loopback HTTP requests
- deterministic normalized diagnostics across relocated workspaces
- a 5-second process timeout and 1 MiB output capture limit
- a 100-diagnostic normalized-output limit
- both decimal `10 MB` and binary `10 MiB` input boundaries
- native probes before remote-reference and oversized-input preflights
- self-tests for timeout, total-output, and diagnostic-volume controls

The size cases intentionally test both `10,000,000` and `10,485,760` bytes.
The spike recommends a final product definition; it does not silently turn the
ambiguous `10 MB` wording into a compatibility contract.

Candidate findings and harness health are separate:

- `PASS` means the candidate plus the explicitly recorded adapter controls met
  the fixture contract.
- `GAP` means the candidate surface did not meet that contract.
- A completed evaluation exits zero even when it finds candidate gaps.
- `npm run evaluate:strict` exits non-zero when any candidate gap remains.
- Harness integrity failures use `runStatus: incomplete` and exit code `2`.

Cases executed once are marked `not-assessed` for determinism. Repeated cases
must produce one canonical SHA-256 after path and diagnostic normalization.

## Reproduce

Requirements:

- Node.js `24.x` or a version supported by the pinned CLIs
- npm `11.6.2`
- Go with toolchain download support (`go1.25.12` is pinned for the build)

From this directory:

```text
npm ci --ignore-scripts
npm run bootstrap
npm test
npm run inventory
npm run snapshot
```

`--ignore-scripts` prevents dependency install hooks from running. Bootstrap
builds the pinned Vacuum source into this directory's ignored `.cache`
directory. Evaluation evidence is also written below `.cache`; only reviewed,
stable summaries belong in the repository.

`npm run inventory` writes:

- an npm CycloneDX 1.5 SBOM;
- Vacuum's `go version -m -json` build inventory;
- candidate dependency and license summaries; and
- a heuristic license inventory for modules linked into Vacuum.

`npm run snapshot` strips raw output and timing noise from a completed run and
refreshes the reviewed, tracked evidence in [`evidence`](evidence/README.md).
Run it only when intentionally updating the issue #3 baseline.

The path-filtered `openapi-validator-evaluation` GitHub Actions job runs the
same locked install, build, evaluation, inventory, and audit on pull requests
that change this spike.

## Boundaries

The harness does not claim to provide a production sandbox. Candidate process
timeouts and output limits are exercised here; enforceable memory, filesystem,
and network isolation remain worker responsibilities. A candidate passes the
remote-reference case only when the canary observes zero requests and the tool
returns a controlled diagnostic.

The shared remote-reference preflight is intentionally a fixture-level
prototype: it scans the entrypoint for an HTTP(S) `$ref`. It is not a security
boundary and does not cover transitive references, URI rebasing, or path
containment. A production adapter must instead use a root-confined local
resolver with HTTP(S) handlers omitted, reject path and symlink escapes, cap
the full reference closure, and run in a no-egress worker.
