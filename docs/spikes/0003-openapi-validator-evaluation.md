# OpenAPI validator evaluation

- Issue: [#3](https://github.com/SpecArgus/PROOF/issues/3)
- Stock CLI screening date: 2026-07-23
- Direct adapter evaluation dates: 2026-07-24 through 2026-07-25
- Current evidence: complete Linux x64, macOS arm64, and Windows x64 run
- Cross-platform status: complete with identical evaluation inputs
- Decision status: final recommendation; maintainer approval pending
- Reproduction harness: [`spikes/openapi-validator`](../../spikes/openapi-validator/README.md)

## Recommendation

Select `openapi-spec-validator 0.9.0` behind a small, versioned process adapter
Do not merge the disposable evaluation adapters into `develop`.

The Python candidate is the only direct adapter that passed every required
gate on Linux x64, macOS arm64, and Windows x64. It combined strict JSON/YAML
preflight parsing, a repository-confined local reference closure, a
deny-by-default in-memory resolver, defining-file diagnostics, and explicit
diagnostic truncation. Its exact CPython `3.14.2` runtime and identical
20-package runtime set are hash locked.

This recommendation is intentionally narrower than a production architecture
decision. PROOF's application, CLI, GitHub App, and report service do not have
to be written in Python. The selected validator can remain an isolated
subprocess behind a stable JSON contract.

The production adapter must still run inside a no-egress, memory-limited
worker. The experiment does not make its path preflight or language runtime a
complete sandbox.

## Decision scope

This spike selects the generic OpenAPI structural and semantic validation
authority used below PROOF's product-specific Agent contract rules. It does
not select the complete application stack and does not implement the rule
engine, CLI UX, GitHub orchestration, or report service.

The comparison is decision-grade rather than a claim of formal parser
verification. It covers the requirements most likely to force a later
validator replacement:

- OpenAPI 3.0 and 3.1 support;
- repository-local multi-file references;
- stable defining-file locations;
- deterministic normalized output;
- remote and repository-escape denial;
- exact input and reference-closure limits;
- diagnostic volume control;
- Windows, Linux, and macOS packaging; and
- pinned dependency, license, SBOM, and known-vulnerability evidence.

Candidate-specific production hardening is deferred until one adapter is
approved.

## Stage 1: stock CLI screening

### Candidates

| Candidate | Version | Profile |
| --- | --- | --- |
| Vacuum | `0.29.10` | `oas3-schema`, reference resolution, remote disabled |
| Stoplight Spectral | `6.16.2` | official OAS ruleset |
| Redocly CLI | `2.40.0` | `spec` ruleset |

### Method and result

The black-box corpus covers valid, malformed, structurally invalid, and
multi-file OAS 3.0/3.1 inputs, unresolved references, a loopback remote
canary, and exact decimal and binary 10 MB boundaries. Native candidate
behavior is recorded separately from runner preflights.

The reviewed run passed 32 of 39 candidate cases. All three stock CLIs retained
gaps:

| Candidate | Screening conclusion |
| --- | --- |
| Vacuum | Strongest stock CLI baseline, but some OAS 3.1 and parse diagnostics lacked the required evidence location |
| Spectral | Useful policy engine, but returned valid for an invalid external referenced schema |
| Redocly CLI | Detected structural problems but frequently lacked the required source coordinates |

A stock CLI is therefore not recommended as PROOF's generic validation
authority. Spectral may still be useful later as an optional style or policy
engine, but its pinned CLI closure is not part of the selected validator path.

## Stage 2: direct adapter comparison

### Candidates

| Candidate | Pinned implementation |
| --- | --- |
| libopenapi | `libopenapi v0.38.7`, `libopenapi-validator v0.14.0`, Go `1.25.12` |
| Redocly Core | `@redocly/openapi-core 2.40.0`, `jsonc-parser 3.3.1`, Node.js `24.13.0` |
| openapi-spec-validator | `openapi-spec-validator 0.9.0`, CPython `3.14.2` |

Each disposable process implements:

```text
validate(entrypoint, repositoryRoot, limits) -> normalized JSON result
```

The result contract distinguishes `valid`, `invalid`, `parse-error`,
`policy-denied`, `limit-exceeded`, and internal failures. Diagnostics contain
a repository-relative source, one-based coordinates, RFC 6901 pointer, stable
code, severity, kind, and message. Sorting, deduplication, output capture, and
process termination are bounded and deterministic.

### Common corpus

The corpus contains 26 cases grouped into nine required gates:

1. OAS 3.0/3.1 and local-reference correctness;
2. strict JSON/YAML parsing, including duplicate keys, invalid UTF-8,
   multiple YAML documents, and cyclic aliases;
3. root-confined path, encoded-path, file URI, symlink, and junction handling;
4. transitive no-egress;
5. reference depth, canonical file-count, and aggregate-byte limits;
6. exact decimal and binary entrypoint byte boundaries;
7. recursive-reference termination;
8. deterministic defining-file diagnostics; and
9. diagnostic observation and truncation.

Partial or candidate-filtered runs cannot produce a selectable disposition or
refresh the reviewed snapshot.

### Reviewed Windows result

The full Windows run evaluated 78 candidate-case combinations. Seventy-five
were applicable, 73 passed, two were gaps, and three POSIX symlink cases were
skipped. All supervisor self-checks and all three Windows junction cases
passed.

| Capability | libopenapi | Redocly Core | openapi-spec-validator |
| --- | --- | --- | --- |
| Applicable required cases | 25 | 25 | 25 |
| Passed required cases | 24 | 24 | 25 |
| Required gates | 8/9 | 8/9 | **9/9** |
| Network request observed | No | No | No |
| Hard-gate failure | No | No | No |
| Windows disposition | `has-gaps` | `has-gaps` | **`selectable-on-windows`** |

#### libopenapi gap

`multi-file-deterministic-invalid` contains two invalid bare schemas in
external local files. All ten repetitions returned `valid` with no
diagnostic. The output was deterministic but wrong, so this is a structural
validation false negative.

#### Redocly Core gap

`diagnostic-flood` contains twelve independent missing-response errors.
Redocly Core exposed only one raw finding. The adapter's output cap is stable,
but it cannot demonstrate the required observation, emitted-count, and
truncation contract when the underlying rule stops after the first error.

#### openapi-spec-validator result

The candidate passed both cases above. It reported defining-file locations for
the invalid external schemas and deterministically observed twelve findings,
emitted the configured five, and reported seven truncated findings.

Version `0.9.0` can raise an internal `KeyError` during a later semantic pass
for some values already rejected by its complete meta-schema pass. The adapter
retains previously yielded structural findings and treats an exception with no
prior finding as an internal adapter failure. This behavior is pinned,
unit-tested, and must be revisited on dependency upgrades.

## Supply-chain evidence

The local inventory was generated with npm `11.6.2`, Go `1.25.12`, and
CPython `3.14.2`.

| Surface | Inventory | Known-vulnerability observation |
| --- | --- | --- |
| Vacuum CLI | 95-96 linked modules; Windows reference binary 90,470,400 bytes | Not the recommended product path |
| Spectral CLI | 240-component Linux/Windows closure; 241 on macOS due to optional `fsevents` | 12 high-severity package records in this rejected closure |
| Redocly Core adapter | 22-component Node closure | None of the 12 npm records occur in this closure |
| libopenapi adapter | 16 linked modules; Windows reference binary 20,269,568 bytes | `govulncheck`: zero reachable or module findings |
| openapi-spec-validator adapter | 20 exactly locked Python packages | PyPI release-specific inventory: zero active records |

No inventory entry had an unrecognized declared license. This is a technical
metadata inventory, not a legal compatibility opinion or a package-content
audit.

The vulnerability results are time-bound:

- Go was checked with `govulncheck 1.6.0` against
  `https://vuln.go.dev`;
- Node was checked with npm `11.6.2` against the official npm registry; and
- Python package releases were queried through PyPI's release-specific JSON
  API.

The Python check does not prove that undisclosed vulnerabilities are absent.
The Node result attributes installed vulnerable package names to recorded
candidate closures but does not prove exploitability or reachability.

## Security boundary and remaining limitations

The experiment proves controlled outcomes and reported closure accounting. It
does not independently instrument every operating-system file read. A
production worker must therefore enforce no-egress, memory, CPU, wall-time,
process-tree, and filesystem boundaries outside the adapter.

The common comparative corpus covers parent and percent-encoded escapes,
`file://`, remote references, and platform link escapes. Absolute POSIX,
Windows drive, device, UNC, and protocol-relative spellings are denied by the
adapter implementations and focused tests or review, but they are not all
separate required common-corpus cases in this decision snapshot.

The corpus rejects cyclic YAML aliases. More general acyclic alias
amplification, concurrent filesystem mutation, and path-resolution
time-of-check/time-of-use attacks require worker-level limits and targeted
production-adapter tests. These are follow-up hardening requirements, not
reasons to make all three disposable candidates production ready.

## Cross-platform evidence and disposition

The workflow runs Ubuntu 24.04 x64, Windows Server 2022 x64, and macOS 15
arm64 from the PR head commit. Every matrix job performs the locked install,
bootstrap, unit tests, both evaluation stages, audits, inventory, and reviewed
snapshot.

Actions run
[`30143349681`](https://github.com/SpecArgus/PROOF/actions/runs/30143349681)
completed all three matrix jobs from commit
`97336e58ea5754d0b17e2aec802b42c7e7d4d618`. The durable
[cross-platform manifest](../../spikes/openapi-validator/evidence/platforms/cross-platform-manifest.json)
records:

- source commit and Actions run;
- platform and runtime versions;
- identical evaluation input fingerprints;
- candidate dispositions and required-gate results; and
- reviewed artifact and file content digests.

All three snapshots have the same evaluation input SHA-256
`e62d2639bdc31b1585ee2a66649d497338897d3daed3332ed5565c63c75432ce`.
Each reports 32/39 stock CLI cases, 73/75 applicable direct-adapter cases, the
same two isolated candidate gaps, and a 9/9 required-gate result for
openapi-spec-validator. Go and Python audits passed on each platform; Node
reported no selection-relevant finding.

The npm graph contains one additional macOS-only `fsevents` component in the
rejected Spectral closure. Vacuum's linked module count also varies with
platform build tags. The Redocly Core closure remains 22 components and the
recommended Python candidate remains the same 20-package set on all three
platforms.

After maintainer approval:

1. preserve the experiment as
   `archive/3-openapi-validator-evaluation`;
2. create an immutable research tag;
3. close PR #13 without merging the disposable adapters into `develop`; and
4. implement only the selected product adapter from a new `develop`-based
   branch.

## Reproduce

From `spikes/openapi-validator`:

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

The tracked evidence snapshot is accepted only when both evaluation stages are
complete, the adapter run is full rather than partial, artifacts and runtime
fingerprints match, supervisor controls pass, and no selection-relevant audit
finding remains.
