# ADR 0001: Use a Python-first workspace with an isolated validator process

- **Status:** Accepted
- **Date:** 2026-07-25
- **Owners:** PROOF maintainers (`@back1ash`)
- **Issue:** [#5](https://github.com/SpecArgus/PROOF/issues/5)

## Context

PROOF needs one deterministic analysis core that is shared by the local CLI
and future hosted workers. The implementation must support OpenAPI 3.0.x and
3.1.x, repository-local references, stable normalized findings, resource
limits, locked dependencies, and Windows, macOS, and Linux.

The validator evaluation in issue
[#3](https://github.com/SpecArgus/PROOF/issues/3) selected
`openapi-spec-validator 0.9.0` behind a small versioned process adapter. It was
the only candidate that passed all nine required gates on the reviewed Linux
x64, macOS arm64, and Windows x64 runs. The reviewed implementation used
CPython `3.14.2` and an exactly locked 20-package runtime set.

The spike deliberately did not choose the application runtime. Its evidence
does, however, change the cost of the alternatives:

- a TypeScript core would still need to distribute and supervise a Python
  validator runtime;
- a Python core and CLI can use the selected library without introducing a
  second end-user runtime, while preserving the required process boundary;
- a future web interface may use TypeScript without owning or reimplementing
  analysis behavior.

The runtime decision must not weaken the language-neutral result contract from
issue [#4](https://github.com/SpecArgus/PROOF/issues/4) or make hosted execution
behave differently from the CLI.

## Decision

### Runtime and tooling

Use CPython as the implementation runtime for the PROOF analysis core, rule
pack, validator worker, CLI, and future hosted scan worker.

- The initial canonical runtime line is CPython `3.14.x`. The exact patch
  version is pinned in development, CI, and release manifests rather than in
  this ADR so security patch upgrades do not require a new architecture
  decision.
- Additional Python minor versions are not supported until their golden,
  packaging, and platform matrices pass. Each runtime identity is part of
  provenance.
- Use `uv` as the project and workspace manager with one committed
  cross-platform `uv.lock`.
- Use `hatchling` as the Python build backend and `pytest` as the test
  framework.
- Use `ruff` for formatting and linting and a strict Python type checker for
  package boundaries. The scaffold issue will select and pin the type checker
  after verifying CPython 3.14 support.

The CLI will initially be published as a Python package and console entry
point. A standalone executable may be added only after its contents,
cross-platform behavior, update path, signatures, and SBOM can be reproduced
from the same source and lockfile.

### Repository shape

Use one repository and one Python workspace with explicit package boundaries:

```text
packages/
  contracts/          versioned JSON Schemas and protocol models
  validator-worker/   isolated openapi-spec-validator process
  rulepack/           versioned built-in rules and documentation
  core/               orchestration, normalization, rules, gate, fingerprints
  cli/                command parsing and console/JSON reporters
services/
  scan-worker/        future hosted supervisor that invokes the same core
  github-app/         future webhook and Check orchestration
  report-web/         future report API and UI
tests/
  contract/           cross-package and process-contract tests
  golden/             deterministic local/hosted parity fixtures
```

Directory names are architectural roles, not reserved public package names.
Public distribution names remain blocked on the product-identity decision.

The dependency direction is:

```text
contracts <- validator-worker
contracts <- rulepack <- core <- cli
contracts <--------------- core
validator process client <- core
core <- future scan-worker
```

The CLI, GitHub integration, and report service must not implement rule or
gate behavior. They consume the same core result. The web UI may use
TypeScript, but it treats versioned result JSON as data and cannot become a
second analysis core.

Workspace convenience is not a security or dependency-isolation mechanism.
Import-boundary checks and package-level tests must prevent a member from
using undeclared dependencies made visible by a shared development
environment.

### Validator boundary

Keep `openapi-spec-validator 0.9.0` in `validator-worker`, not in the core
package. The core invokes it through a versioned JSON request/response
contract over standard input and standard output:

```text
validate(entrypoint, repositoryRoot, limits) -> normalized validator result
```

Standard output is protocol-only. Human diagnostics go to a bounded standard
error stream. The supervisor validates both request and response schemas,
captures bounded output, applies a wall-time limit, terminates the complete
process tree on failure, and maps protocol or process failures to explicit
internal outcomes.

The adapter performs strict JSON/YAML preflight parsing, constructs a
repository-confined reference closure, rejects remote and escaping references,
passes only the closed in-memory resource set to the validator, normalizes
defining-file diagnostics, sorts and deduplicates them, and reports diagnostic
truncation.

The process boundary provides crash and output isolation; it is not by itself
a sandbox.

### Determinism and resource enforcement

- Input bytes, repository-relative source identities, effective configuration,
  rule-pack artifacts, validator artifacts, core artifacts, and the explicit
  evaluation time are inputs to provenance and deterministic comparison.
- Environment-specific values such as absolute paths, temporary directories,
  process IDs, hostnames, and elapsed time are excluded from normalized
  results.
- Contract schemas define canonical ordering and serialization. The core
  performs final sorting and fingerprinting after validator and rule findings
  are normalized.
- The CLI supervisor enforces entrypoint and reference-closure byte limits,
  reference depth, file count, diagnostic count, wall time, captured output,
  and process-tree termination.
- Local CPU and memory limits are best-effort where the host operating system
  cannot enforce them portably. Hosted workers must add hard no-egress,
  filesystem, CPU, memory, wall-time, and process limits outside Python.
- A timeout, malformed worker response, dependency failure, or sandbox failure
  is never converted into a successful scan.

### Supported development and release platforms

The initial required matrix is:

- Windows x64;
- Linux x64; and
- macOS arm64.

macOS x64 remains a compatibility target when runner and release-artifact
capacity is available. Other architectures are unsupported until added by a
separate compatibility decision and test matrix.

Every release workflow must:

1. install a pinned `uv` and CPython patch version;
2. reject a stale lockfile;
3. run unit, contract, golden, and platform smoke tests;
4. build wheels and source distributions from a clean checkout;
5. export dependency inventory and CycloneDX SBOM evidence;
6. record source, runtime, dependency, validator, rule-pack, and artifact
   digests; and
7. sign and attest published artifacts through the release workflow.

## Options considered

### Option A: Python-first core and CLI with an isolated Python validator

- **Summary:** Use one Python runtime for local product behavior while keeping
  parsing and generic validation in a supervised child process.
- **Benefits:** Reuses the selected validator without a second end-user
  runtime, keeps CLI packaging direct, supports one analysis implementation,
  and makes the process contract independently testable.
- **Costs and risks:** Python process startup and packaging must be measured;
  Python workspace members do not get dependency isolation automatically; a
  TypeScript report UI would add a later non-analysis runtime.
- **Reason accepted:** It is the smallest architecture consistent with the
  selected validator, local/hosted parity, and Phase 1 delivery.

### Option B: TypeScript core and CLI with a Python validator sidecar

- **Summary:** Use a `pnpm` TypeScript workspace for product logic and invoke
  the selected Python validator as a child process.
- **Benefits:** Strong alignment with GitHub and web tooling and one language
  for a future server and report UI.
- **Costs and risks:** The local CLI must install, locate, pin, update, and
  diagnose both Node.js and Python. Standalone packaging must bundle two
  runtimes or reproduce an external Python environment. Cross-language models
  and release artifacts increase the parity surface before product value is
  proven.
- **Reason rejected:** The hosted-web benefit does not justify two runtime
  closures in the Phase 1 CLI and core.

### Option C: Go core and CLI with libopenapi

- **Summary:** Build a portable Go binary and use the Go validator candidate.
- **Benefits:** Straightforward single-binary distribution and strong process
  supervision primitives.
- **Costs and risks:** The evaluated libopenapi adapter returned valid for
  invalid schemas reached through local external references. Keeping the
  selected Python validator would reintroduce a second runtime.
- **Reason rejected:** It either changes the approved validation authority or
  retains the dual-runtime cost.

### Option D: Maintain separate Python CLI and hosted core implementations

- **Summary:** Optimize each interface independently and synchronize behavior
  through fixtures.
- **Benefits:** Each deployment can use its locally convenient stack.
- **Costs and risks:** Rule behavior, ordering, fingerprints, error mapping,
  and dependency upgrades can drift despite tests.
- **Reason rejected:** It violates the single-core and local-equals-hosted
  product requirements.

## Consequences

### Positive

- Phase 1 uses one end-user runtime and one dependency lock.
- The selected validator remains replaceable behind a stable process
  contract.
- Validator crashes and malformed output are separated from the parent CLI.
- Hosted workers can call the same core without copying rule behavior.
- TypeScript remains available for a future report UI without becoming an
  analysis authority.

### Negative and trade-offs

- The first supported CLI requires a managed Python runtime unless and until
  standalone artifacts satisfy release criteria.
- Python subprocess startup may affect small-file latency and must be measured
  against the three-minute demo and future p95 target.
- Local no-egress, memory, and CPU enforcement cannot be claimed as a complete
  sandbox on every supported operating system.
- The workspace needs explicit import-boundary enforcement because a shared
  environment can hide undeclared dependencies.
- The Phase 0 TypeScript-first recommendation is superseded by validator
  evidence for the analysis and CLI path, not for a future presentation-only
  web client.

## Security and privacy

All OpenAPI documents, repository paths, configuration, and worker output are
untrusted data. Neither dependency installation hooks nor repository-provided
code or plugins run during a scan. Remote references are denied by default,
and local references must remain inside a canonical repository root after
link resolution.

The validator subprocess receives no GitHub token or service credential.
Future hosted fetchers retrieve immutable content and pass only a prepared
read-only workspace plus bounded request data into a no-egress worker. The
worker cannot choose report destinations or modify trusted policy.

The process adapter, strict parser, and path preflight reduce risk but do not
replace OS-level isolation. Hosted production use is blocked until the threat
model defines and tests hard filesystem, network, CPU, memory, process, output,
and time boundaries. The accepted
[initial threat model](../security/initial-threat-model.md) defines those
boundaries and the verification gates that must precede hosted use.

Normalized results and provenance must not contain secrets, absolute host
paths, environment variables, or credentials. Raw untrusted diagnostics are
escaped by every reporter.

## Reproducibility and compatibility

The source tree, `uv.lock`, pinned runtime/tool versions, JSON Schemas, and
golden fixtures are version controlled. CI uses locked installs and rejects
implicit dependency upgrades. Dependency and runtime upgrades require the
validator contract suite, deterministic golden suite, platform matrix, SBOM
refresh, vulnerability review, and explicit provenance changes.

`openapi-spec-validator 0.9.0` remains pinned until a separate upgrade change
passes the complete validator corpus. Its known post-schema `KeyError`
behavior is normalized only when prior structural findings exist; an
exception without prior findings is an internal failure.

The language-neutral JSON result schema is the compatibility boundary for the
CLI, hosted services, and report clients. Python object layouts are not a
public contract.

## Follow-up actions

- [ ] Accept normalized result schema v1 — issue #4.
- [ ] Scaffold the accepted workspace, package boundaries, lockfile, and CI —
      follow-up implementation issue after this ADR is accepted.
- [ ] Implement only the selected production validator worker and protocol —
      follow-up implementation issue.
- [ ] Specify and test the five P0 rule contracts — issue #10.
- [x] Review and accept the hard worker limits and residual risks in the
      accepted [initial threat model](../security/initial-threat-model.md) —
      issue #8 and PR #47.
- [ ] Decide public distribution names before publishing packages — issue #6.
- [ ] Measure subprocess startup and first-scan installation time before the
      CLI alpha exit review.

## Decision history

- 2026-07-25 — Proposed after completion of the cross-platform validator
  evaluation and maintainer approval of `openapi-spec-validator 0.9.0`.
- 2026-07-25 — Accepted by the repository owner. Product implementation may
  proceed through issue-scoped pull requests based on this architecture.
