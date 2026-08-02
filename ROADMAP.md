# Roadmap

PROOF helps maintainers review whether OpenAPI operations provide clear, actionable contracts for function-calling agents. The roadmap is ordered by validated capability, not calendar dates. A phase advances only when its exit criteria are met.

## Product principles

- Prefer evidence and actionable findings over opaque scores.
- Keep local CLI and hosted results reproducible and equivalent.
- Treat specifications, configuration, forks, and remote references as untrusted input.
- Fail visibly when an input cannot be evaluated.
- Version the engine, rule pack, configuration schema, and result schema.

## Phase 0: Discovery and architecture decisions

### Entry criteria

- The repository foundation is merged into `develop`, with contribution,
  governance, security, and release policies present.
- Protected-branch and repository-validation controls are active.
- The public working identity, three equal co-maintainers, and both evidence
  reviewers are recorded.
- Phase 0 outcomes, evidence work, and exit criteria are tracked in public
  issues and this roadmap.

Foundation PR #2 satisfied the repository-policy and protection prerequisites.
The merge of ADR 0002 into `develop` in Accepted status, after all three role
members acknowledge their responsibilities, satisfies the remaining criteria
and records Phase 0 entry. The merge date does not establish a fixed review
date.

### Governance

- Public working identity: `SpecArgus PROOF`.
- Accountable role for product decisions, success metrics, security response,
  and releases: Phase 0 co-maintainers.
- Equal role members: `@back1ash`, `@Seo-yul`, and `@minsubyun1`.
- Evidence reviewers: `@Seo-yul` and `@minsubyun1`.
- Material-decision rule: recorded agreement from at least two co-maintainers.
- Review timing: exit-criteria-driven, with no fixed calendar date.
- Gate outcomes: proceed, revise and re-evaluate, or stop.

See [ADR 0002](docs/adr/0002-product-identity-and-phase-0-governance.md) for the
decision and evidence trigger.

### Outcomes

- Confirm the public product name, repository scope, decision owners, and success-metric owners.
- Compare candidate OpenAPI validators for OAS 3.0/3.1 support, repository-local `$ref` resolution, source locations, deterministic output, resource limits, no-egress operation, licensing, and supply-chain transparency.
- Record the runtime and repository architecture in an ADR after the validator spike.
- Define result schema v1 for findings, runs, gates, and provenance.
- Specify the initial rules (`AGT-CTX-001`, `AGT-PARAM-001`, `AGT-RESP-001`, `AGT-POL-001`, and `AGT-POL-002`) with positive, negative, and false-positive examples.
- Build a labeled corpus of at least 100 OAS 3.0/3.1 operations.
- Validate GitHub App permissions and public-fork behavior across the identified pull-request matrix.
- Document the threat model for parsers, `$ref`, denial of service, SSRF, tokens, reports, and untrusted repository content.
- Interview 5–8 target maintainers using the pre-registered
  [Phase 0 interview plan](docs/research/phase-0-maintainer-interview-plan.md)
  to evaluate App installation, vendor extensions, acceptable false positives,
  and offline alternatives.

### Exit criteria

- The selected validator satisfies the required dialect, local-reference, location, determinism, and resource-limit tests, or its accepted limitations are documented.
- Runtime and monorepo decisions are accepted through ADRs informed by the validator results.
- Expected findings are agreed for at least 100 labeled operations.
- The public-fork proof of concept demonstrates isolated checks for the test-merge commit, or the initial hosted scope is explicitly narrowed.
- A recorded go/no-go decision determines whether the hosted GitHub App and web report proceed.

> The runtime, package manager, monorepo tooling, and validator are intentionally deferred until this phase is complete.

## Phase 1: Core and CLI alpha

### Outcomes

- Implement the OpenAPI loader, normalizer, generic validation adapter, risk classifier, initial rule pack, gate evaluation, and deterministic fingerprints.
- Provide console and stable JSON reporters, output files, configuration validation, and exit codes `0` through `3`.
- Publish bad/good example specifications and a reproducible three-minute demonstration.
- Produce a provenance manifest, locked dependencies, SBOM, and content-addressed release artifacts.

### Exit criteria

- Repeated runs with identical inputs and pinned artifacts produce byte-equivalent normalized results.
- The bad example is blocked with actionable evidence; the corrected example passes.
- Gate failures, input/configuration failures, and internal failures use distinct documented exit codes.
- Smoke tests pass on supported Windows, macOS, and Linux environments.
- Every published artifact can be traced to its engine, validator, rule-pack, configuration, and input digests.

## Phase 2: GitHub App and web report (conditional)

This phase begins only after the Phase 0 hosted-product go decision.

### Outcomes

- Implement verified webhooks, delivery deduplication, a durable queue/outbox, isolated no-egress workers, retries, and stale-run recovery.
- Derive effective policy from the trusted base while reading pull-request specifications without executing repository code.
- Publish pending, success, advisory, failure, and error Check Run states linked to immutable reports.
- Provide finding filters, JSON download, reproduction commands, rerequests, visibility checks, and report tombstoning.

### Exit criteria

- Successful and blocked pull requests reach the matching terminal Check Run and report states.
- CLI and hosted scans produce identical normalized findings for the golden corpus.
- Public-fork scans complete without executing fork code or exposing write credentials.
- Attempts to weaken the gate through head-branch configuration or scope changes are rejected by the security fixtures.
- Duplicate deliveries and rerequests remain idempotent while preserving distinct attempts.

## Phase 3: Public OSS alpha

### Outcomes

- Run with at least three public design-partner repositories, including a monorepo and a fork-contribution workflow.
- Publish contributor documentation, support and security policies, reproducible packages, and rule documentation.
- Collect rule-level precision, recall, remediation, latency, reliability, and onboarding evidence.

### Exit criteria

- Terminal Check Run coverage is at least 99% and p95 completion time is at most 60 seconds for the agreed workload.
- At least 10 initially blocked pull requests are observed, with at least 50% subsequently corrected and passed.
- At least two of three design partners retain the check after four weeks.
- Initial HIGH-severity rules achieve at least 90% precision and seeded-risk recall reaches at least 80%.
- No security incident occurs, and rules missing their quality target are removed from blocking status.

## Phase 4: Public beta and P1 capabilities

### Candidate scope

- Breaking-change integration, baseline/new-only gates, line annotations, Markdown and SARIF output.
- Versioned shared presets, per-rule controls, and reasoned, expiring ignores.
- Private-repository authorization, retention, and report access controls.
- Monorepo discovery, merge-queue support, risk overrides, and an explicit OAS 3.2 support decision.

### Exit criteria

- Each promoted capability has documented compatibility, migration, security, and rollback behavior.
- Private-repository support passes current-access revalidation and data-retention reviews before availability.
- Preset and rule-pack upgrades remain opt-in, pinned, auditable, and reproducible.
- Beta support, retention, release, and compatibility policies are published.

## Deferred beyond beta

Custom rule languages, executable user plugins, MCP `tools/list` adapters, framework source adapters, LLM remediation, non-GitHub forges, and implementation/traffic drift analysis remain out of scope until the core contract-gating workflow is proven.
