# SpecArgus PROOF

**Policy Review of OpenAPI Operations for Function-calling**

SpecArgus PROOF is the public working identity for Phase 0. The permanent
launch name will be reconsidered at the Phase 0 gate; bare `proof` will not be
used as a package, executable, or GitHub App identifier. See
[ADR 0002](docs/adr/0002-product-identity-and-phase-0-governance.md).

PROOF is an early-stage open source project exploring a deterministic quality
gate for OpenAPI operations that will be exposed as AI agent or MCP tools.

> [!IMPORTANT]
> PROOF is currently in pre-alpha development. The CLI is implemented in the
> source workspace but is not yet published as a release artifact. The
> Python-first runtime and generic OpenAPI validator are selected,
> while the hosted architecture remains subject to the Phase 0 go/no-go
> decision.

## Problem

A syntactically valid OpenAPI document is not necessarily a clear or safe tool
contract for an agent. Tool selection, payload construction, side effects,
confirmation requirements, authorization hints, and structured failures all
depend on information that general-purpose OpenAPI validation may not require.

PROOF aims to identify those contract gaps before an API operation is exposed
to an agent, and to return evidence-based findings that can be reproduced
locally and in pull request checks.

## Intended scope

The initial product hypothesis includes:

- OpenAPI 3.0.x and 3.1.x YAML and JSON inputs
- repository-local `$ref` resolution with remote references disabled by default
- deterministic, versioned findings with evidence and remediation guidance
- a local CLI and a shared validation core
- a GitHub Check and web report, subject to the Phase 0 hosted-service go/no-go
- repository-pinned rule packs and gate thresholds

PROOF does not execute agents, generate MCP servers, call production APIs, or
replace authorization, confirmation, sandboxing, and other runtime controls.
A passing result means only that the configured static contract checks passed.

Separately from runtime enforcement, PROOF cannot verify delivery. Its policy
rules read `x-agent-policy`, a PROOF-defined OpenAPI extension. Surveyed
OpenAPI-to-MCP converters propagate `summary`, `description`, and parameter
descriptions, but do not surface third-party `x-*` extensions to a model by
default. Unless the toolchain that exposes an operation propagates the
extension, a passing policy rule records an auditable declaration for human
review and does not establish that an agent will see it.

## Project status

Work is organized by exit criteria rather than target dates. The current phase
focuses on the normalized result schema, initial rule definitions,
false-positive fixtures, fork pull request feasibility, and user discovery.
The generic validation authority is `openapi-spec-validator 0.9.0` behind an
isolated process contract, and the analysis core and CLI use a Python-first
workspace. See [ADR 0001](docs/adr/0001-python-runtime-and-repository-architecture.md)
and the [roadmap](ROADMAP.md) for the decisions and staged plan. The
[P0 agent contract rule pack](rulepacks/agent-contract/v1) defines the five
initial rules, deterministic risk signals, policy extension, and conformance
fixtures.

## Local scan

After installing the workspace packages, run `specargus proof scan` from a
repository containing `proof.yaml`:

```text
specargus proof scan --evaluation-time 2026-08-13T00:00:00Z
```

The command emits canonical result-v1 JSON by default. Use `--format console`
for a concise human-readable summary with detailed findings; `--color` affects
only that presentation. Both formats can be written with `--output`, which
replaces the destination atomically. It returns `0` for pass or
advisory, `1` for a blocked gate, `2` for configuration or input errors, and
`3` for internal failures. Run `specargus proof scan --help` for configuration,
selector, output, threshold, rule-pack identity, and invocation selection
options.

## Development workflow

- `develop` is the default integration branch and normal pull request target.
- `main` contains stable release history.
- Each change starts with an issue and a topic branch created from `develop`.
- Releases are proposed by pull request from `develop` to `main`.

Read [CONTRIBUTING.md](CONTRIBUTING.md) and the detailed
[branching and release policy](docs/branching-and-releases.md) before starting
work.

## Security

Do not open public issues for suspected vulnerabilities. Follow the private
reporting process in [SECURITY.md](SECURITY.md). The
[initial threat model](docs/security/initial-threat-model.md) defines the P0
security boundary, processing limits, hosted launch gates, and accepted
residual risks.

## License

Licensed under the [Apache License 2.0](LICENSE).
