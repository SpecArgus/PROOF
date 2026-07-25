# PROOF

**Policy Review of OpenAPI Operations for Function-calling**

PROOF is an early-stage open source project exploring a deterministic quality
gate for OpenAPI operations that will be exposed as AI agent or MCP tools.

> [!IMPORTANT]
> PROOF is currently in pre-alpha discovery. There is no installable scanner
> yet. The Python-first runtime and generic OpenAPI validator are selected,
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

## Project status

Work is organized by exit criteria rather than target dates. The current phase
focuses on the normalized result schema, initial rule definitions,
false-positive fixtures, fork pull request feasibility, and user discovery.
The generic validation authority is `openapi-spec-validator 0.9.0` behind an
isolated process contract, and the analysis core and CLI use a Python-first
workspace. See [ADR 0001](docs/adr/0001-python-runtime-and-repository-architecture.md)
and the [roadmap](ROADMAP.md) for the decisions and staged plan.

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
reporting process in [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
