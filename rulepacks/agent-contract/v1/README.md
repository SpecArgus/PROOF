# Agent contract rule pack v1

This directory is the implementation-independent source of truth for the five
P0 PROOF rules tracked by
[Issue #10](https://github.com/SpecArgus/PROOF/issues/10).

The initial artifact identity is:

- rule-pack name: `agent-contract`;
- rule-pack version: `0.1.0`;
- normalized result schema: `1.0.0`; and
- supported inputs: OpenAPI 3.0.x and 3.1.x.

[`rules.json`](rules.json) is the machine-readable catalog. The Markdown files
in [`rules`](rules) define normative rule behavior. Files in [`fixtures`](fixtures)
are executable examples for the future rule engine and the larger benchmark
corpus in Issue #11.

The exact risk vocabulary is also published as
[`risk-classification.json`](risk-classification.json). The accompanying
[`risk-classification.md`](risk-classification.md) defines tokenization,
applicability, and evidence behavior.

## Evaluation boundary

The selected generic validator runs before these rules. It owns OpenAPI syntax,
structure, semantic validation, strict parsing, repository-confined local
reference resolution, and reference-policy diagnostics.

Rules inspect only declared OpenAPI data and successfully resolved,
repository-local references. They never:

- make network requests;
- execute repository content;
- infer runtime behavior from source code or traffic;
- use an LLM or probabilistic classifier; or
- claim that declared hints enforce authorization, confirmation, or isolation.

When invalid structure or an unresolved reference makes an operation unsafe to
inspect, the affected rule is indeterminate. It emits no speculative
`agent-rule` finding. The generic validator diagnostic remains visible and
prevents the invalid document from being treated as a successful scan.

## Common finding behavior

Every emitted finding:

- uses `source: agent-rule`;
- uses the stable ID and default severity from
  [`rules.json`](rules.json);
- identifies the defining repository-relative file and RFC 6901 pointer;
- includes at least one evidence item;
- includes every inferred risk category relevant to the finding;
- uses the fingerprint and canonical ordering contract in the
  [normalized result schema](../../../docs/contracts/result-schema-v1.md); and
- provides the rule's fixed actionable recommendation.

Unless a rule says otherwise, at most one finding is emitted for one operation
and one rule. Multiple missing requirements are aggregated in deterministic
field-name order.

P0 evaluates all discovered operations. Baselines, suppressions, severity
overrides, operation exclusions, and risk-removal overrides are outside this
version.

With the default `failOn: high` gate, the three `medium` documentation rules
are advisory and the two `high` policy rules are blocking.

## Agent policy extension

Policy metadata is declared on an OpenAPI Operation Object:

```yaml
x-agent-policy:
  risks:
    - destructive
  confirmation:
    mode: required
    reason: Human approval is required before deleting an account.
  authorization:
    roles:
      - administrator
  dataClassification: confidential
```

The machine-readable extension contract is
[`schemas/agent-policy.schema.json`](schemas/agent-policy.schema.json).
Root-level and Path Item-level declarations are not inherited in v1.

`risks` may add categories to deterministic inference. It cannot remove a
category inferred from the method, path, or `operationId`. The confirmation
mode `not-required` is a valid explicit policy only when it has a non-empty
reason. It records a static declaration; it does not bypass a runtime control.

### Delivery assumption

`x-agent-policy` reaches a human reviewer through PROOF findings. It does not
automatically reach a tool-calling model. Surveyed OpenAPI-to-MCP converters
propagate `summary`, `description`, and parameter descriptions, but do not
surface third-party `x-*` extensions by default. `AGT-POL-001` and
`AGT-POL-002` verify that a declaration exists and is well formed, not that it
is delivered to an agent. This is separate from the runtime boundary above: a
declaration can be absent from the agent's context even before any question of
runtime enforcement arises.

The optional, versioned
[Agent policy to MCP projection profile v1](../../../docs/contracts/agent-policy-mcp-projection-v1.md)
defines how converter operators can carry the policy into MCP descriptions and
the subset of standard annotations supported by exact policy evidence. Profile
adoption is separate from a rule-pack pass and does not change this rule pack's
identity.

## Resolved P0 choices

The following choices remove ambiguities from the product requirements:

| Question | P0 decision |
| --- | --- |
| `AGT-CTX-001` severity | `medium` |
| Tool-selection minimum | `operationId` and at least one of `summary` or `description` |
| Parameter scope | OpenAPI Parameter Objects only; request-body properties are deferred |
| Structured error | A `4xx`, `5xx`, or `default` response with a JSON or `+json` media type and a schema |
| Confirmation exception | `not-required` is accepted only with a reason |
| Classifier text | Method, path tokens, `operationId` tokens, and explicit extension only |
| Risk overrides | Explicit categories can add but never suppress inferred categories |
| Policy inheritance | Operation Object only |

## Fixture terminology

Each rule has both OpenAPI 3.0 and 3.1 fixtures. Cases use these labels:

- `positive`: a representative violation that must emit the rule;
- `negative`: a representative compliant operation;
- `boundary`: behavior at an exact scope or validity boundary; and
- `false-positive`: plausible but intentionally non-matching input that must
  remain quiet.

The manifest stores the complete five-rule outcome as an unordered set of
conformance labels, not only the finding for the named case rule. A label
contains the stable identity, severity, location, risks, and evidence signals;
the normative rule document supplies its message and remediation template.
Fixtures satisfy non-target rules so the same cases can become full-engine
golden tests. Fixture order must not define output order.
