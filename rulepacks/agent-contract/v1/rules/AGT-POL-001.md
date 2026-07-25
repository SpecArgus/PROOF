# AGT-POL-001: Dangerous API Without Confirmation Policy

## Identity

- Default severity: `high`
- Finding cardinality: at most one per operation
- Applies to: operations with a confirmation-relevant risk

## Intent

Require dangerous operations to declare how an agent should treat
confirmation before invocation.

## Applicability

The rule applies when deterministic classification assigns one or more of:

- `destructive`;
- `financial_action`;
- `external_side_effect`; or
- `permission_change`.

`sensitive_data` alone does not make confirmation mandatory.

## Pass and finding behavior

An operation passes when its operation-level
`x-agent-policy.confirmation` satisfies the v1 extension schema.

- `required` is an explicit confirmation requirement.
- `conditional` requires a non-empty `condition`.
- `not-required` requires a non-empty `reason`.

If confirmation is absent or invalid, the rule emits one finding. A
root-level or Path Item-level extension is not inherited.

An explicit `not-required` declaration records an accountable static policy;
it does not disable runtime confirmation or prove that confirmation is
unnecessary.

## Indeterminate behavior

Invalid operation structure or an unresolved operation is indeterminate. A
present but malformed `x-agent-policy` is determinate and produces this rule
finding because generic OpenAPI validation does not define its product
semantics.

## Finding contract

- Location: `x-agent-policy.confirmation` when present, otherwise the
  Operation Object.
- Message: `Operation classified as {risks} has no valid confirmation policy.`
- Evidence: all method, path, keyword, and extension signals used to classify
  the operation.
- Recommendation: `Declare x-agent-policy.confirmation with required, conditional, or a reasoned not-required mode.`
- Risk categories: all deterministically assigned categories.

## Dialects and false positives

Behavior is identical for OpenAPI 3.0.x and 3.1.x. A generic `POST /search`
does not match from its method alone and therefore does not require a
confirmation policy. Teams must add an explicit risk when a neutral operation
name hides a domain side effect.

See the `AGT-POL-001` cases in
[`../fixtures/manifest.json`](../fixtures/manifest.json).
