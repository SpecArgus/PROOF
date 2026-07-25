# AGT-POL-002: Sensitive or Privileged API Without Security Metadata

## Identity

- Default severity: `high`
- Finding cardinality: at most one per operation
- Applies to: sensitive-data and permission-changing operations

## Intent

Require an agent-facing contract to declare both standard OpenAPI
authentication requirements and the product metadata needed to interpret
sensitive or privileged use.

## Applicability

The rule applies when deterministic classification assigns
`sensitive_data`, `permission_change`, or both.

## Pass and finding behavior

Every applicable operation requires effective OpenAPI `security`. Operation
security overrides root security. The effective array must contain at least
one non-empty Security Requirement Object; `security: []` and an anonymous
`{}` alternative do not pass.

Additional requirements depend on risk:

- `sensitive_data` requires operation-level
  `x-agent-policy.dataClassification` equal to `confidential` or
  `restricted`.
- `permission_change` requires at least one non-empty
  `x-agent-policy.authorization.roles` entry.

An operation with both risks must satisfy both requirements. Missing
requirements are aggregated in this order: `security`,
`dataClassification`, `authorization.roles`.

## Indeterminate behavior

An invalid Security Requirement Object, unresolved security scheme, or invalid
operation structure is indeterminate and owned by the generic validator. A
well-formed operation with absent or inadequate metadata is determinate and
emits this rule.

## Finding contract

- Location: the Operation Object, or the closest present but inadequate
  security or policy field.
- Message: `Operation classified as {risks} is missing security metadata: {requirements}.`
- Evidence: all signals used to assign `sensitive_data` or
  `permission_change`.
- Recommendation: `Declare effective OpenAPI security and the required x-agent-policy classification or roles.`
- Risk categories: all deterministically assigned categories.

These fields are untrusted static hints. Passing this rule does not prove that
the API enforces authentication, authorization, least privilege, or data
handling controls.

## Dialects and false positives

Behavior is identical for OpenAPI 3.0.x and 3.1.x. `GET /roles` is not a
permission change because keyword-based permission classification requires a
state-changing method. It therefore remains outside this rule unless an
explicit risk is declared.

See the `AGT-POL-002` cases in
[`../fixtures/manifest.json`](../fixtures/manifest.json).
