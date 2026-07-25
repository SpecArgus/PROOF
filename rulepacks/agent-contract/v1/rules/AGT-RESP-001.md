# AGT-RESP-001: Missing Structured Error Response

## Identity

- Default severity: `medium`
- Finding cardinality: at most one per operation
- Applies to: state-changing or explicitly dangerous operations

## Intent

Give an agent a machine-readable failure payload instead of requiring it to
interpret free-form status text.

## Applicability

The rule applies when either condition is true:

1. the method is `post`, `put`, `patch`, or `delete`; or
2. deterministic risk classification assigns `destructive`,
   `financial_action`, `external_side_effect`, or `permission_change`.

`get`, `head`, `options`, and `trace` operations without one of those explicit
risks are excluded.

## Pass and finding behavior

An applicable operation passes when at least one effective response:

- has a status key in `400` through `599`, an uppercase wildcard `4XX` or
  `5XX`, or `default`;
- declares `application/json` or a media type ending in `+json`; and
- has a `schema` for that media type.

A response description without structured content does not pass. A valid
local `$ref` to a qualifying Response Object does pass.

If no qualifying response exists, the rule emits one finding.

## Indeterminate behavior

An unresolved Response Object, invalid response key, or invalid Media Type
Object is indeterminate and remains a generic validator concern.

## Finding contract

- Location: the Operation Object `responses` pointer.
- Message: `State-changing operation has no structured JSON error response.`
- Evidence: the method signal and any risk-classification evidence.
- Recommendation: `Declare a 4xx, 5xx, or default JSON error response with a reusable schema.`
- Risk categories: every category assigned by deterministic classification.

## Dialects and false positives

The rule uses the same response-key and media-type behavior for OpenAPI 3.0.x
and 3.1.x. Schema dialect differences do not change whether a schema is
declared. A read-only health operation is intentionally excluded even if it
has no error body.

See the `AGT-RESP-001` cases in
[`../fixtures/manifest.json`](../fixtures/manifest.json).
