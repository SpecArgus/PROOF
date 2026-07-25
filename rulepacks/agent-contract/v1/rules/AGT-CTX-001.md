# AGT-CTX-001: Tool Selection Contract Incomplete

## Identity

- Default severity: `medium`
- Finding cardinality: at most one per operation
- Applies to: every resolved OpenAPI Operation Object

## Intent

Give an agent a stable tool identifier and enough concise context to
distinguish the operation from other available tools.

## Pass and finding behavior

An operation passes only when:

1. `operationId` is present and non-empty; and
2. at least one of `summary` or `description` is present and non-empty after
   trimming JSON whitespace.

Otherwise the rule emits one finding. Missing requirements are reported in
this order: `operationId`, `summary-or-description`.

Tags, path text, schema titles, and external documentation do not replace
these fields. This rule does not assess writing quality or uniqueness;
structural `operationId` constraints remain the generic validator's job.

## Indeterminate behavior

An invalid Operation Object or an operation hidden behind an unresolved
reference is indeterminate. The rule emits no speculative finding and relies
on the generic validator diagnostic.

## Finding contract

- Location: the Operation Object pointer.
- Message: `Operation is missing tool-selection metadata: {fields}.`
- Evidence: one `schema` item per missing requirement at the Operation Object.
- Recommendation: `Add a stable operationId and a concise summary or description that distinguishes this tool.`
- Risk categories: none.

Improved prose may change the message content in the OpenAPI input but does not
change a finding fingerprint once the operation passes and the finding
disappears.

## Dialects and false positives

Behavior is identical for OpenAPI 3.0.x and 3.1.x. An operation with a stable
`operationId` and only `summary` is intentionally compliant; requiring both
`summary` and `description` would add noise without improving the minimum tool
selection contract.

See the `AGT-CTX-001` cases in
[`../fixtures/manifest.json`](../fixtures/manifest.json).
