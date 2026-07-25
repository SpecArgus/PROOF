# AGT-PARAM-001: Parameter Lacks Domain-Specific Meaning

## Identity

- Default severity: `medium`
- Finding cardinality: one per non-compliant effective parameter
- Applies to: effective Path Item and Operation Parameter Objects

## Intent

Ensure an agent has declared domain meaning for values that must be placed in
the path, query, header, or cookie portion of a request.

## Pass and finding behavior

After local `$ref` resolution and standard path/operation parameter override
rules, a parameter passes when its `description` is present and non-empty
after trimming JSON whitespace.

The following case-insensitive header names are excluded because OpenAPI
tooling ignores them as Header Parameters:

- `Accept`;
- `Content-Type`; and
- `Authorization`.

All other parameters without a description emit one finding each. A schema
title, example, parameter name, or primitive type does not replace a
description.

Request-body schema properties are outside P0 scope. Their recursive
composition and dialect-specific annotation behavior require a separate rule
decision.

## Indeterminate behavior

An invalid parameter, an unresolved parameter reference, or an invalid
path/operation override is indeterminate and owned by the generic validator.

## Finding contract

- Location: the defining Parameter Object pointer.
- Message: `Parameter '{name}' in '{in}' is missing a non-empty description.`
- Evidence: one `schema` item pointing to the parameter.
- Recommendation: `Describe the parameter's domain meaning, accepted values, units, and important constraints.`
- Risk categories: none.

## Dialects and false positives

Behavior is identical for OpenAPI 3.0.x and 3.1.x. The protocol header
exclusions above are intentional false-positive controls. Other widely used
headers, including tracing or idempotency headers, still require domain
meaning because their semantics are API-specific.

See the `AGT-PARAM-001` cases in
[`../fixtures/manifest.json`](../fixtures/manifest.json).
