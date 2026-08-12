# Agent policy to MCP projection profile v1

## Identity and status

- Profile name: `agent-policy-mcp-projection`
- Profile version: `1.0.0`
- Source contract: `agent-contract` rule pack `0.1.0`, `x-agent-policy` v1
- MCP baseline: specification `2025-11-25`
- MCP compatibility: verified through specification `2026-07-28`
- Decision: [ADR 0003](../adr/0003-adopt-agent-policy-mcp-projection-profile.md)

This opt-in profile defines deterministic MCP metadata intended for possible
model consumption from a valid operation-level `x-agent-policy` object. It
does not prove that a client places a tool description in a model prompt, keeps
it untruncated, or presents it in a particular order. Those properties require
client-specific integration evidence.

The profile is an interoperability specification, not an executable PROOF
adapter. Profile conformance is separate from passing a PROOF rule.

## Scope

A conforming projector consumes one OpenAPI Operation Object after generic
OpenAPI validation and `x-agent-policy` schema validation. It produces:

1. a deterministic policy block appended to the MCP tool description; and
2. a small set of explicit positive MCP `ToolAnnotations` hints.

The description is the primary carrier. Annotation mapping is deliberately
lossy because current MCP annotations cannot express confirmation policy,
financial action, authorization roles, data classification, or an unknown
value distinct from their protocol defaults.

The projector does not infer policy, execute repository content, contact a
network service, enforce runtime controls, or alter PROOF findings. Standard
OpenAPI authentication wiring remains the converter's responsibility.

## Preconditions, limits, and visible failure

- The Operation Object must be structurally valid.
- When `x-agent-policy` is present, it must satisfy
  `rulepacks/agent-contract/v1/schemas/agent-policy.schema.json`.
- A missing policy leaves the description and annotations unchanged.
- A malformed policy produces `projection.invalid-policy`.
- An annotation conflict produces `projection.annotation-conflict`.
- Exceeding any limit below produces `projection.size-limit`.
- A failure leaves the complete destination tool or overlay unchanged. Partial
  descriptions, partial annotations, and truncation are forbidden.

Limits are inclusive and measured after schema validation:

| Value | Profile v1 limit |
| --- | ---: |
| RFC 8785 serialization of `x-agent-policy` | 32,768 UTF-8 bytes |
| Selected base `description` or `summary` | 16,384 UTF-8 bytes |
| Each `condition`, `reason`, or role | 1,024 UTF-8 bytes |
| Authorization roles | 64 |
| Ignored `x-*` extension pointers | 256 |
| Complete projected tool description | 32,768 UTF-8 bytes |

Every schema-permitted extension at the policy top level, under
`confirmation`, or under `authorization` has no v1 destination. Emit one
`projection.extension-ignored` informational operator diagnostic per ignored
field. Sort diagnostics by the field's RFC 6901 pointer and never include the
extension value or these diagnostics in MCP metadata.

## Description projection

### Exact text algorithm

`trim_ascii(value)` removes only leading and trailing U+0009, U+000A, U+000D,
and U+0020. It does not apply Unicode normalization. Normalize CRLF and CR
inside the selected base to LF.

1. Use a non-empty `trim_ascii(operation.description)` as the base.
2. Otherwise use a non-empty `trim_ascii(operation.summary)`.
3. Otherwise use the empty string.
4. Construct policy lines in the order below.
5. When at least one line exists, prefix them with the exact heading:

   `Agent policy (SpecArgus PROOF projection 1.0.0):`

6. Join the heading and lines with one LF. If the base is non-empty, join the
   base and block with exactly two LF characters.
7. Emit no final LF or trailing whitespace.

The following pseudocode is normative. `JCS(value)` means RFC 8785
serialization and `join(items, separator)` uses the literal separator shown.

```text
lines = []
if risks is present:
    values = sort_by_unicode_scalar(risks)
    lines.append("- Declared risks: " + join(values, ", ") + ".")
if confirmation is present:
    line = "- Confirmation: " + confirmation.mode
    if confirmation.condition is present:
        line += "; condition=" + JCS(confirmation.condition)
    if confirmation.reason is present:
        line += "; reason=" + JCS(confirmation.reason)
    lines.append(line + ".")
if authorization is present:
    lines.append(
        "- Authorization roles: "
        + JCS(sort_by_unicode_scalar(authorization.roles))
        + "."
    )
if dataClassification is present:
    lines.append("- Data classification: " + dataClassification + ".")

if lines is empty:
    projected_description = base
else:
    block = "Agent policy (SpecArgus PROOF projection 1.0.0):\n" + join(lines, "\n")
    projected_description = base + "\n\n" + block if base is non-empty else block
```

A valid policy containing only schema-permitted `x-*` extensions therefore
produces no policy block, preserves the selected base, and emits only sorted
`projection.extension-ignored` operator diagnostics.

Policy lines use these exact forms and order:

```text
- Declared risks: destructive, external_side_effect.
- Confirmation: required; condition="Only above the limit"; reason="Human approval is required".
- Authorization roles: ["administrator","operator"].
- Data classification: confidential.
```

Rendering rules:

- sort risks and roles by Unicode scalar value;
- join risks with comma plus one U+0020;
- serialize the complete sorted roles array with RFC 8785;
- serialize `condition` and `reason` individually as RFC 8785 JSON strings;
- emit confirmation mode first, then condition, then reason;
- render enum values as their exact lowercase schema values; and
- preserve all selected base characters except the trim and line-ending
  transformations stated above.

RFC 8785 quoting preserves syntactic field boundaries. It does not remove the
semantic prompt-injection risk of untrusted prose.

## Field destinations

| `x-agent-policy` field | MCP description | Standard MCP annotation |
| --- | --- | --- |
| `risks` | Emit the complete sorted list. | Apply only the positive writes below. |
| `confirmation.mode` | Emit the exact mode. | None. |
| `confirmation.condition` | Emit as a quoted value. | None. |
| `confirmation.reason` | Emit as a quoted value. | None. |
| `authorization.roles` | Emit the sorted JSON array. | None; roles remain runtime policy. |
| `dataClassification` | Emit the exact classification. | None. |
| `x-*` at any schema-permitted level | Do not emit; issue an operator diagnostic. | None. |

### Annotation writes and MCP defaults

The profile writes only fields justified by positive declarations:

| Declared risk | Explicit profile writes |
| --- | --- |
| `destructive` | `readOnlyHint: false`, `destructiveHint: true` |
| `external_side_effect` | `readOnlyHint: false`, `openWorldHint: true` |
| `financial_action` | `readOnlyHint: false` |
| `permission_change` | `readOnlyHint: false` |
| `sensitive_data` | None; description only |

Omission is not an unknown value in MCP. Both reviewed MCP versions define
these effective defaults:

| Field | Default when absent |
| --- | --- |
| `readOnlyHint` | `false` |
| `destructiveHint` | `true` |
| `idempotentHint` | `false` |
| `openWorldHint` | `true` |

Consequently, the annotation output is a conservative, lossy secondary signal,
not a one-to-one policy projection. Consumers must use the description for the
complete declaration and must not interpret an omitted field as unknown.
Annotations remain untrusted hints unless they come from a trusted server.

### Existing annotation merge

Merge by field, never by replacing the annotation object:

1. Copy every existing explicit field, including `title`, `idempotentHint`,
   and fields not written by this profile.
2. For each explicit profile write, add it when the field is absent.
3. Preserve it when the existing value is identical.
4. If the existing explicit value differs, fail the whole projection with
   `projection.annotation-conflict`.

Do not resolve a conflict by weakening either input. The same rules apply when
merging into a pre-existing `x-speakeasy-mcp` object; unrelated keys such as
name, title, or scopes are preserved.

## Adoption path: FastMCP

FastMCP `3.4.4` preserves operation `x-*` values in
`HTTPRoute.extensions` and calls `mcp_component_fn` after generating an
`OpenAPITool`. An integration can apply the profile without modifying the
source OpenAPI document:

```python
from fastmcp.server.providers.openapi import HTTPRoute, OpenAPITool


def apply_proof_projection(route: HTTPRoute, component: object) -> None:
    if not isinstance(component, OpenAPITool):
        return

    policy = route.extensions.get("x-agent-policy")
    if policy is None:
        return

    # All helpers implement this profile. They raise before mutation.
    description, writes, diagnostics = project_operation_v1(
        operation_description=route.description,
        operation_summary=route.summary,
        policy=policy,
    )
    annotations = merge_annotations_v1(component.annotations, writes)

    component.description = description
    component.annotations = annotations
    emit_operator_diagnostics(diagnostics)
```

This is an integration route, not a normative implementation. In particular,
`merge_annotations_v1` must preserve existing fields and fail on conflict as
specified above. The generated `component.description` is deliberately not a
profile input: only the source Operation `description`, with `summary` as the
defined fallback, can produce byte-equivalent output across converters.
Consumers pin and test their FastMCP release; if its `HTTPRoute` API does not
expose both raw fields, they must retain them while parsing the source Operation
instead of substituting the already-combined destination description.

## Adoption path: Speakeasy

Generate an OpenAPI Overlay from validated profile output and apply it before
MCP generation. Merge into, rather than replace, any existing
`x-speakeasy-mcp` object:

```yaml
overlay: 1.0.0
info:
  title: Apply SpecArgus PROOF projection profile 1.0.0
  version: 1.0.0
actions:
  - target: $.paths["/accounts/{accountId}"].delete
    update:
      x-speakeasy-mcp:
        description: |-
          Delete an account permanently.

          Agent policy (SpecArgus PROOF projection 1.0.0):
          - Declared risks: destructive.
          - Confirmation: required; reason="Human approval is required".
          - Authorization roles: ["administrator"].
          - Data classification: confidential.
        readOnlyHint: false
        destructiveHint: true
```

The overlay is generated output, not an independent policy authority. An
existing conflicting hint fails generation with
`projection.annotation-conflict`; unrelated extension keys are retained.
The generated profile description is derived only from the source Operation
`description` or `summary` rule above. A pre-existing
`x-speakeasy-mcp.description` is destination metadata, not a base-description
input: replace it only when it is absent or byte-identical to the generated
description; otherwise fail with `projection.annotation-conflict` rather than
silently choosing converter-specific text.

## Security boundary

Projection makes policy available in MCP metadata eligible for model
consumption; it does not make that metadata trusted or prove actual prompt
delivery. The source specification and every free-form string remain untrusted
data. Conforming implementations must validate and bound input before
projection, keep repository content away from credentials and execution, and
escape the final description again for its transport and presentation context.

JSON quoting is syntactic isolation, not semantic sanitization. A description
or annotation never proves authentication, authorization, confirmation,
idempotency, data handling, or sandbox enforcement. Clients keep
security-critical decisions in trusted runtime controls.

MCP `2026-07-28` adds runtime elicitation through multi round-trip requests.
That can implement confirmation during a call, but it is not static tool
metadata and does not replace this profile or enforce projected declarations.

## Versioning and conformance

A conforming implementation identifies profile `1.0.0` in build or generated
artifact metadata. It tests byte-equivalent description text, explicit
annotation fields, and stable diagnostics for pinned input.

At minimum, fixtures cover missing policy; every risk alone and together; all
confirmation modes and condition/reason combinations; zero, one, and multiple
roles; every data classification; extensions at all three permitted levels;
Unicode and control characters; every limit at and one unit above its boundary;
existing non-conflicting annotations; and every explicit annotation conflict.
Client-specific tests separately capture `tools/list` and the actual prompt or
tool catalog to establish delivery, ordering, and truncation behavior.

Changing a destination, fixed text, ordering, quoting, limit, diagnostic code,
or annotation merge rule requires a new profile version. Profile conformance
does not change the `agent-contract` identity and must not be reported as a
PROOF scan pass.

## Reviewed references

- [MCP tools specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [MCP tools specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [MCP schema reference 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/schema)
- [MCP 2026-07-28 release](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [FastMCP 3.4.4 source](https://github.com/PrefectHQ/fastmcp/tree/9138d40e8813c2a7c6c7a015f3dffe0a120730e0)
- [FastMCP OpenAPI integration](https://gofastmcp.com/integrations/openapi)
- [Speakeasy tool customization and Overlays](https://www.speakeasy.com/docs/standalone-mcp/customize-tools)
