# Agent policy to MCP projection profile v1

## Identity and status

- Profile name: `agent-policy-mcp-projection`
- Profile version: `1.0.0`
- Source contract: `agent-contract` rule pack `0.1.0`, `x-agent-policy` v1
- MCP reference: specification `2025-11-25`
- Decision: [ADR 0003](../adr/0003-adopt-agent-policy-mcp-projection-profile.md)

This opt-in profile defines a deterministic mapping from a valid operation-level
`x-agent-policy` object to model-visible MCP tool metadata. It is an
interoperability specification, not an executable PROOF adapter. Conformance to
this profile is separate from passing a PROOF rule.

## Scope

A conforming projector consumes one OpenAPI Operation Object after generic
OpenAPI validation and `x-agent-policy` schema validation. It produces:

1. a policy block appended to the MCP tool description; and
2. the subset of standard MCP `ToolAnnotations` justified by explicit v1
   policy values.

The projector does not infer new policy, execute repository content, contact a
network service, enforce runtime controls, or alter PROOF findings. Standard
OpenAPI authentication wiring remains the converter's responsibility.

## Preconditions and visible failure

- The Operation Object must be structurally valid.
- When `x-agent-policy` is present, it must satisfy
  `rulepacks/agent-contract/v1/schemas/agent-policy.schema.json`.
- A malformed policy must produce a visible projector diagnostic. It must not
  be partially projected or treated as a safe policy.
- A missing `x-agent-policy` produces no policy block and no policy-derived
  annotations.
- Nested extension fields matching `x-*` are preserved by the source schema but
  have no v1 destination. They are ignored with an informational diagnostic.

## Description projection

### Base description

Use the trimmed, non-empty OpenAPI operation `description` as the base. If it is
absent, use the trimmed, non-empty operation `summary`. If both are absent, the
base is empty. This choice matches the most conservative common behavior among
reviewed converters: load-bearing policy text must not depend on `summary`
surviving when a `description` is present.

### Policy block

Append one blank line and this heading when at least one standard policy field
is present:

```text
Agent policy (SpecArgus PROOF projection 1.0):
```

Emit the following lines in this exact order, omitting a line when its source
field is absent:

```text
- Declared risks: destructive, external_side_effect.
- Confirmation: required; reason="Human approval is required".
- Authorization roles: ["administrator"].
- Data classification: confidential.
```

Rendering rules are deterministic:

- sort `risks` and `authorization.roles` by Unicode scalar value;
- render `condition`, `reason`, and each role as an RFC 8785 JSON string so
  quotes, newlines, and control characters cannot break field boundaries;
- render enum values as their exact lowercase schema values;
- for `confirmation`, emit `mode` first, then `condition`, then `reason`;
- preserve the base description text except for trimming its outer whitespace;
  and
- end the complete description without trailing whitespace.

The policy block is declarative data. A projector must not add instructions
that tell a model to bypass client confirmation, runtime authorization, or
other controls.

## Field destinations

| `x-agent-policy` field | MCP description | Standard MCP annotation |
| --- | --- | --- |
| `risks` | Always emit the complete declared list. | Apply only the exact mappings below. |
| `confirmation.mode` | Emit the exact mode. | None. MCP has no confirmation-policy annotation. |
| `confirmation.condition` | Emit as a quoted value when present. | None. |
| `confirmation.reason` | Emit as a quoted value when present. | None. |
| `authorization.roles` | Emit the sorted quoted role list. | None. Authentication and authorization remain runtime controls. |
| `dataClassification` | Emit the exact classification. | None. MCP `2025-11-25` has no data-classification annotation. |
| nested `x-*` extension | Do not emit in profile v1. | None unless a separately versioned profile defines it. |

### Annotation mapping

Set only positive hints supported by explicit policy evidence:

| Declared risk | Annotation output |
| --- | --- |
| `destructive` | `readOnlyHint: false`, `destructiveHint: true` |
| `external_side_effect` | `readOnlyHint: false`, `openWorldHint: true` |
| `financial_action` | `readOnlyHint: false` |
| `permission_change` | `readOnlyHint: false` |
| `sensitive_data` | No current standard annotation; description only. |

Do not emit `destructiveHint: false`, `openWorldHint: false`, or
`idempotentHint` from the absence of a policy risk. Absence is not evidence for
the negative property. When a converter already has annotations from stronger
trusted evidence, it may merge them only if the result does not contradict a
positive profile hint. A contradiction must be visible and must not be resolved
by silently weakening the profile output.

These annotations are hints. The MCP specification requires clients to treat
them as untrusted unless they come from a trusted server.

## Adoption path: FastMCP

FastMCP `3.4.4` preserves operation `x-*` values in
`HTTPRoute.extensions` and calls `mcp_component_fn` after generating an
`OpenAPITool`. A projector can therefore apply this profile without changing
the source OpenAPI document:

```python
from mcp.types import ToolAnnotations

from fastmcp.server.providers.openapi import HTTPRoute, OpenAPITool


def project_policy_v1(policy: dict) -> tuple[str, dict]:
    """Validate policy and return the profile block and camelCase hints."""
    # Implement exactly the ordering, quoting, and mapping rules above.
    ...


def apply_proof_projection(route: HTTPRoute, component: object) -> None:
    if not isinstance(component, OpenAPITool):
        return

    policy = route.extensions.get("x-agent-policy")
    if policy is None:
        return

    block, hints = project_policy_v1(policy)
    base = (component.description or "").strip()
    component.description = f"{base}\n\n{block}" if base else block
    if hints:
        component.annotations = ToolAnnotations(**hints)
```

The snippet is an integration route, not the normative projector
implementation. Consumers must pin and test their FastMCP release. FastMCP API
names can change across major versions; the profile's output semantics do not.

## Adoption path: Speakeasy

Speakeasy reads its own `x-speakeasy-mcp` extension. Generate an OpenAPI Overlay
from the validated profile output and apply it before MCP generation. For one
operation, the generated overlay has this shape:

```yaml
overlay: 1.0.0
info:
  title: Apply SpecArgus PROOF projection profile 1.0
  version: 1.0.0
actions:
  - target: $.paths["/accounts/{accountId}"].delete
    update:
      x-speakeasy-mcp:
        description: |-
          Delete an account permanently.

          Agent policy (SpecArgus PROOF projection 1.0):
          - Declared risks: destructive.
          - Confirmation: required; reason="Human approval is required".
          - Authorization roles: ["administrator"].
          - Data classification: confidential.
        readOnlyHint: false
        destructiveHint: true
```

The overlay is generated output. It must be derived from the source operation
and policy rather than maintained as an independent policy authority.

## Security boundary

Projection makes policy values model-visible; it does not make them trusted.
The source specification and every free-form string remain untrusted data.
Conforming implementations must:

- validate before projecting;
- bound input and output sizes;
- render free-form values through the quoted representation above rather than
  raw concatenation;
- keep repository content away from credentials and execution; and
- escape the final description again for its transport and presentation
  context.

No description or annotation proves authentication, authorization,
confirmation, idempotency, data handling, or sandbox enforcement. Clients must
keep security-critical decisions in trusted runtime controls.

## Versioning and conformance

A conforming implementation identifies profile `1.0.0` in its build or
generated artifact metadata and tests byte-equivalent output for pinned input.
Changing any field destination, fixed text, ordering, quoting, or annotation
rule requires a new profile version.

Profile conformance does not change the `agent-contract` rule-pack identity and
must not be reported as a PROOF scan pass. PROOF may add executable conformance
fixtures later without adding an OpenAPI-to-MCP adapter to the product.

## Reviewed references

- [MCP tools specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [FastMCP 3.4.4 source](https://github.com/PrefectHQ/fastmcp/tree/9138d40e8813c2a7c6c7a015f3dffe0a120730e0)
- [FastMCP OpenAPI integration](https://gofastmcp.com/integrations/openapi)
- [Speakeasy tool customization and Overlays](https://www.speakeasy.com/docs/standalone-mcp/customize-tools)
