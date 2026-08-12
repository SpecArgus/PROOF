# ADR 0003: Adopt a versioned Agent policy to MCP projection profile

- **Status:** Accepted
- **Date:** 2026-08-12
- **Owners:** PROOF maintainers (`@back1ash`)
- **Issue:** [#64](https://github.com/SpecArgus/PROOF/issues/64)

## Context

The two P0 blocking rules inspect `x-agent-policy`, a PROOF-defined OpenAPI
extension. A rule pass proves that the declared policy is present and well
formed for static review. It does not prove that an OpenAPI-to-MCP converter
places that policy in the tool definition seen by a model.

Issue #64 surveyed nine OpenAPI-to-MCP converters. The reviewed converters
propagate standard operation and parameter descriptions, but none was shown to
surface an arbitrary third-party `x-*` extension to a model by default.
Independent checks of representative current implementations confirmed the
relevant boundary:

- FastMCP `3.4.4` preserves operation `x-*` values in `HTTPRoute.extensions`
  and exposes an `mcp_component_fn` customization hook, but its default tool
  description is derived from the standard operation description or summary.
- Speakeasy exposes descriptions and standard MCP behavioral hints through its
  own `x-speakeasy-mcp` extension and documents OpenAPI Overlays as the way to
  add that extension without modifying the source document.
- MCP specification `2025-11-25` defines only the standard title, read-only,
  destructive, idempotent, and open-world hints. It requires clients to treat
  tool annotations as untrusted unless they come from a trusted server.

The production example recorded in #64 remains reproducible: the
`inkeep/agents` OpenAPI document declares an `x-authz` description and role for
project deletion, while its generated Speakeasy MCP tool includes the standard
operation description and method-derived annotations without the `x-authz`
declaration.

Three responses were considered:

- **C1:** require `confirmation.reason` when `confirmation.mode` is
  `required`;
- **C2:** publish a versioned mapping from `x-agent-policy` to MCP tool
  descriptions and annotations; and
- **C3:** document that a rule pass does not establish agent visibility.

C3 was completed by issue #65 and pull request #66. A decision remains needed
for C1 and C2 before the Phase 0 gate can interpret the policy-rule evidence.

## Decision

### Adopt C2 as a specification-only interoperability profile

Adopt [Agent policy to MCP projection profile v1](../contracts/agent-policy-mcp-projection-v1.md).
The profile is an opt-in, versioned specification for converter and gateway
operators. It:

- uses the MCP tool description as the primary model-visible channel;
- maps only semantically justified policy signals to current standard MCP
  annotations;
- names the destination or explicit non-mapping for every v1
  `x-agent-policy` field;
- treats annotations as untrusted hints rather than enforcement; and
- gives implementation routes for FastMCP and Speakeasy without adding either
  dependency to PROOF.

The profile is inside the current product scope because it describes how an
already-reviewed OpenAPI contract can retain meaning during mechanical
conversion. It is not an MCP server generator, a `tools/list` adapter, or a
second analysis engine. Executable adapters remain deferred by the roadmap.

The profile does not change scan behavior, rule findings, fingerprints, gates,
result schemas, or the `agent-contract` `0.1.0` identity. A consumer must opt in
and pin the profile version. PROOF does not claim that an unverified consumer
implemented the profile correctly.

### Defer C1

Do not require `confirmation.reason` for `mode: required` in the P0 rule pack.
C1 is deferred, not rejected permanently.

C1 does not solve the delivery failure by itself. Even with C2, the current
schema can require only a non-whitespace string, so a value such as `"x"`
passes without providing meaningful domain context. The projection profile can
already produce a deterministic statement from the risk and confirmation
enumerations when no reason is present. C1 would therefore introduce a
rule-pack version bump and migrate seven current corpus operations before the
project has evidence that the additional required slot improves reviewer or
agent outcomes.

C1 may be reconsidered only with recorded evidence, such as the maintainer
interviews in issue #9 or a projection-profile trial showing that missing
domain-specific reasons cause material ambiguity. Any later adoption remains
sequenced behind corpus-to-engine enforcement (#58) and the policy-finding
location fix (#59).

### Retain `x-agent-policy`

Keep the existing extension name. The profile maps from the stable PROOF
namespace to converter-specific surfaces. It does not rename the source
contract to `x-mcp` or a vendor namespace.

## Options considered

### Require a reason without publishing a projection profile

- **Summary:** Adopt C1 and decline C2.
- **Benefits:** Gives human reviewers a dedicated prose slot for every required
  confirmation declaration.
- **Costs and risks:** Does not make the policy visible to an agent, cannot
  assure prose quality, changes the rule-pack identity, and migrates corpus
  expectations.
- **Reason rejected:** It does not address the observed delivery failure and
  its incremental value is not yet evidenced.

### Publish the profile and require a reason immediately

- **Summary:** Adopt both C1 and C2.
- **Benefits:** Gives a projector a domain-specific reason when authors provide
  a meaningful value.
- **Costs and risks:** Couples a reversible documentation profile to an
  immediate blocking-rule compatibility change even though deterministic
  generic text is already possible.
- **Reason rejected:** C2 can be evaluated without making an unevidenced
  breaking rule change. C1 remains available after user evidence is collected.

### Publish the profile and defer the reason requirement

- **Summary:** Adopt C2 and defer C1.
- **Benefits:** Directly addresses the delivery gap, preserves current rule
  compatibility, and keeps the mapping replaceable as MCP evolves.
- **Costs and risks:** Generated descriptions may remain generic when authors
  omit a reason, and adoption is not automatic.
- **Reason accepted:** It is the smallest change that addresses the verified
  problem while keeping unresolved product assumptions visible.

### Document the limitation only

- **Summary:** Complete C3 and decline both C1 and C2.
- **Benefits:** No compatibility or maintenance cost.
- **Costs and risks:** Leaves mechanical OpenAPI-to-MCP conversion without a
  defined way to carry the policy that the blocking rules require.
- **Reason rejected:** Accurate disclaimers are necessary but do not provide an
  interoperability path.

## Consequences

### Positive

- The blocking rules remain honest about what they establish.
- Converter authors have one deterministic mapping target without PROOF
  shipping an executable adapter.
- Current rule-pack findings and fingerprints remain stable.
- The projection can be replaced by a later profile version if MCP standardizes
  richer trust, sensitivity, confirmation, or authorization metadata.

### Negative and trade-offs

- Adoption is voluntary and cannot be inferred from a PROOF scan result.
- Tool descriptions consume model context and can still be ignored or altered
  by clients and gateways.
- Current MCP annotations cannot represent financial action, confirmation
  policy, authorization roles, or data classification directly.
- C1's possible value remains unresolved until user or operational evidence is
  collected.

## Security and privacy

Operation descriptions, policy reasons, conditions, role names, and extension
values are untrusted input. A projector must validate the policy before use,
render free-form values as bounded quoted data, and avoid treating projected
text as executable instructions. Projection does not replace authentication,
authorization, confirmation, sandboxing, or no-egress controls.

MCP annotations remain hints. Clients must not make security-critical decisions
from annotations supplied by an untrusted server. Authentication wiring remains
owned by the converter and runtime; projecting `authorization.roles` into a
description does not enforce those roles.

## Reproducibility and compatibility

Profile v1 records the following reviewed references:

- [MCP tools specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/server/tools);
- [FastMCP 3.4.4 source at `9138d40e8813c2a7c6c7a015f3dffe0a120730e0`](https://github.com/PrefectHQ/fastmcp/tree/9138d40e8813c2a7c6c7a015f3dffe0a120730e0);
- [FastMCP OpenAPI integration](https://gofastmcp.com/integrations/openapi); and
- [Speakeasy MCP tool customization](https://www.speakeasy.com/docs/standalone-mcp/customize-tools).

Consumers pin the profile version independently from the rule-pack version.
Any change to field destinations, text templates, ordering, escaping, or hint
semantics requires a new profile version. A future MCP specification change
does not silently rewrite profile v1.

## Follow-up actions

- [ ] Exercise profile v1 against representative mechanical-conversion paths
      and record adoption evidence in issue #9.
- [ ] Revisit C1 only if issue #9 or profile trials show material ambiguity
      caused by missing domain-specific reasons.
- [ ] Complete corpus-to-engine enforcement in issue #58 before any future
      rule-pack migration.
- [ ] Complete the AGT-POL-002 location correction in issue #59.
- [ ] Re-evaluate the profile at the Phase 0 gate in issue #18 and whenever MCP
      accepts a relevant annotation SEP.

## Decision history

- 2026-08-12: Accepted C2 as a specification-only profile, deferred C1 pending
  evidence, and retained the existing `x-agent-policy` source contract.
