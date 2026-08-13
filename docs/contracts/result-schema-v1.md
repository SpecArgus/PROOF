# Normalized result schema v1

Issue [#4](https://github.com/SpecArgus/PROOF/issues/4) defines one
language-neutral result contract for the CLI, hosted scan worker, persistence,
and report consumers. The machine-readable source is in
[`packages/contracts`](../../packages/contracts).

## Contract boundary

The normalized result contains deterministic analysis data only. Hosted and
interface-specific metadata belongs in a separate envelope and must not alter
the core result.

The result contract excludes:

- absolute filesystem paths and temporary-directory names;
- hostnames, process IDs, environment variables, and credentials;
- queue, webhook, Check Run, report, request, or database identifiers;
- elapsed time, scheduling time, and retry counters; and
- interface-specific links, Markdown, HTML, console formatting, and
  annotations.

`evaluationTime` is not ambient clock data. It is an explicit analysis input.
The first hosted run fixes it at durable webhook acceptance time, and an exact
rerequest reuses it. A new evaluation uses a new value and therefore has a
different result digest. Producers use the exact UTC whole-second form
`YYYY-MM-DDTHH:MM:SSZ`; offsets and fractional seconds are not canonical v1
inputs.

Optional properties are omitted when they are unknown. `null` is not a
substitute for omission unless a future schema explicitly permits it.

## Terminal states

`run.status` records whether analysis completed:

| Run status | Meaning | Required gate outcome | CLI exit |
| --- | --- | --- | --- |
| `completed` | Validation and configured rules reached a result | `pass`, `advisory`, or `blocked` | `0` for pass/advisory, `1` for blocked |
| `input-error` | Input or configuration prevented evaluation | `not-evaluated` | `2` |
| `internal-error` | Timeout, dependency, protocol, sandbox, or internal failure prevented evaluation | `not-evaluated` | `3` |

A structural or semantic OpenAPI violation is a normalized finding and a
completed blocked run, not an input error. A timeout, malformed worker
response, dependency failure, or sandbox failure is never reported as a
successful run. Exceeding the bounded validator-observation limit is an
`input-error` with a not-evaluated gate and retained `truncatedFindings` count;
partial diagnostics are not used to make a gate claim.

Gate outcomes mean:

- `pass`: the run has no findings;
- `advisory`: findings exist, but none meet the configured blocking threshold,
  including when `failOn` is `none`;
- `blocked`: at least one finding meets the configured threshold; and
- `not-evaluated`: the run did not complete, so no gate claim is made.

`causingFindingFingerprints` is empty for pass and not-evaluated results. It is
non-empty for advisory and blocked results and identifies the findings that
explain the outcome.

## Finding identity

Every finding contains a stable `sha256:` fingerprint. The fingerprint is the
SHA-256 digest of the RFC 8785 JSON Canonicalization Scheme serialization of
this projection:

```json
{
  "fingerprintVersion": 1,
  "source": "agent-rule",
  "ruleId": "AGT-POL-001",
  "location": {
    "path": "api/openapi.yaml",
    "pointer": "/paths/~1users~1{id}/delete"
  },
  "operation": {
    "method": "delete",
    "path": "/users/{id}"
  },
  "riskCategories": [
    "destructive"
  ],
  "evidence": [
    {
      "kind": "method",
      "pointer": "/paths/~1users~1{id}/delete",
      "value": "delete"
    }
  ]
}
```

The projection rules are:

1. Include `source`, `ruleId`, repository-relative path, and JSON Pointer.
2. Include operation method and path when an operation is known. Do not include
   `operationId`.
3. Sort risk categories by Unicode code point and omit the property when the
   finding has none.
4. For each evidence item, include `kind`, and include `pointer` when present.
   The identity projection always includes a `value` property: use the evidence
   `value` when present, otherwise use the evidence `description` string as that
   property's value.
5. Sort projected evidence items by their RFC 8785 byte representation.
6. Omit absent optional properties; never synthesize `null`.

Severity, message wording, remediation wording, line, and column are excluded
so formatting, severity policy, and improved source mapping do not change the
identity of the same violation. Identity-bearing rule behavior changes require
a rule ID or fingerprint-version change.

## Canonical ordering

Before serialization, producers order arrays as follows:

1. Findings by severity rank `error`, `high`, `medium`, `low`, `info`.
2. Then by `source`, `ruleId`, `location.path`, `location.pointer`, and
   `fingerprint`, each in Unicode code point order.
3. Terminal errors by `kind`, `code`, optional location path, optional pointer,
   and message.
4. Risk categories, evidence projections, and gate fingerprint lists in
   lexicographic canonical-byte order.

Reporters may present a different view, but they must not mutate or persist
that presentation order as the normalized result.

## Result digest

`resultDigest` is `sha256:` followed by the SHA-256 digest of the RFC 8785
serialization of the complete normalized run after:

1. canonical array ordering has been applied; and
2. the `resultDigest` property itself has been removed.

All `x-` extension fields are included in the result digest. They are excluded
from finding fingerprints unless the extension specification explicitly
defines an identity-bearing fingerprint-version change.

With identical input, configuration, core, validator, rule-pack, runtime, and
evaluation-time identities, repeated execution must produce byte-identical
canonical results and the same digest.

## Paths and locations

All paths use repository-relative forward-slash form. Absolute POSIX paths,
Windows drive paths, backslashes, and any `..` segment are invalid. A location
always contains an RFC 6901 JSON Pointer. The empty string identifies the
document root.

Line and column are one-based and optional. They identify the defining file,
not necessarily the entrypoint. They are presentation aids and are not part of
finding identity.

## Provenance

The run requires identities for:

- core;
- generic OpenAPI validator;
- built-in rule pack;
- language runtime;
- effective configuration; and
- transitive input manifest.

Artifacts require name, version, and content digest. A valid configuration uses
the digest of its effective, default-materialized content. If configuration
resolution fails, the configuration identity is the versioned, sanitized
attempt identity defined by the configuration contract.

A completed run or a failure after closure construction uses the transitive
input-manifest digest. If evaluation cannot construct a manifest, the input
identity is the digest of a versioned attempt projection containing only its
state, sorted repository-relative configuration selectors, and any
already-known bounded file identities. A configuration failure uses an
explicit `not-attempted`
input projection. Host paths, raw bytes, error messages, references, download
URLs, credentials, and mutable labels are not provenance identities.

## Extensions

Objects reject unknown standard fields. An extension name must match
`x-[a-z0-9][a-z0-9._-]*`. Extensions may carry any JSON value, but they:

- cannot replace or weaken required fields;
- cannot redefine standard field semantics;
- must be deterministic when emitted by the core; and
- must be ignored or preserved by consumers that do not understand them.

Experimental data uses extensions until a future contract version adopts a
standard field.

## Versioning and compatibility

The initial contract version is exactly `1.0.0`. The schema identifiers and
published v1 artifacts are immutable after release.

- Documentation, examples, or implementation fixes that do not change accepted
  instances, required data, ordering, fingerprint inputs, or semantics may
  update the contracts package without changing `schemaVersion`.
- Adding or removing a standard property, changing requiredness, adding an enum
  value, changing nullability, changing terminal-state meaning, or changing
  canonical identity rules requires a new major result-schema version.
- Experimental additive data must use an `x-` extension.

CLI and hosted producers pin the same exact contracts artifact. Consumers
select a schema by `schemaVersion`; they must not silently reinterpret an
unsupported major version.
