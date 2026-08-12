# PROOF built-in rule pack

`proof-rulepack` implements the versioned `agent-contract` 0.1.0 rules over
the immutable operation-set v1 contract:

- `AGT-CTX-001`
- `AGT-PARAM-001`
- `AGT-RESP-001`
- `AGT-POL-001`
- `AGT-POL-002`

The evaluator emits normalized finding v1 dictionaries with deterministic
ordering and RFC 8785 SHA-256 fingerprints. It consumes no repository paths,
network data, free-form classifier input, ambient time, or host identity.

The rule-pack identity includes its exact semantic manifest digest. Changes to
applicability, evidence, messages, remediation, or fingerprint inputs must
change that identity and pass the Issue #10 conformance fixtures.
