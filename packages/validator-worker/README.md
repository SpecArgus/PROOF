# PROOF validator worker

`proof-validator-worker` is the isolated OpenAPI 3.0/3.1 validation authority
used by the PROOF core. It pins `openapi-spec-validator` 0.9.0 behind a
versioned JSON protocol over standard input and standard output.

The worker accepts only an immutable, content-addressed input closure. It does
not receive a repository root and does not open specification files itself.
All `$ref` resolution is served by a deny-by-default in-memory resource map.

The package is normally launched by `proof_core.validate_openapi`. Direct
invocation is available for process-contract tests:

```text
python -I -m proof_validator_worker
```

Exactly one JSON request is read from standard input. Exactly one compact JSON
response plus a trailing newline is written to standard output. Contract or
unexpected internal failures exit non-zero and can never be confused with a
valid OpenAPI result.
