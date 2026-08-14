# PROOF CLI

`specargus proof scan` runs deterministic static analysis over repository-relative
OpenAPI JSON or YAML files. It reads repository data but never executes it,
does not resolve remote or `file:` references, and does not claim to sandbox a
compromised local host.

The command emits one canonical result-v1 JSON object by default. `--format
console` prints a concise summary, detailed findings, terminal errors, gate
state, truncation count, and provenance. Console color is optional and does
not affect ordering or the normalized result. `--output` atomically replaces
the selected report file. The default gate blocks `error` and `high` findings.
Exit codes are `0` for pass or advisory, `1` for a blocked gate, `2` for
configuration or input errors, and `3` for internal failures.

Run `specargus proof scan --help` for the supported inputs.
