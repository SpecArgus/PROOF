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

Use `--format console --color never --output ../proof-report.txt` for a
plain-text report outside the scanned repository. A `.md` output filename is
also viewable as plain text, but is not a dedicated Markdown report format.
For automation or future web rendering, use `--format json --output
../proof-result.json` and consume the stable normalized result rather than
parsing console output. `--output` accepts a regular file path; pipelines and
special sinks should use stdout redirection.

Run `specargus proof scan --help` for the supported inputs.
