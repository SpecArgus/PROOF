# Security Policy

## Security model

The [initial threat model](docs/security/initial-threat-model.md) defines the
P0 trust boundaries, processing limits, required controls, verification, and
accepted residual risks for untrusted OpenAPI documents and GitHub events.
Hosted scanning remains blocked until its launch gates are implemented and
verified.

## Supported versions

PROOF has not published a stable release yet. Until a version support policy is announced, security fixes are applied to the active development line and included in the next release as appropriate.

## Reporting a vulnerability

Do not report suspected vulnerabilities in a public issue, discussion, pull request, or other public channel.

Use the repository's **Private vulnerability reporting** option under the
Security tab. This creates a private GitHub Security Advisory where maintainers
can investigate and coordinate a fix. If GitHub makes that option temporarily
unavailable, contact any current co-maintainer privately and request a secure
reporting channel before sharing vulnerability details.

Please include, when possible:

- the affected component and revision or version;
- steps to reproduce or a minimal proof of concept;
- the expected impact and attack conditions; and
- any suggested mitigation.

Maintainers will acknowledge the report when practical, assess its severity, and coordinate disclosure and remediation with the reporter. Please allow time for a fix before public disclosure.

For ordinary defects without security impact, use the public issue tracker.
