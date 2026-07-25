# Cross-platform reviewed evidence

This directory preserves the reviewed artifacts from GitHub Actions run
[`30143349681`](https://github.com/SpecArgus/PROOF/actions/runs/30143349681)
at commit `97336e58ea5754d0b17e2aec802b42c7e7d4d618`.

The Linux x64, macOS arm64, and Windows x64 snapshots were produced from the
same evaluation input, package lock, candidate versions, and runtime versions.
Each platform completed both evaluation stages, the reviewed gap assertion,
the Go, Node, and Python vulnerability observations, inventory generation,
and snapshot integrity checks.

`cross-platform-manifest.json` records the workflow and artifact identities,
common input fingerprints, semantic comparison, platform-specific inventory
counts, and the SHA-256 of every preserved reviewed JSON file. The GitHub
artifact digests remain recorded even after the temporary Actions artifacts
expire.

The platform directories intentionally omit raw stdout, stderr, temporary
workspaces, and full vulnerability-service responses. Those raw artifacts
were retained by Actions for 30 days and are not durable repository evidence.

The common result is:

- stock CLI screening: 32 of 39 candidate cases passed;
- direct adapters: 73 of 75 applicable candidate-case combinations passed;
- libopenapi retained the reviewed deterministic-but-wrong validation gap;
- Redocly Core retained the reviewed diagnostic-volume gap; and
- openapi-spec-validator passed all nine required gates on all three
  platforms.

This evidence supports a recommendation. It does not record maintainer
approval or a product selection decision.
