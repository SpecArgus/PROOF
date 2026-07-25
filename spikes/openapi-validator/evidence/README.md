# Reviewed evidence snapshot

These files preserve the reviewed evidence behind the issue #3 report:

- [`platforms`](platforms/README.md) contains the durable Linux x64, macOS
  arm64, and Windows x64 reviewed snapshots from the final identical-input CI
  run, plus a cross-platform manifest with source, artifact, and file hashes.
- `evaluation-summary.json` contains normalized first observations, repeated
  result hashes, native probes, stock-CLI adapter qualifications, and
  supervisor-control status without raw candidate output or timing noise.
- `adapter-evaluation-summary.json` contains the common direct-adapter gate
  results, normalized first observations, deterministic hashes, and supervisor
  self-checks. It records candidate gaps; it is not a selection decision.
- `inventory-summary.json` contains the npm CycloneDX and Vacuum inventory
  aggregates, both direct-adapter aggregates, and their known coverage
  limitations.
- `vacuum-modules.json` records every module linked into the evaluated Vacuum
  binary with its version, Go checksum, and locally detected license.
- `libopenapi-adapter-modules.json` records every module linked into the
  evaluated libopenapi adapter with its version, Go checksum, and locally
  detected license.
- `libopenapi-adapter-vulnerability-summary.json` records the time-bound,
  normalized `govulncheck` result for the exact adapter binary.
- `node-vulnerability-summary.json` records the time-bound npm audit result
  and attributes affected packages to the candidate closures captured by the
  inventory. Findings confined to rejected candidates remain visible without
  being treated as selection-relevant.
- `openapi-spec-validator-python-packages.json` records the exact hash-locked
  Python runtime package inventory used by the evaluated adapter.
- `python-vulnerability-summary.json` records the time-bound,
  release-specific PyPI vulnerability observations for that exact Python
  package set.

The top-level snapshot was generated on Windows x64 with Node `24.13.0`, Go
`1.25.12`, and the pinned candidate versions. The `platforms` directory
contains the final CI snapshots for Linux x64, macOS arm64, and Windows x64.
Vacuum and libopenapi binary hashes, sizes, and some build-tagged linked
modules are platform-specific. Windows evaluates junction escape cases and
skips the POSIX symlink cases; Ubuntu and macOS invert those platform-specific
cases.

Refresh the snapshot only after reviewing a completed evaluation:

```text
npm test
npm run audit:go
npm run inventory
npm run audit:node
npm run audit:python
npm run snapshot
```

`npm test` includes the reviewed direct-adapter gap assertion. That assertion
fails if either known gap disappears without review, if a new gap appears, or
if the harness is incomplete. Passing it does not mean a candidate has been
selected.

Raw stdout, stderr, full npm SBOM, complete vulnerability-service responses,
and build metadata remain generated under ignored `.cache/evidence`. The
tracked snapshot is the durable, reviewer-oriented record.
