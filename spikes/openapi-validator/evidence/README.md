# Reviewed evidence snapshot

These files preserve the reviewed evidence behind the issue #3 report:

- `evaluation-summary.json` contains normalized first observations, repeated
  result hashes, native probes, adapter qualifications, and supervisor-control
  status without raw candidate output or timing noise.
- `inventory-summary.json` contains the npm CycloneDX and Vacuum inventory
  aggregates and their known coverage limitations.
- `vacuum-modules.json` records every module linked into the evaluated Vacuum
  binary with its version, Go checksum, and locally detected license.

The current snapshot was generated on Windows x64 with Node `24.13.0`, Go
`1.25.12`, and the pinned candidate versions. Vacuum binary hashes and sizes
are platform-specific.

Refresh the snapshot only after reviewing a completed evaluation:

```text
npm test
npm run inventory
npm run snapshot
```

Raw stdout, stderr, full npm SBOM, and build metadata remain generated under
ignored `.cache/evidence`. The tracked snapshot is the durable,
reviewer-oriented record.
