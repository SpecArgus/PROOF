# Architecture decision records

PROOF uses architecture decision records (ADRs) for choices that materially
affect architecture, compatibility, security boundaries, reproducibility,
governance, or the release process.

## Creating an ADR

1. Copy [`0000-template.md`](0000-template.md).
2. Name the file `NNNN-short-decision-title.md` using the next available
   four-digit number.
3. Open an issue for the decision and link it from the ADR.
4. Submit the proposed ADR through a pull request to `develop`.
5. Record material revisions in the decision history instead of silently
   rewriting an accepted decision.

## Status values

- **Proposed**: under discussion and not yet authoritative.
- **Accepted**: approved and currently authoritative.
- **Rejected**: considered but not selected.
- **Superseded**: replaced by a later ADR, which must be linked.
- **Deprecated**: retained for history but no longer recommended.

Implementation should not depend on a proposed decision unless the related
issue explicitly authorizes a reversible spike.

## Records

- [ADR 0001: Adopt the Phase 0 product identity and governance](0001-product-identity-and-phase-0-governance.md)
  — Accepted on 2026-07-31.
