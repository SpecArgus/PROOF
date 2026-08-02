# ADR 0001: Adopt the Phase 0 product identity and governance

- **Status:** Accepted
- **Date:** 2026-07-23
- **Accountable role:** Phase 0 co-maintainers
- **Role members:** `@back1ash`, `@Seo-yul`, `@minsubyun1`
- **Evidence reviewers:** `@Seo-yul`, `@minsubyun1`
- **Tracking issue:** [#6](https://github.com/SpecArgus/PROOF/issues/6)

## Context

The repository needs a stable public identity and explicit decision ownership
before technical choices become implementation commitments. `PROOF` expands to
**Policy Review of OpenAPI Operations for Function-calling**, but the bare word
is too crowded to use consistently across public machine identifiers.

The unscoped `proof` package name is already registered on
[npm](https://www.npmjs.com/package/proof) and
[PyPI](https://pypi.org/project/proof/), and the
[`proof` GitHub account](https://github.com/proof) already exists. GitHub App
names must be unique and cannot match an existing GitHub account unless that
account is owned by the App owner, according to GitHub's
[App registration requirements](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app).
Using bare `PROOF` everywhere would therefore create avoidable package, CLI,
App, search, and brand ambiguity.

The runtime and hosted-product direction are still Phase 0 decisions. Naming
must not select a runtime prematurely or imply that static contract findings
guarantee runtime safety.

## Decision

### Public identity

**SpecArgus PROOF** is the public working identity for Phase 0. The repository
remains `SpecArgus/PROOF`, and documentation may use `PROOF` after the full name
has been introduced in context.

The intended public surfaces are:

| Surface | Phase 0 identity | Status |
| --- | --- | --- |
| Product and documentation | `SpecArgus PROOF` | Adopted for Phase 0 |
| Repository | `SpecArgus/PROOF` | Existing canonical repository |
| CLI | `specargus proof` | Planned naming direction; implementation waits for #5 |
| npm package | `@specargus/proof` | Candidate if the selected runtime uses npm |
| Other package registries | `specargus-proof` or ecosystem-appropriate `SpecArgus.Proof` | Candidate; decide in #5 |
| GitHub App | `SpecArgus PROOF` | Conditional on the hosted-product decision in #9 |

Candidate identifiers are not reservations. Availability, registry ownership,
and release provenance must be revalidated immediately before registration or
publication. GitHub normalizes the proposed App display name into a URL slug,
so #7 and #9 must verify both the `SpecArgus PROOF` display name and the
resulting `specargus-proof` slug before registration.

The final launch name is intentionally revisited at the Phase 0 gate. Bare
`proof` is not an acceptable package, executable, or GitHub App identifier.
Names that imply comprehensive runtime `Safety` are also excluded because
PROOF performs static contract analysis and does not replace authorization,
confirmation, or sandbox enforcement.

### Accountability

The Phase 0 co-maintainer role is the accountable owner. Its current members,
`@back1ash`, `@Seo-yul`, and `@minsubyun1`, are equal co-maintainers. There is
no primary/deputy hierarchy. Each has the same authority and responsibility
for:

- product scope and product decisions;
- success metrics and the evidence used to evaluate them;
- security response and acceptance of residual risk; and
- releases and public artifacts.

The co-maintainers seek practical consensus. A material product, architecture,
security, governance, or release decision requires recorded agreement from at
least two of the three co-maintainers. A co-maintainer with a relevant conflict
of interest recuses from the decision; both non-conflicted co-maintainers must
then agree. If fewer than two eligible co-maintainers are available, the
material decision pauses.

Any co-maintainer may take an urgent, proportionate action needed to contain an
active security incident, including credential revocation or rotation. The
action and rationale must be recorded as soon as safe disclosure permits.
Accepting residual risk, making a public disclosure, or publishing a release
still requires the material-decision rule above.

`@Seo-yul` and `@minsubyun1` are both designated evidence reviewers. Both
review the labeled-corpus expectations required by #11. Their evidence-review
assignment is a division of work, not a higher or lower authority level. It is
also separate from GitHub's required-approval count and does not create a
branch-protection approval requirement during the repository-foundation period.

### Role acceptance

All three current role members recorded their acceptance of the co-maintainer
responsibilities in the linked pull request. The ADR was therefore changed to
Accepted before merge. Merging it into `develop` activates the role and records
Phase 0 entry. The acknowledgements are governance records, not
branch-protection approval requirements.

### Phase 0 gate

Phase 0 begins only after:

- the repository foundation has been merged into `develop`;
- contribution, governance, security, and release policies are present;
- protected-branch and repository-validation controls are active;
- the public working identity, co-maintainers, and evidence reviewers are
  recorded; and
- Phase 0 outcomes, evidence work, and exit criteria are tracked in public
  issues and the roadmap.

Foundation PR #2 satisfied the repository-policy and protection prerequisites.
The merge of this ADR into `develop` in Accepted status will satisfy the
remaining identity and accountability prerequisites and record entry into
Phase 0. That merge date will not be a scheduled gate-review date.

The Phase 0 gate is **exit-criteria-driven and has no fixed calendar date**.
This is a deliberate scheduling decision, not an unresolved date.

Any co-maintainer may convene the gate when the evidence bundle is complete:

- validator evaluation and recommendation (#3);
- normalized result schema v1 (#4);
- runtime and repository architecture ADR (#5);
- public-fork Check feasibility evidence (#7);
- initial threat model (#8);
- target-maintainer interviews and hosted-product recommendation (#9);
- five P0 rule specifications (#10); and
- the labeled 100-operation corpus with review evidence from both designated
  reviewers (#11).

An earlier gate may be convened if evidence exposes a blocker that invalidates
the product hypothesis or makes further work irresponsible. The final outcome
requires recorded agreement from at least two co-maintainers. `@Seo-yul` and
`@minsubyun1` also participate as the designated evidence reviewers.

The permitted gate outcomes are:

1. **Proceed** to the next phase.
2. **Revise and re-evaluate** after named evidence gaps are closed.
3. **Stop** the affected product direction.

The hosted GitHub App and web report receive a separate `hosted`, `CLI-only`,
or `defer` recommendation through #9 before Phase 2 work begins.

## Options considered

### Use bare `PROOF` on every surface

- **Benefits:** Short and consistent in prose.
- **Costs and risks:** Conflicts with existing packages and accounts, weak
  searchability, and no dependable exact GitHub App name.
- **Decision:** Rejected.

### Use `SpecArgus PROOF` during Phase 0

- **Benefits:** Preserves the existing acronym and repository while providing
  a distinctive namespace for packages, CLI commands, and the App.
- **Costs and risks:** Longer display name and a possible launch-time rename.
- **Decision:** Accepted.

### Select an unrelated permanent launch brand now

- **Benefits:** Could provide stronger independent searchability.
- **Costs and risks:** Requires a broader brand and trademark investigation
  before the product hypothesis and hosted direction are validated.
- **Decision:** Deferred to the Phase 0 gate.

### Set a calendar review date

- **Benefits:** Creates a time-based forcing function.
- **Costs and risks:** Encourages decisions without the required evidence or an
  arbitrary delay after evidence is ready.
- **Decision:** Rejected in favor of the explicit evidence trigger above.

## Consequences

### Positive

- Public references have one namespace without committing to a runtime.
- Accountable decisions and evidence-review responsibilities are explicit.
- The gate cannot be declared complete merely because a date has arrived.
- Package and App collisions are handled before implementation depends on them.

### Negative and trade-offs

- The public working name may change at the Phase 0 gate.
- Package and App identifiers remain candidates until their implementation
  decisions and registration checks are complete.
- With no fixed date, issue status and exit evidence must remain visible so the
  gate does not drift indefinitely.

## Security and privacy

Security responsibility is shared equally by the three co-maintainers.
Material residual-risk acceptance must be recorded and requires agreement from
at least two co-maintainers. Public naming must not overstate static-analysis
assurances or expose confidential vulnerability information.

## Reproducibility and compatibility

This decision changes names and governance only. It does not select a runtime,
validator, schema implementation, or hosted architecture. Future package names
and compatibility aliases must be documented in #5 before publication.

## Follow-up actions

- [ ] The three co-maintainers jointly own revalidation of CLI and package
  identifiers in #5 before the first package or executable is published.
- [ ] The three co-maintainers jointly own revalidation of the GitHub App
  display name, normalized slug, and registration constraints in #7 and #9
  before App registration.
- [ ] The three co-maintainers jointly own completion of #11; `@Seo-yul` and
  `@minsubyun1` provide and record both designated evidence reviews before the
  Phase 0 gate.
- [ ] The three co-maintainers reconsider the permanent launch name at the
  Phase 0 gate under the two-of-three material-decision rule.

## Decision history

- 2026-07-23: Proposed `SpecArgus PROOF`, equal Phase 0 authority for the three
  co-maintainers, and an exit-criteria-driven gate without a calendar date.
- 2026-07-31: Accepted after `@back1ash`, `@Seo-yul`, and `@minsubyun1`
  acknowledged the shared co-maintainer responsibilities in pull request #12.
