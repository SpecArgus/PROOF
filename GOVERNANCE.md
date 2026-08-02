# Governance

PROOF is developed in the open through issues, pull requests, and documented decisions.

## Roles

- **Contributors** propose ideas, report problems, review changes, and submit pull requests.
- **Maintainers** have repository write access and are responsible for review, releases, security response, and enforcement of project policies.

Consistent, constructive participation is the basis for expanded project responsibility. Maintainer appointments and changes should be recorded publicly in the repository.

## Phase 0 accountability

During Phase 0, `@back1ash`, `@Seo-yul`, and `@minsubyun1` are equal
co-maintainers with no primary/deputy hierarchy. The Phase 0 co-maintainer role
is the accountable owner for product decisions, success metrics, security
response, and releases. `@Seo-yul` and `@minsubyun1` also provide both
designated reviews of the labeled-corpus expectations. That work assignment
does not create a higher or lower authority level.

The Phase 0 gate has no fixed calendar date. It is convened when the evidence
listed in the roadmap is complete, or earlier when blocking evidence requires a
formal `proceed`, `revise and re-evaluate`, or `stop` decision. The full
identity and governance decision is recorded in
[ADR 0002](docs/adr/0002-product-identity-and-phase-0-governance.md).

## Maintainer equality and issue ownership

All active Maintainers have equal repository and governance authority. PROOF
does not use Maintainer levels, lead-versus-secondary reviewer ranks, or
permanent module ownership. Any future change to that model requires a public
governance decision recorded in the repository.

Issue assignment is temporary coordination ownership. It identifies the person
responsible for communicating progress and bringing that issue to a reviewable
outcome; it does not grant extra decision, review, merge, release, or module
authority. The same applies when the assignee is a Maintainer.

An assignee may make routine implementation choices within the accepted issue
scope. Material changes to architecture, compatibility, data formats, security
boundaries, governance, or release policy still require the normal public
decision process. Other Maintainers and Contributors remain free to review,
question, and improve the work.

## Decisions

Routine changes are decided through issue and pull-request review. The project seeks practical consensus based on user value, technical evidence, security, maintainability, and alignment with the product requirements.

Changes that materially affect architecture, compatibility, data formats, security boundaries, governance, or release policy require prior discussion. Their outcome should be recorded in an ADR or equivalent repository document. Recorded runtime and validator choices remain in force until another explicit, documented decision supersedes them.

The co-maintainers seek practical consensus. Material product, architecture,
security, governance, and release decisions require recorded agreement from at
least two of the three co-maintainers. A conflicted co-maintainer recuses, in
which case both non-conflicted co-maintainers must agree. If fewer than two
eligible co-maintainers are available, the material decision pauses.

Any co-maintainer may take an urgent, proportionate action to contain an active
security incident, including credential revocation or rotation, and must record
it as soon as safe disclosure permits. Residual-risk acceptance, public
disclosure, and release publication still require the material-decision rule.
Routine repository decisions remain part of normal issue and pull-request
review.

## Branches and releases

`develop` is the default integration branch, and normal pull requests target it. `main` is the stable release branch. Releases are promoted through a reviewed `develop` to `main` pull request. Urgent fixes branch from `main` and must be synchronized back to `develop`.

Project governance may evolve as the contributor community grows. Material governance changes follow the same public review process.
