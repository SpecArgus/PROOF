# Contributing to PROOF

Thank you for helping improve PROOF. The project is still establishing its technical foundation, so no runtime, package manager, framework, or validator should be treated as selected until the relevant decision is documented.

## Before you start

1. Search existing issues and pull requests.
2. Open or claim an issue before beginning a substantive change.
3. Confirm that the proposed work fits the issue's scope and current project decisions.

For architectural or dependency choices, discuss the trade-offs in the issue first. Significant decisions should be captured in an Architecture Decision Record (ADR).

## Branch workflow

- `develop` is the default integration branch.
- `main` contains stable releases.
- Create topic branches from `develop` using `type/<issue>-<slug>`, for example `feat/42-result-schema` or `docs/17-contributing-guide`.
- Open normal pull requests against `develop`.
- Releases are promoted with a pull request from `develop` to `main`.
- Create urgent release fixes from `main` as `hotfix/<issue>-<slug>`, then synchronize the merged fix back into `develop`.
- Do not push directly to `develop` or `main`.

## Pull requests

Keep each pull request focused on one issue. In the description:

- link the issue;
- explain the change and its motivation;
- describe how it was verified;
- call out compatibility, security, or documentation effects; and
- record any follow-up work explicitly.

Use clear, imperative titles. Pull-request titles must follow Conventional
Commits, for example `feat(core): add finding schema`. Update tests and
documentation when behavior changes, and ensure all required checks pass before
requesting review.

During the repository-foundation phase, protected branches do not require a
minimum number of approving reviews. Required checks and resolved review
conversations still apply. Any co-maintainer may decide a routine merge after
those controls pass. A pull request that contains a material product,
architecture, security, governance, or release decision also needs the recorded
agreement defined in [GOVERNANCE.md](GOVERNANCE.md). Enabling a formal approval
requirement is itself a material governance decision and does not happen until
that agreement is recorded.

By contributing, you agree that your work is licensed under the repository's license.
