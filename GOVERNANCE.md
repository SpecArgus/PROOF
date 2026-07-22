# Governance

PROOF is developed in the open through issues, pull requests, and documented decisions.

## Roles

- **Contributors** propose ideas, report problems, review changes, and submit pull requests.
- **Maintainers** have repository write access and are responsible for review, releases, security response, and enforcement of project policies.

Consistent, constructive participation is the basis for expanded project responsibility. Maintainer appointments and changes should be recorded publicly in the repository.

## Decisions

Routine changes are decided through issue and pull-request review. The project seeks practical consensus based on user value, technical evidence, security, maintainability, and alignment with the product requirements.

Changes that materially affect architecture, compatibility, data formats, security boundaries, governance, or release policy require prior discussion. Their outcome should be recorded in an ADR or equivalent repository document. No runtime or validator is currently selected; such a choice requires an explicit documented decision.

When consensus cannot be reached, maintainers make the final repository decision and document the rationale. Maintainers must disclose relevant conflicts of interest and should not unilaterally approve their own contentious governance changes.

## Branches and releases

`develop` is the default integration branch, and normal pull requests target it. `main` is the stable release branch. Releases are promoted through a reviewed `develop` to `main` pull request. Urgent fixes branch from `main` and must be synchronized back to `develop`.

Project governance may evolve as the contributor community grows. Material governance changes follow the same public review process.
