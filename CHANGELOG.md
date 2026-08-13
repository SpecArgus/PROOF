# Changelog

All notable changes to this project will be documented in this file.

The format is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project intends to use [Semantic Versioning](https://semver.org/) once releases begin. No release has been published yet.

## [Unreleased]

### Added

- Establish the repository governance, contribution workflow, issue templates,
  release policy, review ownership, and exit-criteria-based roadmap.
- Add language-neutral repository metadata validation for pull requests.
- Add a versioned, specification-only profile for projecting `x-agent-policy`
  into MCP tool descriptions and supported annotation hints.
- Add a deterministic normalized-run producer that combines validator,
  normalization, and rule-pack findings with verified provenance, gate state,
  summaries, terminal failures, and RFC 8785 result digests.

### Changed

- Temporarily set the required approving-review count to zero while the
  repository foundation is being established; required CI and resolved review
  conversations remain enforced.
- Adopt `SpecArgus PROOF` as the Phase 0 public identity and record three equal
  co-maintainers, both evidence reviewers, and the exit-criteria-driven Phase 0
  gate.

### Deprecated

<!-- Features scheduled for removal. -->

### Removed

<!-- Features removed from the project. -->

### Fixed

<!-- Bug fixes. -->

### Security

- Enable GitHub Private vulnerability reporting for confidential security
  reports.
