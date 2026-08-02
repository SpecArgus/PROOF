# Branching and release policy

PROOF uses a two-branch model: `develop` integrates the next release, while `main` contains stable, releasable history. Changes reach either long-lived branch through pull requests.

## Long-lived branches

### `develop`

- GitHub default branch and normal pull-request target.
- Integration branch for the next release.
- Protected from direct pushes, force pushes, and deletion.
- Must remain buildable; incomplete work should stay on topic branches or behind an explicitly documented boundary.

### `main`

- Stable release branch.
- Receives planned releases from `develop` and emergency hotfixes only.
- Protected from direct pushes, force pushes, and deletion.
- Release tags are created from commits on this branch.

## Topic branches

Create each topic branch from an up-to-date `develop` branch and link it to an issue. Use a short lowercase slug:

- `feat/<issue>-<slug>` for features
- `fix/<issue>-<slug>` for non-release bug fixes
- `spike/<issue>-<slug>` for time-boxed technical investigation
- `docs/<issue>-<slug>` for documentation
- `chore/<issue>-<slug>` for maintenance

Keep each branch focused on one reviewable outcome. Rebase or update it as required by repository rules; do not force-push after review has begun unless reviewers are notified.

## Pull requests into `develop`

1. Open the pull request against `develop` and link the governing issue.
2. Explain the change, verification, risks, and any follow-up work.
3. Pass required checks and resolve review conversations.
4. During the repository-foundation phase, no approving review is required by
   the ruleset. Any co-maintainer may decide a routine merge after the required
   controls pass. A pull request containing a material product, architecture,
   security, governance, or release decision also requires the recorded
   agreement defined in [GOVERNANCE.md](../GOVERNANCE.md). Enabling required
   approvals is itself a material governance decision.
5. For normal topic branches, use **squash merge** so one topic pull request
   becomes one coherent commit.
6. Delete the topic branch after merge.

Pull-request titles become squash commit subjects and must follow Conventional Commits, for example:

```text
feat(core): add deterministic finding fingerprints
fix(cli): distinguish input and internal failures
docs(governance): document the release flow
```

Use a breaking-change footer only when the compatibility impact and migration path are documented.

## Planned releases

1. Confirm that `develop` satisfies the milestone exit criteria and required checks.
2. Finalize the version, changelog entry, compatibility notes, and release evidence on `develop`.
3. Open a release pull request from `develop` to `main`.
4. Review the exact release diff and provenance.
5. Use a **merge commit** for `develop` into `main`; do not squash or rebase the release pull request.
6. Create the signed or protected semantic-version tag and GitHub release from the resulting `main` commit.

Using a merge commit preserves the relationship between the two long-lived branches and keeps later release diffs meaningful.

## Hotfixes

1. Create `hotfix/<issue>-<slug>` from the affected commit on `main`.
2. Add focused regression coverage and open a pull request to `main`.
3. After review and required checks, squash-merge the hotfix and publish the required patch release.
4. Immediately open a pull request from `main` back into `develop` and merge it
   with a merge commit. This synchronization PR is the explicit exception to
   the normal squash-merge rule for `develop`.
5. Resolve any conflicts in the synchronization pull request; never reimplement the fix independently on `develop`.

No planned release should proceed until all prior hotfixes are present in `develop`.

## Exceptions

No role has a standing bypass for protected-branch rules. An emergency change
to a ruleset must be explicit, limited to restoring the repository or release
process, documented in an issue or retrospective, and reverted immediately
after the branch state is reconciled through pull requests.
