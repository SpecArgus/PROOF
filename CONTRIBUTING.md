# Contributing to PROOF

Thank you for helping improve PROOF. The project is still establishing its
technical foundation. Follow the decisions recorded in the repository, and
discuss any proposed architecture or dependency change before implementation.

## Before you start

1. Search existing issues and pull requests.
2. Open or claim an issue before beginning a substantive change.
3. Confirm that the proposed work fits the issue's scope and current project decisions.

For architectural or dependency choices, discuss the trade-offs in the issue first. Significant decisions should be captured in an Architecture Decision Record (ADR).

## Issue priority and claiming

PROOF keeps issues unassigned until a contributor chooses one. Priority labels
are strict delivery gates, not estimates of difficulty:

- `priority:p0` is required for the current phase. No P1 or P2 issue may start
  while any P0 issue is open.
- `priority:p1` is the next product increment. No P2 issue may start while any
  P1 issue is open.
- `priority:p2` is future work. It may also depend on an explicit product
  decision recorded in its issue.

Work within the currently active priority may proceed in parallel when its
explicit dependencies are satisfied. A lower-priority issue remains blocked
even when it could technically be implemented independently. If a higher
priority issue is opened or reopened, lower-priority work must pause at a safe
boundary and return to the blocked state.

The status label is the authoritative answer to whether an issue can be
started:

- `status:blocked` means that a priority gate, decision, or explicit dependency
  is incomplete. Do not start or claim the issue.
- `status:ready` means that every gate and dependency is satisfied and the
  issue is available to claim. Maintainers keep ready issues unassigned.
- `status:in-progress` means that one contributor has claimed the issue and is
  actively responsible for coordinating it.
- A closed issue with the `completed` reason is complete. Closing an issue as
  `not planned` does not satisfy a dependency unless the dependent issue or
  decision explicitly says that it does.

The `help wanted` label is a discovery aid, not a workflow state. Use
`status:ready` to find work that can actually start.

### Claiming ready work

Immediately before starting, refresh the issue and confirm that it is open,
unassigned, and labeled `status:ready`. Then:

1. assign the issue to yourself;
2. replace `status:ready` with `status:in-progress`;
3. remove `help wanted`; and
4. comment with a short plan, expected deliverables, and any known risks.

The assignee and `status:in-progress` label reserve the issue against duplicate
work. If two contributors race to claim it, the earlier complete transition in
the issue history wins. The other contributor must stop and coordinate in the
issue before doing substantive work.

Keep progress, scope changes, and blockers visible in the issue. A pull request
must link the issue and use a closing keyword, such as `Closes #17`, only when
merging the pull request will satisfy every acceptance criterion.

### Pausing or releasing work

Do not leave an inactive issue claimed. Before pausing or releasing it:

1. comment with completed work, remaining work, branch or pull-request links,
   and the reason for release;
2. remove yourself as assignee;
3. replace `status:in-progress` with `status:ready` and restore `help wanted`
   when all gates and dependencies still pass; or
4. replace it with `status:blocked` when a gate or dependency no longer passes,
   and identify the blocker in the issue.

Maintainers promote a blocked issue to ready only after checking both its
explicit dependencies and the global priority gate. The transition must remove
`status:blocked`, add `status:ready`, leave the issue unassigned, and add
`help wanted`. These labels are mutually exclusive: an open issue must not
carry more than one `status:*` label.

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
