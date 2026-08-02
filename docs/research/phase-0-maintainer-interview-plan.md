# Phase 0 maintainer interview plan

- **Status:** Proposed interview protocol
- **Owner:** Phase 0 co-maintainers
- **Issue:** [#9](https://github.com/SpecArgus/PROOF/issues/9)
- **Decision:** Hosted GitHub App, CLI-only, or defer

This plan defines how PROOF will interview maintainers before deciding whether
to pursue a hosted GitHub App. It fixes the qualification rules, interview
guide, evidence model, and decision thresholds before the first interview so
that interest in a proposed solution cannot be substituted for evidence of a
real problem.

The protocol may be used only after at least two Phase 0 co-maintainers record
agreement in the linked pull request or issue. Interview evidence can be
collected while the GitHub and security investigations are in progress, but a
final hosted-product recommendation remains gated on issues
[#7](https://github.com/SpecArgus/PROOF/issues/7) and
[#8](https://github.com/SpecArgus/PROOF/issues/8).

## Research questions

The interviews answer these questions:

1. Do maintainers encounter repeated, consequential OpenAPI contract-quality
   problems when reviewing changes intended for agent or function-calling use?
2. How are those problems found today, and where do current linters, validators,
   review conventions, or manual checks fail?
3. Would maintainers use advisory or blocking contract feedback in their pull
   request workflow, and what false-positive rate or failure behavior is
   acceptable?
4. Can the intended users install or obtain approval for a least-privilege
   GitHub App on a public repository?
5. Do public-fork behavior, public reports, vendor extensions, or repository
   data handling create non-negotiable adoption blockers?
6. If a hosted App is unsuitable, is a local or existing-CI CLI useful enough
   to justify the product direction?

The study does not estimate market size, pricing, or adoption volume. A stated
willingness to try a tool is weaker evidence than a concrete recent workflow,
incident, or policy constraint.

## Target participant profile

The primary participant is a maintainer or regular reviewer of a public GitHub
repository that accepts OpenAPI 3.x contract changes through pull requests.
They should understand either the repository's contract-review workflow or the
approval path for CI and GitHub App changes.

A participant qualifies only when all of the following are true:

- they maintained or regularly reviewed the relevant repository during the
  preceding 12 months;
- the repository contains or publishes an OpenAPI 3.0.x or 3.1.x contract;
- they have direct experience reviewing, troubleshooting, or governing at
  least one API-contract change; and
- they can discuss the repository workflow without disclosing confidential,
  private-repository, customer, or security-sensitive information.

Current PROOF contributors and people who can discuss only a hypothetical
workflow do not qualify. A participant without GitHub App installation
authority may qualify when they understand the actual approval process and can
identify the responsible role.

## Sample and recruitment

Attempt eight interviews and complete at least five qualifying interviews. Use
one primary participant per organization. A second participant from the same
organization may be interviewed for a meaningfully different role, but counts
only in a sensitivity analysis and not as an independent organization.

Recruit across overlapping workflow characteristics rather than trying to
represent a broad market. The qualifying set should include:

- at least two repositories that receive public-fork pull requests;
- at least two repositories already using automated OpenAPI validation or
  linting;
- at least two participants who can approve an App or CI change and at least
  two who must request that approval; and
- at least one monorepo or multi-specification repository.

If five qualifying interviews are complete but a diversity target is missing,
the evidence bundle must name that limitation and the final recommendation is
`defer` unless two co-maintainers approve a narrower target segment before
interpreting the results.

Recruitment messages must describe the topic as OpenAPI contract review, not as
a request to validate PROOF or endorse a GitHub App. Do not offer a product
benefit, roadmap influence, or public attribution in exchange for favorable
answers.

## Consent and data handling

Before starting, tell each participant:

- the purpose and expected duration of the interview;
- that participation is voluntary and any question may be skipped;
- that committed notes are anonymized and aggregated;
- that no private repository, customer, incident, credential, or organization-
  sensitive information should be shared; and
- whether audio or video recording is requested and how it will be deleted.

Use participant IDs such as `P01`. Do not commit names, organization names,
contact details, raw recordings, private repository references, or verbatim
text that could identify a participant without explicit consent. Store only the
sanitized note produced from the
[interview note template](maintainer-interview-note-template.md). Delete any
temporary recording after the participant has had the agreed opportunity to
correct the notes, and do not rely on a recording as the only evidence source.

## Interview method

Plan 40–50 minutes. Ask about observed behavior before presenting any solution
concept. Follow-up questions may clarify an answer but must not imply that one
delivery path is preferred.

### 1. Qualification and context — 5 minutes

1. What do you maintain or review, and what responsibility do you have for its
   OpenAPI contract?
2. Which OpenAPI dialects, file layouts, and pull-request sources are common?
3. Who can change CI requirements or approve a GitHub App installation?

End the interview as non-qualifying when the required profile cannot be
confirmed. Retain only a recruitment outcome, not interview evidence.

### 2. Recent concrete behavior — 10 minutes

1. Walk through the most recent contract change that was difficult to review or
   caused a problem after merge.
2. How was the problem noticed, who did extra work, and what happened next?
3. Which information would have made the review decision easier?
4. When did a contract-quality check last prevent or delay a merge?

Ask for the sequence of events and consequences. Do not ask for confidential
specification content or accept a generalized complaint as a concrete example.

### 3. Current alternatives — 8 minutes

1. Which validators, linters, review checklists, generated artifacts, or manual
   conventions run today?
2. Where do those tools produce noise, miss context, or fail to fit the
   workflow?
3. How are repository-local references, monorepos, and fork pull requests
   handled?
4. What happens when the tool cannot fully evaluate an input?

### 4. Contract feedback requirements — 7 minutes

1. Which contract problems should block a pull request, remain advisory, or be
   ignored?
2. How many incorrect blocking findings across 20 representative pull requests
   would make the check unacceptable?
3. What evidence and remediation detail must accompany a finding?
4. Would repository configuration through documented vendor extensions be
   acceptable? Which kinds would not be?

Record the participant's own threshold. Do not translate qualitative language
into a number unless the participant confirms the translation.

### 5. Present the three delivery concepts — 10 minutes

Present all three concepts with equal detail and in rotating order across
participants.

**Hosted App.** A least-privilege App reads immutable public-repository content
and pull-request metadata, evaluates trusted base policy without executing
repository code, and publishes a pull-request Check. Any public report follows
an explicit retention and visibility policy. Feasibility and security remain
subject to #7 and #8.

**CLI-only.** A versioned command runs locally or in repository-controlled CI,
uses the same static rules and result contract, and sends no specification to a
PROOF-hosted service. The repository owns installation, credentials, caching,
and presentation.

**Deferred hosted.** PROOF validates the CLI and rule quality first. A hosted
App is reconsidered only after usage evidence and the technical gates are
stronger.

For each concept ask:

1. What would have to be true for you to try this in a real repository?
2. Who would approve it, and what permissions or evidence would they require?
3. What data, public-report, fork, or operational concern would prevent use?
4. Which concept best fits the current workflow, and what trade-off drives that
   choice?

### 6. Contradictory evidence and close — 5 minutes

1. What important case have these questions missed?
2. Who would disagree with your answers, and why?
3. What would cause you to remove or disable this check after adoption?
4. May the anonymized observations be included in the Phase 0 evidence bundle?

Do not ask for a commitment to install the product.

## Evidence model

Each sanitized note separates:

- **direct observation:** a participant-reported event, current control,
  measured tolerance, approval rule, or clearly attributed preference;
- **interpretation:** the researcher's explanation of why the observation
  matters; and
- **open question:** an uncertainty that needs another participant, #7, #8, or
  a named follow-up to resolve.

Aggregate only qualifying participants. Count organizations, not interviews,
for threshold decisions. Preserve negative and contradictory observations even
when they are a minority. Similar statements from two people at the same
organization are one independent signal.

The aggregate evidence table uses these dimensions:

| Dimension | Evidence to record |
| --- | --- |
| Repeated pain | Concrete recent examples, consequence, frequency, and current workaround |
| Current alternatives | Tool or process, useful behavior, gaps, switching cost |
| Check policy | Blocking/advisory preference, participant-defined false-positive tolerance, failure behavior |
| Hosted adoption | Installation authority, approval path, acceptable permissions, public-report and data constraints |
| Fork workflow | Fork frequency, first-time contributor path, stale-result expectations, required-check behavior |
| CLI adoption | Local/CI ownership, offline requirement, operational burden, result presentation |
| Contradictory evidence | Counterexample, source context, and whether it narrows or rejects the target hypothesis |

## Pre-registered decision thresholds

Let `N` be the number of independent qualifying organizations, from 5 through
8. A recurring signal requires `S = max(3, ceiling(0.6 * N))` independent
organizations. Results below `S` may be reported but cannot satisfy a decision
criterion.

These evidence-quality gates apply to every recommendation:

- at least five qualifying organizations are included and eight interviews
  were attempted where feasible;
- the recruitment diversity targets are met or a narrower segment was approved
  before interpretation;
- at least `S` participants describe a concrete recent contract-review problem
  with a meaningful cost, delay, risk, or repeated manual workaround;
- direct observations, interpretation, opposition, and missing evidence remain
  separately visible; and
- at least two co-maintainers approve the final evidence interpretation.

### Recommend `hosted`

Recommend a hosted GitHub App only when all of the following are true:

- at least `S` participants prefer or would realistically trial pull-request
  Check feedback over a CLI-only workflow;
- at least `S` can approve the proposed installation or identify a demonstrated
  approval path for the minimum permissions;
- at least `S` accept an advisory-first rollout and describe a path to blocking
  use after the participant-defined false-positive threshold is met;
- no installation, public-report, or data-handling hard blocker recurs across
  two independent organizations without a tested mitigation;
- #7 demonstrates the required public-fork and Check isolation behavior; and
- #8 is accepted with no unresolved control that blocks the hosted concept.

### Recommend `CLI-only`

Recommend CLI-only when the common evidence-quality gates pass and all of the
following are true:

- at least `S` participants would realistically use the CLI locally or in
  repository-controlled CI;
- the hosted path fails an installation, fork, report, or security criterion;
  and
- no equivalent hard blocker recurs for the CLI path across two independent
  organizations.

### Recommend `defer`

Recommend `defer` when neither delivery path satisfies every applicable
criterion, when fewer than five qualifying organizations are represented, when
diversity is materially incomplete, or while #7 or #8 lacks the evidence needed
for a final hosted decision. Evidence that undermines the broader product
hypothesis is forwarded explicitly to the Phase 0 gate; `defer` must not hide a
possible `stop` outcome for the product direction.

Thresholds cannot be loosened after the first interview. A material correction
must be recorded, approved by two co-maintainers, and applied only to interviews
conducted after the amendment or to a fresh study.

## Delivery-path comparison

Complete this table from interview evidence and technical findings. Do not
score a cell before its evidence source is available.

| Decision dimension | Hosted App | CLI-only | Deferred hosted |
| --- | --- | --- | --- |
| Pull-request feedback and required gate | Pending interviews and #7 | Pending interviews | No hosted gate during deferral |
| Public-fork behavior | Pending #7 | Repository CI policy | Re-evaluate after evidence |
| Installation and permissions | Pending interviews and #7 | Package and CI approval | No App installation yet |
| Data handling and public reports | Pending interviews and #8 | Repository-controlled | No hosted report yet |
| Offline or no-egress operation | Hosted worker gate in #8 | Local best-effort boundary | CLI evidence first |
| False-positive rollout | Pending participant thresholds | Pending participant thresholds | Collect CLI quality evidence |
| Maintainer operational burden | Pending interviews | Pending interviews | Lower immediate hosted burden |
| Product learning speed | Pending interviews | Pending interviews | Slower hosted learning by design |

## Synthesis and decision record

After the interviews:

1. verify qualification and independent-organization counts;
2. publish sanitized participant notes or a traceable aggregate when even
   anonymized notes could identify a participant;
3. calculate `N` and `S`, then count supporting and opposing observations for
   every criterion;
4. integrate the final #7 and #8 findings without changing interview evidence;
5. complete the delivery-path comparison and list every unmet criterion;
6. record the recommendation, rationale, minority evidence, and confidence; and
7. assign each follow-up question an owner and next action.

The final record must include:

- evidence cutoff and participant count;
- qualifying and diversity summary;
- threshold result for every criterion;
- `hosted`, `CLI-only`, or `defer` recommendation;
- explicit relationship to #7 and #8;
- contradictory evidence and known limitations;
- agreement from at least two Phase 0 co-maintainers; and
- owned follow-up actions for the Phase 0 gate.
