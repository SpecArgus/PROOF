# Maintainer interview note template

Copy this template for each qualifying Phase 0 interview. Commit only sanitized
notes that meet the data-handling rules in the
[interview plan](phase-0-maintainer-interview-plan.md). Use participant IDs,
never names or organization identifiers.

## Interview metadata

- **Participant ID:** PXX
- **Interview date:** YYYY-MM-DD
- **Interviewer:**
- **Qualification:** qualifying / non-qualifying
- **Independent organization count:** primary / sensitivity-only
- **Repository archetype:** public forks / direct branches / monorepo /
  multi-specification / other
- **OpenAPI dialects:** 3.0.x / 3.1.x
- **Current automation:** none / validator / linter / generated diff / other
- **App or CI authority:** approver / documented requester / unknown

## Consent and sanitization

- [ ] Purpose and voluntary participation explained.
- [ ] Participant allowed anonymized observations in the Phase 0 evidence.
- [ ] Recording consent captured separately, if recording was used.
- [ ] Names, organizations, contacts, private repositories, customers,
      credentials, and sensitive incident details removed.
- [ ] Temporary recording deleted according to the agreed process.

Do not continue as a qualifying interview if the participant cannot safely
discuss the workflow without organization-sensitive information.

## Qualification evidence

Record the evidence for each required criterion without identifying the person
or repository.

| Criterion | Direct evidence | Pass? |
| --- | --- | --- |
| Maintained or regularly reviewed in the preceding 12 months | | yes / no |
| Public repository uses OpenAPI 3.x | | yes / no |
| Direct API-contract review or governance experience | | yes / no |
| Can discuss a real workflow safely | | yes / no |

## Direct observations

Record events, current controls, participant-defined thresholds, and clearly
attributed preferences. Paraphrase by default. A short quotation may be used
only when consented and not identifying.

| ID | Topic | Observation | Context or consequence | Evidence strength |
| --- | --- | --- | --- | --- |
| O-01 | | | | concrete event / current policy / preference |

## Interpretation

Keep researcher interpretation separate from the observation that supports it.

| ID | Observation IDs | Interpretation | Alternative explanation | Confidence |
| --- | --- | --- | --- | --- |
| I-01 | O-XX | | | low / medium / high |

## Current workflow

- **Most recent contract-review problem:**
- **Consequence and affected role:**
- **Current tools or manual controls:**
- **Useful behavior in the current approach:**
- **Gaps or recurring workarounds:**
- **Fork, monorepo, or local-reference behavior:**
- **Incomplete-analysis failure behavior:**

## Feedback policy

- **Should block:**
- **Should remain advisory:**
- **Should not be reported:**
- **Incorrect blocking findings tolerated per 20 representative PRs:**
- **Required evidence or remediation detail:**
- **Acceptable vendor extensions:**
- **Unacceptable configuration mechanism:**

Do not infer a numeric false-positive threshold from qualitative language.

## Delivery concept reactions

### Hosted App

- **Trial conditions:**
- **Approval path and minimum evidence:**
- **Permission concerns:**
- **Public-report or data concerns:**
- **Fork or required-check concerns:**
- **Hard blocker:** none / described below

### CLI-only

- **Trial conditions:**
- **Local or CI owner:**
- **Offline/no-egress requirement:**
- **Operational or presentation concerns:**
- **Hard blocker:** none / described below

### Deferred hosted

- **Evidence required before reconsideration:**
- **Cost of waiting:**
- **Hard blocker:** none / described below

- **Participant's preferred path and reason:**
- **What could change that preference:**

## Contradictory and missing evidence

- **Who or what workflow may contradict this account:**
- **Counterexample raised by the participant:**
- **Question not answered:**
- **Evidence that would resolve it:**

## Sanitized summary

Summarize only what the direct observations support. Do not convert interest
into an adoption commitment.

- **Repeated pain signal:** supports / opposes / neutral
- **Hosted adoption signal:** supports / opposes / neutral
- **CLI adoption signal:** supports / opposes / neutral
- **Public-fork relevance:** supports / opposes / neutral
- **Material objection:**
- **Research limitation:**

## Follow-up

| Question or action | Owner | Due trigger | Public artifact |
| --- | --- | --- | --- |
| | | | |
