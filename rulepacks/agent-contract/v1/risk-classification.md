# Deterministic risk classification v1

The P0 classifier assigns zero or more normalized risk categories to each
OpenAPI operation. Its output supplies applicability and evidence to
`AGT-POL-001` and `AGT-POL-002`; it is not a runtime risk assessment.

[`risk-classification.json`](risk-classification.json) is the machine-readable
vocabulary. This document defines how that vocabulary is applied.

## Inputs

Only these inputs participate:

1. the lowercase HTTP method;
2. exact ASCII tokens from the path template;
3. exact ASCII tokens from `operationId`; and
4. entries in operation-level `x-agent-policy.risks`.

Summary, description, parameter text, schema names, examples, and external
data are excluded. Wording changes therefore cannot silently change a gate.

## Tokenization

For a path or `operationId`:

1. split lower-to-upper and letter-to-digit ASCII transitions;
2. convert ASCII letters to lowercase;
3. replace every non-ASCII-alphanumeric run with one boundary;
4. discard empty tokens; and
5. compare complete tokens without stemming or substring matching.

Path-template variable names are tokenized like other path text. A token is a
signal only when it exactly matches the versioned vocabulary below.

## Categories and signals

`DELETE` always adds `destructive`.

For `POST`, `PUT`, `PATCH`, and `DELETE`, vocabulary matches add:

| Category | Exact tokens |
| --- | --- |
| `destructive` | `cancel`, `cancels`, `delete`, `deletes`, `deletion`, `destroy`, `destroys`, `purge`, `purges`, `remove`, `removes`, `terminate`, `terminates` |
| `financial_action` | `charge`, `charges`, `checkout`, `debit`, `debits`, `deposit`, `deposits`, `invoice`, `invoices`, `pay`, `payment`, `payments`, `payout`, `payouts`, `purchase`, `purchases`, `refund`, `refunds`, `transfer`, `transfers`, `withdraw`, `withdrawal`, `withdrawals` |
| `external_side_effect` | `dispatch`, `dispatches`, `email`, `emails`, `message`, `messages`, `notification`, `notifications`, `notify`, `publish`, `publishes`, `send`, `sends`, `sms`, `webhook`, `webhooks` |
| `permission_change` | `access`, `grant`, `grants`, `invite`, `invites`, `permission`, `permissions`, `revoke`, `revokes`, `role`, `roles` |

For every HTTP method, these tokens add `sensitive_data`:

`credential`, `credentials`, `health`, `medical`, `password`, `passwords`,
`pii`, `profile`, `profiles`, `secret`, `secrets`, `ssn`, `token`, and
`tokens`.

Every valid entry in `x-agent-policy.risks` adds that category regardless of
method or tokens. No extension value can remove a method or token result.

## Evidence

The classifier records all matching signals, deduplicates identical evidence,
and orders it by evidence kind, pointer, and value.

| Signal | Evidence kind | Pointer | Value |
| --- | --- | --- | --- |
| HTTP method | `method` | Operation pointer | Lowercase method |
| Path token | `path` | Path Item pointer | Matched token |
| `operationId` token | `keyword` | Operation `operationId` pointer | Matched token |
| Explicit category | `extension` | Exact `risks` array item pointer | Category |

Every risk-based finding contains at least one recorded classification signal.
If several signals infer one category, all are retained so a user can see why
the operation matched.

## Conservative limits

The classifier intentionally accepts false negatives in preference to hidden
semantic guesses. For example, `POST /process` is not considered risky from
that name alone. Teams can explicitly declare a category in `x-agent-policy`
when the versioned vocabulary cannot express the domain meaning.

Vocabulary changes can alter findings and fingerprints. They require a new
rule-pack version and benchmark review.
