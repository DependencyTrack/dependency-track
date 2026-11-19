| Status   | Date       | Author(s) |
|:---------|:-----------|:----------|
| Proposed | 2026-11-07 | [WenFeng Gao (@007xf)](https://github.com/007xf) |

## Context

A violation identifies a component and policy condition in a project. It can stay open while
another known exploited vulnerability starts matching the same condition. [ADR 043] lets a
condition return the identifiers in its message. Reconciliation updates that message, but only
new violations produce notifications. [Issue 7649] describes the missing change alert.

The old notification group has creation semantics. Reusing it for updates would change existing
automations. Reading old messages before an upsert also needs care. PostgreSQL can resolve an
upsert conflict with a row that was not visible in that statement's snapshot.

## Decision

Add an event group named `POLICY_VIOLATION_UPDATED`. Existing rules do not subscribe to it
automatically. Keep `POLICY_VIOLATION` for creation and keep summary notifications unchanged.
A null-safe change to the stored message produces an update event. The event has a distinct
subject with the project, component, stable violation UUID, policy and condition, optional previous
and current messages, and the database statement time. Absent message fields mean null.

Use a short READ COMMITTED transaction for reconciliation and the notification outbox write.
Acquire the project row lock in a separate statement before reading old messages. This serializes
reconciliation even when the project has no violations yet. The next statement sees the preceding
committed transition. Preserve the bulk upsert and deletion, and do not issue per-violation reads.
Require an active READ COMMITTED transaction so callers cannot silently release the lock early
or reuse a stale transaction snapshot. Use a non-key-changing row lock so foreign-key checks
can continue. Normal project analysis workflows already serialize their full evaluation by project.

Retain existing approval and suppression filters for `POLICY_VIOLATION_UPDATED`. Add a
separate explicit opt-in group, `POLICY_VIOLATION_UPDATED_REVIEWED`, for changed messages
when the analysis state is APPROVED or suppression is true. Existing rules gain no subscription
automatically. This group reports changed content despite a retained review decision. It does
not approve, unapprove, suppress or unsuppress the violation.

Fetch update subjects and their analysis state and suppression in one bulk SQL statement.
Classify each transition once from that statement's snapshot, sending either the ordinary or
reviewed update group. Do not query the two classes separately, since a concurrent review
could otherwise move a record between those queries and cause duplicate or missing events.
Include optional analysis state and suppression in reviewed-update subjects. A present false
is an explicit unsuppressed state. Ordinary updates retain their original payload shape and
omit these fields. Absence means no captured value. The metadata is
an observation during subject assembly, not a claim that review cannot change before delivery.
Review-only changes, new subscriptions and clearing a decision do not replay prior transitions.

Order vulnerability inputs by their stable database identity. A message that joins the same input
set then stays stable across query plans. Do not parse arbitrary policy messages as KEV lists or
infer whether a change increases risk. A removal, replacement, or wording change also counts as
a message change. Notification filter expressions can narrow the events sent to a destination.

## Consequences

A second KEV can produce an opt-in update alert while the violation keeps its identity and review
history. Existing subscribers keep creation semantics. The outbox and violation change commit
or roll back together. Delivery uses the existing durable notification workflow and retry policy.
A retry may deliver the same event more than once. Receivers can deduplicate by notification ID.
Permanent delivery failures still follow the existing failed-workflow behavior.

Boolean conditions have no message and cannot describe changes to a matching set. Users must
return a stable message containing the relevant identities. The existing 1024-character message
limit still applies. Changes that produce identical stored text, including changes past that limit,
cannot be distinguished. Conditions that include time or other unstable values can produce an
alert on each analysis. No semantic risk classifier or unbounded history is added.

The project lock adds one round trip per reconciliation. Different projects can reconcile in
parallel. Same-project writers wait for the short reconciliation and outbox transaction. Policy
compilation, evaluation and HTTP delivery stay outside it. Direct callers that bypass the project
workflow must not race stale evaluations. The reconciliation lock serializes writes, not input reads.

Protobuf gains a new enum value and message without changing existing numbers or fields.
Rules store group names in a text array, so no schema migration or automatic subscription update
is required. Consumers opting into reviewed updates must understand group 26 and the optional review context.
New-event consumers must understand the new subject. Existing event payloads keep
their schema. Custom templates may need an explicit branch for the new group.

[ADR 043]: ./043-policy-condition-message-expression.md
[Issue 7649]: https://github.com/DependencyTrack/dependency-track/issues/7649
