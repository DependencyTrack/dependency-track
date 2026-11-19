# Policy violation update notifications

`POLICY_VIOLATION` reports a newly created violation. Subscribe separately to
`POLICY_VIOLATION_UPDATED` to receive changes to the message of an existing violation.
The rule must be enabled and use the event trigger. Its existing project, tag, level, and
CEL filters still apply. Approved or suppressed violations stay excluded from this ordinary
update group. To receive message changes while a violation is approved or suppressed, explicitly
subscribe to `POLICY_VIOLATION_UPDATED_REVIEWED` instead, or subscribe to both update groups
to cover both classes. Neither group clears review decisions or extends the scheduled summary
groups. Existing rules are not subscribed to the reviewed group automatically.

A reviewed violation has analysis state `APPROVED` or suppression `true`. A `REJECTED`,
unsuppressed violation still belongs to the ordinary update group. Each message transition
chooses exactly one group, so a rule subscribing to both gets one event. These are message
change events, including removals and wording changes, not a claim that risk always increased.
Changing a decision alone, adding a subscription or clearing suppression does not replay an
older message change. A later message change is evaluated with the review context then observed.

For a component policy with subject `EXPRESSION`, a basic KEV message is:

```cel
vulns.filter(v, v.is_kev).map(v, v.id).join(",")
```

A non-empty string means a match and is saved as the message. No active KEVs produces
an empty string, so the violation disappears. Vulnerabilities enter this expression in stable
database identity order. A Boolean expression such as `vulns.exists(v, v.is_kev)` can still be
used, but has no message to change when a second KEV appears. Do not include `now` or
random data in messages used as change signals. Messages retain the existing 1024-character
limit. Equal stored messages cannot distinguish different underlying sets.

The new subject type is
`org.dependencytrack.notification.v1.PolicyViolationUpdatedSubject`. Its fields are:

- `project`, `component`, and `policy_violation`, including the original violation UUID and
  policy condition. `policy_violation.message` holds the current message when non-null.
- Optional `previous_message` and `current_message`. An absent field means null, while a
  present empty string is empty text. Protobuf JSON uses `previousMessage` and `currentMessage`.
- `changed_at`, the time of the reconciliation statement on the database server.
- Optional `analysis_state` and `suppressed`, captured together from one SQL snapshot during
  subject assembly for reviewed-group events. Present `false` means explicitly unsuppressed.
  An absent field means no captured value; ordinary-group events retain their original shape
  and omit review metadata. Decisions may change later without altering this historical event.

An example notification filter is
`has(subject.current_message) && subject.current_message.contains('CVE-2021-45046')`.
An arbitrary text change is not proof of a new KEV. Added and removed identifiers are not
parsed from policy text. Set a filter appropriate to the policy and destination. Existing
JSON webhook templates serialize the structured subject. Default human-readable templates
show previous and current text. Custom templates should add an explicit update-group branch.

A repeated evaluation with unchanged text creates no update event. A removed violation
that reappears gets a new UUID and the ordinary creation event. Message changes and their
outbox event commit atomically. HTTP delivery happens later through the normal notification
workflow. Transient failures can retry the same notification ID. Receivers should deduplicate
that ID; this is not an exactly-once HTTP guarantee. Check failed workflows after permanent
failures according to the existing operational procedures.

This implementation needs no schema migration. Existing group numbers and configured
subscriptions stay unchanged. Older consumers should continue processing the original group;
consumers newly subscribing to updates need support for the new group and subject. The reviewed
update group uses Protobuf value 26 and the same subject type with additive optional fields.
A rule can use `has(subject.analysis_state) && subject.analysis_state == 'APPROVED'` or
`has(subject.suppressed) && subject.suppressed` to narrow the reviewed events it receives.
Presence checks distinguish an absent value from a recorded value. Normal project, tag and
group subscriptions still apply; a CEL
filter cannot turn an ordinary-group subscription into a reviewed-group subscription.
