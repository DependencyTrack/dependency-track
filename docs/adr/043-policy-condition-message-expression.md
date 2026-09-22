| Status   | Date       | Author(s)                                  |
|:---------|:-----------|:-------------------------------------------|
| Proposed | 2026-09-15 | [@fffinkel](https://github.com/fffinkel)   |

## Context

When a policy condition is violated, Dependency-Track records a policy violation and sends a
`POLICY_VIOLATION` notification. The violation and the notification carry the condition that was
violated (subject, operator, configured value), the affected component, and the project. They do not
carry the data that caused the match.

For conditions that look at a set of things, this is a real gap. A component may have several
vulnerabilities above an EPSS threshold, or several vulnerabilities of a given severity. The
recipient of the notification cannot tell which one triggered the violation. A follow-up API call
does not help, because the set may have changed since the evaluation ran, and because the API does
not know which entity the condition matched either. The same applies to license conditions, where
the recipient has to look up the component to learn which license was found.
[DependencyTrack/dependency-track#6553] describes this problem in detail.

The policy engine evaluates every condition as a [CEL] (Common Expression Language) expression that
returns `true` or `false`. Legacy subjects such as `EPSS`, `SEVERITY`, or `LICENSE` are translated
into CEL expressions of the form `vulns.exists(vuln, vuln.epss_score >= 0.5)`. The `EXPRESSION`
subject lets users write the CEL expression themselves. In both cases the engine only learns that a
condition matched, not what matched.

A violation is stored as the pair of component and condition, plus type and timestamp. Both
notification paths read violations from the database rather than from the engine's memory. The
`POLICY_VIOLATION` notification is assembled right after evaluation. The
`NEW_POLICY_VIOLATIONS_SUMMARY` notification is assembled later by a scheduled rule, possibly hours
after the evaluation. Any detail that should appear in notifications therefore has to be captured at
evaluation time and persisted with the violation.

### Possible Solutions

#### Option A: Structured matched-entity fields

The engine resolves the matched entities for each legacy subject and stores them as structured data
on the violation. Vulnerability subjects would store the matched vulnerabilities, license subjects the
matched license, and component subjects the matched component value. The notification schema gains
typed fields for each kind of entity.

Pros:

* Downstream integrations receive machine-readable data.
* No user action is needed. Existing conditions gain the detail automatically.

Cons:

* Each legacy subject needs its own resolution logic in the engine, separate from the CEL expression
  that decides the match. The two must be kept in sync by hand.
* The `EXPRESSION` subject cannot be supported. An arbitrary expression has no single matched entity.
  Since the project steers users towards `EXPRESSION` conditions and away from legacy subjects, the
  feature would not cover the preferred way of writing policies.
* The notification schema and the violation table need a new field for every kind of entity. Adding a
  new subject means touching the schema again.

#### Option B: Message expression

Each policy condition gets an optional CEL expression that evaluates to a string. When the condition is
violated, the engine evaluates the message expression with the same variables the condition itself
had access to, and stores the resulting string on the violation. Notifications include the string.
This is the approach used by [Kyverno] and by Kubernetes [ValidatingAdmissionPolicy], where a
`messageExpression` produces a human-readable description of a failed validation.

Pros:

* Works for every subject, including `EXPRESSION`. Users decide what is relevant for their condition.
* One mechanism for all subjects. No per-subject resolution logic in the engine.
* One new string field on the violation and in the notification schema. New subjects or new
  vulnerability fields need no further schema change.
* Uses the CEL infrastructure that already exists for conditions and for notification filter
  expressions ([ADR 017](./017-notification-filter-expressions.md)).

Cons:

* Users must write the message expression themselves. Conditions without one gain nothing.
* The result is free text, not structured data. Integrations that want to parse it need to agree on a
  format with the policy author.

#### Option C: Both

Add structured fields for legacy subjects and a message expression for everything else.

Pros:

* Covers all use cases.

Cons:

* Two mechanisms for one problem, with all the costs of option A.

## Decision

We will add an optional message expression to policy conditions (option B). We will not add
structured matched-entity fields.

A message expression is a CEL expression that must evaluate to a string. It is stored as a new
nullable text column on the policy condition table and exposed as a new optional field on the
policy condition in the REST API. The expression is limited to 2048 characters, the same limit as
notification filter expressions.

The expression is validated when a condition is created or updated. It is compiled against the same
CEL environment as the condition, and its result type must be `string`. An invalid expression is
rejected with an [RFC 9457] problem details response, in the same way invalid `EXPRESSION` conditions
are rejected today.

The policy engine evaluates the message expression only for conditions that were violated. It uses
the same variables as the condition: `component`, `project`, `vulns`, and `now`. The fields the
message expression reads are added to the engine's data requirements, so the data is loaded together
with the data the conditions need and no extra database queries are issued per component. The
resulting string is truncated to 1024 characters and stored on the violation. Since the same
condition applies to every component, message expressions have to use CEL to select what is relevant.
For example, a condition `vulns.exists(vuln, vuln.epss_score >= 0.5)` may use the message expression:

```
"EPSS >= 0.5 matched by: " + vulns.filter(vuln, vuln.epss_score >= 0.5)
  .map(vuln, vuln.id + " (EPSS " + string(vuln.epss_score) + ")").join(", ")
```

Evaluation of a message expression never affects whether a violation is recorded. If the expression
fails at runtime, the engine logs a warning, records the violation without a message, and continues.
A broken message expression must not hide a violation.

The violation table already has an unused nullable `TEXT` column of 255 characters, inherited from
v4. We will widen this column to unbounded text and use it for the message. The violation model
already exposes this column as `text` in the v1 REST API, so violations gain the message in the API
without a change to the API shape. When the engine re-evaluates a project and a violation already
exists, the stored message is updated if the newly evaluated message differs. The violation itself,
including its timestamp and analysis, is kept.

The notification schema gains an optional `message` string on the `PolicyViolation` message used by
`POLICY_VIOLATION` notifications, and on the per-violation entry used by
`NEW_POLICY_VIOLATIONS_SUMMARY` notifications. Both are read from the stored violation. The default
notification templates for email, Slack, Microsoft Teams, and Mattermost print the message when it is
present.

Out of scope for this decision:

* Default message expressions for legacy subjects. The engine could generate a sensible message for
  `EPSS`, `SEVERITY`, or `LICENSE` conditions when the user did not provide one. This is a possible
  follow-up and does not change the mechanism decided here.
* Structured matched-entity data in notifications.
* The frontend. The policy condition form needs an input for the message expression and the
  violation views should show the message. This work happens in the frontend repository.

## Consequences

Users can make policy violation notifications self-contained. A recipient can see which
vulnerability, license, or component value caused a violation without a follow-up API call. Because
the message is stored with the violation, the scheduled summary notification shows the same message
as the immediate notification, even when the underlying data has changed since.

Message expressions are a power-user feature, like notification filter expressions. Users need to know
CEL and the structure of the `component`, `project`, and `vulns` variables. Documentation with
examples for the common cases (EPSS, severity, license) will matter for adoption. Conditions without
a message expression behave exactly as before.

The message is free text. Integrations that need structured data have to agree on a format with the
policy author, for example by producing JSON from the message expression. This is a deliberate
trade-off for a single mechanism that covers all subjects.

The policy condition table and the violation table each change by one column. The v1 REST API for
policy conditions gains an optional field. Both changes are additive and backward compatible. The
`text` field on violations, which was always present but never populated, now carries data.

Each violated condition with a message expression costs one additional CEL evaluation per component.
Conditions that are not violated and conditions without a message expression cost nothing extra. The
data requirements of message expressions are merged into the existing preload, so the number of
database queries per evaluation does not change.

The fail-open behavior means a broken message expression produces violations without a message and a
warning in the logs. Save-time validation catches syntax and type errors, so runtime failures are
limited to cases such as missing optional fields.

[CEL]: https://cel.dev
[DependencyTrack/dependency-track#6553]: https://github.com/DependencyTrack/dependency-track/issues/6553
[Kyverno]: https://kyverno.io/docs/policy-types/validating-policy/#using-messageexpression-to-generate-dynamic-messages
[RFC 9457]: https://www.rfc-editor.org/rfc/rfc9457
[ValidatingAdmissionPolicy]: https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/
