| Status   | Date       | Author(s)                                  |
|:---------|:-----------|:-------------------------------------------|
| Accepted | 2026-09-15 | [@fffinkel](https://github.com/fffinkel)   |

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

Before it evaluates any condition, the engine inspects all condition expressions of a project to
learn which fields they read, and loads only those fields for all components of the project. Any
mechanism that reads data the conditions do not read adds to this load for every component, even
though a message is only needed for the violated ones.

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

#### Option B: Separate message expression

Each policy condition gets a second, optional CEL expression that evaluates to a string. When the
condition is violated, the engine evaluates the message expression with the same variables the
condition had access to, and stores the resulting string on the violation. This is the approach used
by [Kyverno] and by Kubernetes [ValidatingAdmissionPolicy], where a `messageExpression` produces a
human-readable description of a failed validation.

Pros:

* Works for every subject, including `EXPRESSION`. Users decide what is relevant for their condition.
* The condition expression stays a plain boolean expression. Existing conditions are untouched.
* Reuses the CEL infrastructure that already exists for conditions and for notification filter
  expressions ([ADR 017](./017-notification-filter-expressions.md)).

Cons:

* The message expression largely duplicates the condition. To name the vulnerabilities that matched
  `vulns.exists(vuln, vuln.epss_score >= 0.5)`, the message expression has to repeat the same filter.
  The two can drift apart when one is edited and the other is not.
* It is a second evaluation per violated condition.
* Its data requirements are merged into the engine's requirements, so data that is only needed for
  messages is loaded for every component. Bounding that cost needs a restricted CEL environment for
  message expressions, with a list of allowed fields and functions that has to be maintained.
* It adds a column to the policy condition table and a field to the policy condition API.

#### Option C: Condition expressions may return a string

The condition expression itself is allowed to return either a boolean or a string. A boolean works
as today. A non-blank string means the condition matched and the string is the message. A blank
string means the condition did not match. The expression that decides the match also produces the
message, so there is only one expression and one evaluation.

Pros:

* Works for every subject, including `EXPRESSION`.
* No duplication. The filter that decides the match is the same filter that produces the message.
* No extra evaluation and no extra data loading. The message can only use data the condition reads
  anyway, so no restricted environment or allowlist is needed.
* No change to the policy condition table or the policy condition API. Only the violation gains a
  message.
* Existing conditions keep returning booleans and continue to work.

Cons:

* An `EXPRESSION` condition that wants a message has to be restructured. Instead of `exists`, it
  filters the set, binds the result to a variable, and returns a message or a blank string. This is
  more to write than a boolean expression.
* The result is free text, not structured data. Integrations that want to parse it need to agree on a
  format with the policy author.
* A blank string suppresses the violation. A message that is accidentally blank for a real match hides
  that match. Save-time validation cannot detect this.

#### Option D: Options A and B together

Add structured fields for legacy subjects and a separate message expression for everything else.

Pros:

* Covers all use cases.

Cons:

* Two mechanisms for one problem, with all the costs of options A and B.

## Decision

We will let policy condition expressions return a string in addition to a boolean (option C). We
will not add a separate message expression and we will not add structured matched-entity fields.

The result type of a condition expression must be `bool` or `string`. This is checked when an
`EXPRESSION` condition is created or updated, together with the checks that exist today. An
expression with any other result type, including one whose type cannot be determined statically, is
rejected in the same way an invalid expression is rejected today.

The engine interprets the result of a condition expression as follows:

* `true`: the condition is violated. The violation has no message. This is the behavior of today.
* `false`: the condition is not violated.
* A string that is not blank: the condition is violated. The string, with leading and trailing
  whitespace removed and truncated to 1024 characters, is the message of the violation.
* A blank string: the condition is not violated. This is equivalent to `false`.

Runtime failures are handled as today. If an expression fails during evaluation, the engine logs a
warning and treats the condition as not violated. The decision adds no new failure path, because
there is no second evaluation.

We will enable the CEL [bindings extension] for condition expressions. It provides `cel.bind`,
which assigns the result of a sub-expression to a variable. Without it, an expression that filters
a set and then both tests and prints the result has to repeat the filter. The extension is
available to every condition expression, not only to those that return a string. For example, an
`EXPRESSION` condition that names the vulnerabilities above an EPSS threshold reads:

```
cel.bind(
  matched,
  vulns.filter(vuln, has(vuln.epss_score) && vuln.epss_score >= 0.5),
  size(matched) > 0
    ? "EPSS >= 0.5 matched by: " + matched.map(vuln, vuln.id).join(", ")
    : ""
)
```

Legacy subjects get a message without user action. The builder that translates a legacy subject,
operator, and value into a CEL expression generates a string-returning expression where the
condition matches a set of entities, for example `EPSS`, `SEVERITY`, `CWE`, `VULNERABILITY_ID`,
`LICENSE`, and `LICENSE_GROUP`. Match and message come from the same generated expression, so they
cannot drift apart. For the `EPSS` condition "greater than or equal 0.5", the generated expression
is the one shown above. Where a legacy condition has no entity to name, for example a negated
condition such as "vulnerability ID is not X", the builder keeps generating a boolean expression and
the violation has no message. Legacy conditions cannot be given a custom message. Users who want
one convert the condition to an `EXPRESSION` condition.

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

Structured matched-entity data in notifications is out of scope for this decision.

## Consequences

Policy violation notifications become self-contained. A recipient can see which vulnerability,
license, or component value caused a violation without a follow-up API call. Legacy subject
conditions get this from the generated expression. `EXPRESSION` conditions get it once the user
rewrites the expression to return a string. Because the message is stored with the violation, the
scheduled summary notification shows the same message as the immediate notification, even when the
underlying data has changed since.

Writing a condition that returns a message is a power-user feature, like notification filter
expressions. Users need to know CEL, the structure of the `component`, `project`, and `vulns`
variables, and the `cel.bind` pattern. Such expressions are longer than boolean ones. The generated
expressions for legacy subjects double as documentation for how to write one. Existing `EXPRESSION`
conditions behave exactly as before.

The blank-string rule is a trade-off. It lets one expression both decide the match and produce the
message, but a logic error that yields a blank string for a real match suppresses the violation.
Save-time validation checks the result type, not the logic. Users should test a rewritten
expression against a project with known violations before relying on it. This is the same class of
risk as any other logic error in a condition expression.

The message is free text. Integrations that need structured data have to agree on a format with the
policy author, for example by producing JSON from the expression. This is a deliberate trade-off for
a single mechanism that covers all subjects.

Evaluation cost does not change. The message is a by-product of the evaluation that already runs,
and it can only use data the condition reads anyway. There is no second evaluation, no additional
data loading, and no restricted environment to maintain.

The policy condition table and the policy condition API do not change. The violation table changes
by one widened column. The `text` field on violations, which was always present but never populated,
now carries data. Both changes are additive and backward compatible.

The bindings extension becomes part of the CEL environment for all condition expressions. It is a
small, standard extension of CEL and has no cost when an expression does not use it. The
`EXPRESSION` validation becomes stricter in one respect: expressions whose result type is neither
`bool` nor `string` are rejected at save time. Today such expressions are accepted and fail at
evaluation time, so no working condition is affected.

[bindings extension]: https://github.com/cel-expr/cel-java/blob/main/extensions/src/main/java/dev/cel/extensions/README.md#celbind
[CEL]: https://cel.dev
[DependencyTrack/dependency-track#6553]: https://github.com/DependencyTrack/dependency-track/issues/6553
[Kyverno]: https://kyverno.io/docs/policy-types/validating-policy/#using-messageexpression-to-generate-dynamic-messages
[ValidatingAdmissionPolicy]: https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/
