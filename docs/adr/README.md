# Architecture Decision Records

This directory holds the project's [architecture decision records][ADR] (ADRs).

An ADR records an *architecturally significant* decision, one that affects the project's
structure, dependencies, interfaces, or qualities like performance, scalability, and security.
[`CONTRIBUTING.md`](../../CONTRIBUTING.md#architecture-decision-records) explains *when* an
ADR is required, and the rule that it must reach `Accepted` before its implementation pull
request can merge.

## Starting a new ADR

1. Copy [`000-template.md`](./000-template.md).
2. Number it in sequence. Take the highest existing number in this directory, add one, and pad with zeros to three digits.
3. Name the file `<number>-<title>.md` with `<title>` in kebab-case.
4. Fill in the header. Use today's date and the author's GitHub handle.

## Status

* `Proposed` while the decision is still under discussion.
* `Accepted` once the stakeholders agree. Required before the implementation pull request can merge.
* `Rejected` if the decision was discussed and turned down. Keep the file.
* `Deprecated` or `Superseded` when a later ADR changes the decision. Link to the replacement.

Small ADRs that land together with their implementation can start as `Accepted` when the design is not contested.

## Sections

**Context.** Describe the technical and operational pressures that motivate the decision.
These pressures often pull in different directions, say so when they do. Keep the language
factual, not opinionated. The recommendation belongs in `Decision`. When you compare real
alternatives, add a `### Possible Solutions` subsection. Give each option a sub-heading and
list its pros and cons. [ADR 001](./001-drop-kafka-dependency.md) is the canonical example.

**Decision.** State the response in active voice ("We will ..."). Name the chosen option
when the Context listed alternatives. Say clearly what is in scope and what is not.

**Consequences.** Describe what changes once the decision is in place. Cover the good, the
bad, and the neutral effects honestly.

**Follow-up (optional).** When later work adds detail to an `Accepted` ADR without changing
the decision, add a `## Follow-up (yyyy-mm-dd)` section to the same file.
[ADR 028](./028-hash-verification-computed-not-materialized.md) is an example. Write a new
ADR when the original decision is reversed, and link the two with `Superseded by` and
`Supersedes`.

## Writing style

* Write as if speaking to a future contributor. Use full sentences in paragraphs. Bullets are
  fine for lists, but do not use them to hide fragments.
* Use simple language at roughly [CEFR B1] level. Many readers are not native English
  speakers. Prefer common words over jargon, short sentences over long ones, and explain
  acronyms on first use unless they are obvious in the domain (for example BOM, URL, VEX).
* Stay at the architecture level. Refer to modules (`apiserver`, `notification-publisher`),
  subsystems, data stores, and external dependencies. Avoid class and method names unless
  the ADR is about a Java API.
* Keep each sentence short, but do not leave out important context. An honest ADR is more
  useful than a brief one.
* Keep punctuation simple. Em-dashes and semicolons usually stitch together clauses that
  read more clearly as two shorter sentences. Use a comma or a full stop instead.
* Define links at the bottom as `[Label]: url` and reference them inline as `[Label]`.
  [ADR 001](./001-drop-kafka-dependency.md) is the canonical example.
* Link other ADRs by relative path, for example `[ADR 007](./007-spec-first-rest-api-v2.md)`.
* Draw diagrams in [Mermaid] using fenced ` ```mermaid ` blocks. GitHub renders them
  natively, so the source stays diffable and reviewable in pull requests. Avoid embedded
  images for anything a diagram can express.

[ADR]: https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions
[CEFR B1]: https://www.coe.int/en/web/common-european-framework-reference-languages/table-1-cefr-3.3-common-reference-levels-global-scale
[Mermaid]: https://mermaid.js.org/intro/syntax-reference.html
