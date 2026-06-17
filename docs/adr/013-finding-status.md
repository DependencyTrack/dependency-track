| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-02-12 | [@nscuro](https://github.com/nscuro) |

## Context

Findings are expressed as records in the `COMPONENTS_VULNERABILITIES` table.
The table is a simple junction table with the following schema:

| Column           | Type   | Constraints |
|:-----------------|:-------|:------------|
| COMPONENT_ID     | BIGINT | PK, FK      |
| VULNERABILITY_ID | BIGINT | PK, FK      |

For each finding, additional metadata is recorded in the `FINDINGATTRIBUTION` table:

| Column           | Type        | Constraints  |
|:-----------------|:------------|:-------------|
| ID               | BIGINT      | PK           |
| PROJECT_ID       | BIGINT      | FK, NOT NULL |
| COMPONENT_ID     | BIGINT      | FK, NOT NULL |
| VULNERABILITY_ID | BIGINT      | FK, NOT NULL |
| ANALYZERIDENTITY | TEXT        | NOT NULL     |
| ATTRIBUTED_ON    | TIMESTAMPTZ | NOT NULL     |
| ALT_ID           | TEXT        |              |
| REFERENCE_URL    | TEXT        |              |
| UUID             | UUID        | NOT NULL     |

Only a single `FINDINGATTRIBUTION` record can exist for each `COMPONENTS_VULNERABILITIES` record.
This is enforced using a `UNIQUE` constraint on the `COMPONENT_ID, VULNERABILITY_ID` columns.

Consequently, only the first analyzer that reported a finding gets an attribution.

So far this design has been sufficient, because findings were only *added*, but never *removed*.

This does not reflect reality though:

* Vulnerability databases get updated, vulnerable version ranges get revised.
* Upstream analyzers such as OSS Index correct their data in response to FP reports.
* Users disable analyzers that they no longer want to use.

In any of the cases above, findings would need to be *removed*.
The current design makes this challenging to do. Consider the following sequence of events:

1. Analyzer **A** reports vuln **X** on component **C**. An attribution is created for analyzer **A**.
2. Analyzer **B** also reports vuln **X** on component **C**.
   No attribution is created because there already is one for analyzer **A**.
3. Analyzer **A** stops reporting the finding. Analyzer **B** still reports it.
   We can't safely remove the finding because we never tracked which analyzer other than **A** reported it.

Additionally, we can't just *delete* finding records:

* It would achieve the desired effect, but would leave users who check timeseries metrics
  behind wondering *what the hell happened*.
* Findings may already have an audit trail with user comments etc., which would be wiped.
  If a finding is later re-discovered (e.g. by an analyzer being re-enabled),
  the audit trail no longer being there would be confusing.

## Decision

* Modify the `FINDINGATTRIBUTION` table such that all analyzers that reported a finding are
  tracked, not just the first. Modify the `UNIQUE` constraint to include the `ANALYZERIDENTITY`.
* Use soft-deletion for `FINDINGATTRIBUTION` records. Introduce a new `DELETED_AT` column for this.
  When an analyzer no longer reports a finding, update its attribution's `DELETED_AT` timestamp accordingly.
* Never delete `COMPONENTS_VULNERABILITIES` records, unless the corresponding `COMPONENT` record is deleted.
  This resembles the status quo and is necessary to retain attributions.
* When analyzers report a finding again, unset their attribution's `DELETED_AT` column.
* Consider findings with *at least one* `FINDINGATTRIBUTION` record where `DELETED_AT`
  is `NULL` as *active*.
* Consider findings with only deleted `FINDINGATTRIBUTION` records as *inactive*.
* Hide *inactive* findings by default. Eventually add API parameters and UI elements to show them.
* To avoid breaking changes in the REST API, continue to only report a single attribution per finding.
  The attribution to report is the *first, non-deleted one* (first meaning lowest `ID`), or, 
  if all attributions are deleted, the *last deleted* one.

This enables findings to transition between *active* and *inactive* status
without dropping or otherwise modifying their audit trail.

By using soft-deletion for `FINDINGATTRIBUTION` records, we retain a history of
what analyzers previously reported a finding, but no longer do. We could further
surface this data to users, enabling them to see where analyzers overlap.

### Considered Alternatives

It was considered to automatically *suppress* findings that are no longer reported by
any analyzer. This was discarded because it made coordination of who "owns" the analysis
of a finding challenging. i.e.:

1. Finding gets reported.
2. User suppresses finding.
3. Finding is no longer reported, but already suppressed so no action.
4. Finding gets reported again, but is it safe / OK to un-suppress without user consent?

It would have also mixed two different concerns, i.e. a finding being applicable at all,
and it being applicable but suppressed.

## Consequences

* Reconciliation logic of findings and finding attributions must be updated.
* Queries for listing findings must be updated to not produce duplicate rows
  when more than one attribution exists for a finding.
* Queries that return attribution data must be updated to only return one
  attribution, not multiple.

