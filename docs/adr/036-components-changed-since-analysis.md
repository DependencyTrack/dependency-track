| Status   | Date       | Author(s)                                              |
|:---------|:-----------|:-------------------------------------------------------|
| Proposed | 2026-08-10 | [@ElenaStroebele](https://github.com/ElenaStroebele) |

## Context

Vulnerability analysis for a project runs as the `AnalyzeProjectWorkflow`.
A BOM upload starts that workflow. Manual component create, update, and delete
through the API or UI do not. Findings and project metrics therefore stay at the
state of the last successful analysis until someone runs a manual reanalysis.

`PROJECT` already stores `LAST_VULNERABILITY_ANALYSIS`. That timestamp says when
analysis last finished. It does not say whether the component inventory changed
after that. The UI and API clients have no durable signal that findings and
metrics may be stale after a manual edit.

`COMPONENT` rows have no last-modified timestamp. There is no cheap way to derive
"inventory changed since analysis" from existing columns alone.

Important constraints:

* BOM import already triggers analysis, so marking those writes as stale would
  add noise without helping the user.
* Manual component edits must stay cheap. Starting a full analysis on every
  create, update, or delete was ruled out for this change.
* Project reads happen often. The signal must be cheap to return with a normal
  project fetch.

### Possible Solutions

#### A: Boolean column on `PROJECT`

Add `COMPONENTS_CHANGED_SINCE_ANALYSIS` as a non-null boolean that defaults to
`false`. Set it on manual component create, update, and delete. Clear it when
vulnerability analysis finishes, in the same write that updates
`LAST_VULNERABILITY_ANALYSIS`.

*Pro*:

1. One column, one cheap write on mutation, one cheap read with the project.
2. Clear lifecycle: set on inventory change, clear on successful analysis.
3. Fits the existing project JSON without a second round trip.

*Con*:

1. Needs a Flyway migration and a persistence-model change.
2. The flag is only as correct as the write paths that set and clear it.

#### B: Internal `PROJECT_PROPERTY`

Store the same signal as a project property, for example under an internal
group name. Set or clear that property on the same events as option A.

*Pro*:

1. No `ALTER TABLE` on `PROJECT`.

*Con*:

1. Heavier than a boolean column for a single bit of state.
2. Properties can appear in the Project Properties UI unless filtered.
3. Users with property edit rights can change or delete the value.
4. `GET /project/{uuid}` does not expose properties as a first-class field today,
   so the API or UI would need extra loading logic.

#### C: Derive the signal at read time

Compare component change times to `LAST_VULNERABILITY_ANALYSIS` when the project
is loaded.

*Pro*:

1. No stored flag to keep in sync.

*Con*:

1. Components have no last-modified timestamp, so this needs new columns on
   `COMPONENT` first, or another derived store.
2. Computing `MAX(changed_at)` over a large project on every read is more
   expensive than reading one boolean.

#### D: Start analysis on every manual component change

Treat create, update, and delete like a BOM upload and start
`AnalyzeProjectWorkflow` automatically.

*Pro*:

1. Findings and metrics stay current. No stale-state UI is needed.

*Con*:

1. Analysis is heavy. Small edits would start large work.
2. Changes the product behavior beyond a warning signal.
3. Out of scope for this decision.

## Decision

We will add a boolean column `COMPONENTS_CHANGED_SINCE_ANALYSIS` on `PROJECT`,
default `false`, and expose it on the project API as
`componentsChangedSinceAnalysis`.

We set the flag to `true` when a component is created, updated, or deleted
through the manual API and UI paths. BOM import does not set the flag, because
it already starts analysis.

We clear the flag to `false` when vulnerability analysis finishes successfully,
together with the update of `LAST_VULNERABILITY_ANALYSIS`. That clear path covers
manual reanalysis, scheduled analysis, and BOM-triggered analysis.

## Consequences

Clients can tell when a project's inventory changed after the last analysis
without scanning components.

New write paths that change the component inventory outside BOM import must set
the flag, or the signal becomes wrong. New analysis completion paths must clear
it through the same update that records `LAST_VULNERABILITY_ANALYSIS`, or the
warning will stick after a successful run.

The schema grows by one boolean on `PROJECT`. Fresh installs get the column from
the init migration. Existing installs get it from a follow-up Flyway script with
default `false`, so historical projects start unmarked.
