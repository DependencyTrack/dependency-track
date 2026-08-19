| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-07-07 | [@nscuro](https://github.com/nscuro) |

## Context

[ADR 036] addressed the count on the v1 finding list endpoints. This ADR addresses the lists themselves,
i.e. the queries behind the portfolio-wide `GET /v1/finding` and `GET /v1/finding/grouped` endpoints.

> [!NOTE]
> For perspective: Dependency-Track v4 did not paginate these endpoints in the database *at all*.
> The queries ran without a limit, the server loaded the entire result set into memory,
> and cut the requested page out of it there. Every request paid the cost of the full
> portfolio, *even for the first page*, and the server's memory capped how large a portfolio
> could get. The v5 queries push pagination into the database, which raises that ceiling.

In the default order, the list query walks an index and stops at the requested page.
On a 100 million finding dataset, it returns in tens of milliseconds.
However, the endpoints also offer ~15 sortable columns, and some of the sort keys are
computed at read time rather than stored:

* Severity and CVSS combine an analysis override with the vulnerability's own value.
* EPSS is resolved through aliases (see [ADR 022]).

No index can cover a computed key. Sorting by one forces the database to compute the key for *every* matching finding,
and sort the whole set, before it can return the first page. On the same dataset,
sorting by severity does not finish within 90 seconds. Unindexed filters behave the same way,
as does access control that grants a user only a few projects.

In their current shape, with arbitrary sorts, filters, and aggregations over the entire portfolio,
these endpoints are an analytical workload. Our schema is built for transactional processing,
which is a poor fit for this kind of workload once the data gets large.
None of the solutions below removes this mismatch.

### Constraints

* The "Vulnerability Audit" page works well on the small and medium portfolios that are the large majority.
  The solution must not degrade that.
* On very large portfolios, the runtime of the expensive operations is effectively unbounded today.
  The solution must bound it.
* The database is a security record. It must reflect current suppression and analysis state.
  Any solution that trades freshness for speed has to justify the staleness.

### Possible Solutions

#### A: Denormalize the resolved fields onto a finding row

*Pro*:

1. Sorts and filters become index-backed, and can stop early once the requested page is full.

*Con*:

1. EPSS reloads daily. In Postgres, an update rewrites the entire row, so the reload would rewrite tens of millions
   of rows every day. This is the same objection as in [ADR 028].
2. Denormalizing only the stable fields (mainly the resolved severity) avoids the write cost,
   but access control still forces a scan when a user only sees a small slice of the portfolio.
3. All other computed sort keys would still need a timeout boundary,
   so the added write-path complexity does not buy a simpler system.

#### B: Materialized view, refreshed on a schedule

*Pro*:

1. The expensive join runs off the request path.

*Con*:

1. A refresh recomputes the entire join, which is the very scan we want to avoid,
   now on a schedule. Postgres has no incremental refresh.
2. On the 100 million finding dataset, the initial populate did not finish within tens of minutes.
3. The view would often be refreshed more often than it is read.
4. The view's snapshot is stale between refreshes. This matters, because suppression and analysis state must be current.

#### C: Replace the page with an asynchronous report

*Pro*:

1. Entirely drops the expectation of an instant answer over the whole portfolio.

*Con*:

1. The page works fine for the large majority of deployments.
   Turning it into a report downgrades everyone, only to accommodate the extreme tail.

#### D: Drive vulnerability-grain sorts from the vulnerability side

EPSS and KEV are properties of the vulnerability, and the number of distinct vulnerabilities is far smaller than the number of findings.
A sort by such a key can walk vulnerabilities in key order, expand each into its visible findings, and stop once the page is full.

*Pro*:

1. Measured on the 100 million finding dataset: the EPSS sort returns in about 1.3 seconds,
   where the finding-driven query does not finish within 120 seconds.

*Con*:

1. For a user whose access only grants a small slice of the portfolio,
   the walk expands millions of rows to fill a single page, and does not finish either.
2. Serving both cases means routing on how many projects the user can see, i.e. two query paths for one endpoint.
3. It only covers vulnerability-grain sort keys, so a timeout boundary is needed regardless.

#### E: Offload the workload to a dedicated search datastore

Search engines such as [OpenSearch] are built for exactly this kind of workload,
as are analytical databases such as [ClickHouse]. Findings would be continuously
synchronized into the external datastore, and the endpoints would query it instead of Postgres.

*Pro*:

1. Arbitrary sorts, filters, and aggregations become fast at any portfolio size.
2. This is the standard industry answer for running search and analytics next to a transactional database.

*Con*:

1. It requires new infrastructure. We removed Kafka precisely to reduce the operational burden on users
   and on our community support ([ADR 001]), and are not willing to walk that back at this time.
2. The synchronization pipeline is a system of its own, with its own failure modes and monitoring needs.
3. The synchronized copy is stale between syncs. This is the same objection as for
   [option B](#b-materialized-view-refreshed-on-a-schedule), but with more moving parts.

## Decision

We will keep serving portfolio-wide finding lists from live queries, and degrade gracefully as data grows,
rather than build a materialized, denormalized, or externally synchronized read model.

All rejected options move the cost of the portfolio-wide scan off the request path,
and pay for that with staleness, write amplification, or new infrastructure.

We keep the cost on the read path instead, where only the queries that need it pay for it.

* The default view stays live and fast at any size: default order, combined with the bounded count from [ADR 036].
* Expensive operations are bounded by the platform's global query timeout
  (`dt.datasource.query-timeout-ms`, 60 seconds per default).
  Requests that exceed it fail with `504` instead of hanging.
  This applies to *every* findings request, including default requests that do not opt into the bounded count.
  The error message advises to retry with the bounded count, which can resolve a timed-out exact count.
* The SARIF and FPF exports must return *all* findings, so no other remediation applies
  to them, and they are subject to the timeout as well. Exports too large for the timeout
  budget need streaming or bounding, which would be follow-up work.
* If a deployment needs fast arbitrary sorts later, we can still add an optional,
  size-gated snapshot.
* We do not build [option D](#d-drive-vulnerability-grain-sorts-from-the-vulnerability-side) now,
  due to the cons listed above. It is however the measured path to restoring the portfolio-wide EPSS sort,
  so we defer it as follow-up.

For a timed-out sort, there is no remediation we can offer.
We initially assumed that applying a filter would make an expensive sort viable again by shrinking the result.
However, measurement showed that filtering narrows what is *returned*, not what must be scanned and sorted.

For sorting by severity the loss is small. Millions of findings share the same few severity values,
so the first page is mostly noise anyway. Continuous sort keys like the EPSS score are different.
Their first page is a portfolio-wide triage worklist, and no filter can narrow it down
without changing what the result means.

> [!NOTE]
> For very large portfolios, that workflow never worked.
> The timeout only makes its failure explicit. We accept this gap for now.

## Consequences

* Small and medium portfolios are unaffected. The page, every sort, and the exact count keep working,
  with no added infrastructure, storage, or staleness.
* Very large portfolios keep the same page and a fast default view. Expensive sorts hit the timeout,
  whether filtered or not. No feature is removed, and there is no separate product for large tenants.
* The boundary is a timeout, so it is not a sharp line. The same query can pass with a warm cache and fail under load,
  and portfolios near the limit will see intermittent `504` responses.
  A deterministic guard, e.g. rejecting a sort when the estimated result is too large, would draw a sharper line.
  However, it would require an estimator that can fail in both directions, and it would only catch the query shapes
  it can predict. We accept the fuzziness, in exchange for a bound that catches every expensive request.
* The frontend must opt into the bounded count, as otherwise the default view still requests an exact count,
  which times out on the portfolios this ADR is about. The frontend change is part of this work.

### Hardware Considerations

The numbers in this ADR come from a reference machine that gives Postgres HDD storage and about 3 GB of cache,
for a 45 GB dataset. The scan-heavy numbers are therefore pessimistic.
For the largest portfolios, more memory and faster storage are a legitimate part of the solution.
While hardware does not change the growth curve, it can be the difference between failing the timeout budget and fitting it.

The timeout is the platform's global ceiling, not a per-endpoint knob.
Every endpoint inherits it, and operators who invest in hardware can raise it to match.

We acknowledge that this hand-waves the underlying mismatch rather than solving it.

### REST API v2

The long-term answer remains the v2 finding endpoint.
The [v2 API] already prescribes keyset pagination and a total that states its own type.
The measurements in this ADR outline what that endpoint should look like:

* The flat list only offers sorts that a stored, indexed key can serve, so every offered sort stops early.
  Comparable products made the same trade-off:
    * [GitHub's][GitHub alerts] organization-wide alert list offers three stored sort keys and cursor pagination only.
    * [GitLab][GitLab report] limits the counts on its vulnerability report to a fixed bound.
* The grouped view moves to vulnerability grain. Distinct vulnerability counts are in the hundreds of thousands,
  where findings are in the hundreds of millions. A query that picks the page of vulnerabilities first,
  and only then expands it into its aggregates, touches only what it returns.
  This is [option D](#d-drive-vulnerability-grain-sorts-from-the-vulnerability-side),
  applied to the grouped view. Measured at ~1/10th of the reference dataset,
  the sorted grouped page drops from about 100 seconds to well under a second.
  Even a sort key without an index stays in that range, because the cost scales with the page size,
  not with the portfolio size.
* Aggregates such as the affected project count are computed live, for the current page only.
  We do not store them. Every write that touches a popular vulnerability would rewrite its stored count,
  which causes bloat and contention.
* This requires the group key to be the vulnerability alone. The v1 grouped endpoint also keys on per-finding values,
  such as the analyzer identity and analysis overrides. That is what forces it to aggregate the whole portfolio before
  the first sorted page. The contract cannot change for API v1, so the vulnerability-grain view is a v2 change,
  and the v1 endpoints keep the timeout as their boundary.
* A user whose access only grants a small slice of the portfolio still degrades,
  as with [option D](#d-drive-vulnerability-grain-sorts-from-the-vulnerability-side).

[ADR 001]: ./001-drop-kafka-dependency.md
[ADR 022]: ./022-read-time-epss-resolution-via-alias.md
[ADR 028]: ./028-hash-verification-computed-not-materialized.md
[ADR 036]: ./036-api-v1-opt-in-partial-counts.md
[ClickHouse]: https://clickhouse.com/
[GitHub alerts]: https://docs.github.com/en/rest/dependabot/alerts
[GitLab report]: https://docs.gitlab.com/user/application_security/vulnerability_report/
[OpenSearch]: https://opensearch.org/
[v2 API]: ../../api/src/main/openapi/openapi.yaml
