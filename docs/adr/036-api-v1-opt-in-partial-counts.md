| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-07-03 | [@nscuro](https://github.com/nscuro) |

## Context

Paginated REST API v1 list endpoints return the exact number of matching records in the
`X-Total-Count` response header. The count is computed in the same query that returns the
requested page. This means the database must scan *all* matching records before it can
return even the first page.

For small result sets this is cheap. But the cost grows with the result set.
At some size, every exact count becomes too slow. The only approach that keeps working
at any size is to stop counting after a fixed limit. Such a bounded count caps the cost of counting,
independent of how many records match.

A cheaper alternative would be to use the query planner's row estimate, as offered by
[PostgREST] for example. We decided against it though:

* Portfolio access control and finding filters skew the planner statistics heavily.
* The estimate relies on table statistics, which lag behind under high churn.
* An estimate cannot communicate its own error margin. Clients have no way to tell a good estimate from a bad one.
* A bounded count is deterministic. It is either exact, or a guaranteed lower bound.

The [v2 API] supports partial counts through a `total` that states its own type.
That is the direction we already decided on.

However, the v1 API contract must not break. Many integrations expect `X-Total-Count`
to be exact, so exact counts must remain the default behavior.
The immediate pressure comes from the portfolio-wide finding list endpoints,
where the result set is by definition the whole portfolio.

## Decision

We will allow clients to opt into a partial count, per endpoint and per request.
Clients that do not opt in get the same exact `X-Total-Count` as before.

### Opt-In Contract

The opt-in is expressed with a new `totalCount` query parameter. A new `X-Total-Count-Type`
response header communicates what kind of count the client got. Endpoints that offer the
opt-in return the header on *every* paginated JSON collection response, so clients that do not
opt in see `EXACT`. The grouped finding endpoint is the one exception, described below.
Responses that are not paginated carry neither header. Today that is only the SARIF
variant of `GET /v1/finding/project/{uuid}`.

| `totalCount` value | Counting behavior                     | Resulting `X-Total-Count-Type`                                                                                                                   |
|:-------------------|:--------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| `EXACT` (default)  | Count all matching records.           | `EXACT`                                                                                                                                          |
| `BOUNDED`          | Stop counting at a server-side limit. | `EXACT` if the count completes within the limit or the requested page determines the total, otherwise `AT_LEAST`, never below the end of the requested page |

When the header reports `AT_LEAST`, `X-Total-Count` is only a lower bound of the true total.

Noteworthy details:

* The parameter names the counting *mode*, not the limit. The limit is determined by the server,
  so clients cannot raise it and force a slow full scan. Each endpoint chooses its own.
* The parameter values and the header follow the wording of the v2 API's `total`.

### Finding List Endpoints

`GET /v1/finding` and `GET /v1/finding/project/{uuid}` are the first endpoints to offer the opt-in,
because the exact count hurts them the most. Their limit is 10k. Most portfolios have fewer findings than that,
so most deployments keep an exact total. Only the largest portfolios see a lower bound.

### Grouped Finding List Endpoint

`GET /v1/finding/grouped`, which returns findings grouped by vulnerability,
offers the opt-in as well, but with a weaker guarantee.

We first assumed a bounded count could not help this endpoint, because the aggregation
would need to materialize every group anyway. Measurement showed the opposite:

* In the default order, which is by the vulnerability's internal ID and thus by the grouping key
  itself, the database streams the groups and stops at the requested page.
  On a 100 million finding dataset, this completes in about a second.
* It is the *exact count* that forces aggregating the whole portfolio first, which runs for minutes on the same dataset.
* A capped count does not fit either. Counting a group means reading all of its findings.
  A cap of 10k groups read five million findings on that dataset.

With `BOUNDED`, the endpoint therefore skips the count *entirely*, and reports what the requested
page itself proves: `EXACT` when the page ends the result set, `AT_LEAST` otherwise. A page past
the end proves nothing at all and reports `AT_LEAST` zero. This is the weakest guarantee we can offer,
but it is the only variant of the grouped view that works regardless of portfolio size.

A page past the end is the one case where `EXACT` is not exact. The other endpoints resolve
the count from a window function over the page, which returns nothing on an empty page,
and fall back to a count query. The grouped endpoint has no affordable count query,
so it reports `AT_LEAST` zero instead of a made-up total.

This only applies to the default order. Sorted requests do not stream,
even on indexed vulnerability columns. We measured that the database aggregates every group
before it can return the first sorted page. Grouped sorts therefore keep hitting the timeout
boundary, with or without the opt-in.

Other v1 endpoints can adopt the opt-in later, without requiring a new contract.

## Consequences

* Clients with large result sets can opt in to get a fast response, at the cost of an exact total they rarely need at that size.
* Existing integrations are unaffected, since clients ignore response headers they do not know.
* None of this takes effect until clients send the parameter.
  Updating the frontend to opt in is therefore part of this work.
* Browsers only let scripts read response headers listed in `Access-Control-Expose-Headers`.
  The default of the `dt.cors.exposed-headers` property must include `X-Total-Count-Type`.
  Operators who override that property must add the header themselves. Upgrade notes must state this.

[PostgREST]: https://docs.postgrest.org/en/stable/references/api/pagination_count.html
[v2 API]: ../../api/src/main/openapi/openapi.yaml
