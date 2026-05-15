| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-05-04 | [@nscuro](https://github.com/nscuro) |

## Context

Sonatype's [*Open is not costless*][open-not-costless] post lays out the motivating concern: Public package registries
absorb increasing load from automated tooling, and operators are responding with rate limits and quota enforcement.
Dependency-Track is one such tool, and a single deployment can fan out to thousands of registry requests per refresh
cycle.

Package metadata is refreshed every 24 hours. Today every refresh issues an unconditional `GET`. All major registries
emit `ETag` and `Last-Modified`, but no resolver attaches conditional headers and no validators are stored between
refreshes. The result is repeated full-body transfers of documents that are usually unchanged.

The 13 resolvers do not share a uniform request shape. Most issue one request per resolution, a few hit
package-level and version-specific URLs, one (Composer) traverses a tree of include files, and one (Nixpkgs) downloads
a single channel index per repository on a fixed cadence.

Two industry patterns exist:

* Storing validators as columns on the resolved row fits when each row maps to one upstream URL.
* Storing them alongside cached bodies in a URL-keyed cache fits when one resolution touches many URLs,
  or when the unit of caching is the URL itself.

## Decision

Introduce HTTP conditional revalidation in the package metadata resolution path, keyed by URL.
The design follows Renovate's [`PackageHttpCacheProvider`][renovate-pkg-cache] as prior art.

### Caching and revalidation

Each resolver owns a URL-keyed cache holding the response body and its validators (`ETag`, `Last-Modified`).
Fresh entries are served without contacting the registry. Stale entries trigger a conditional `GET` per [RFC 9110][rfc9110].
A `304` replays the cached body, a `200` replaces it.

### Freshness and eviction

Freshness is governed by the upstream `Cache-Control` header (per [RFC 9111][rfc9111]) within a per-resolver cap.
Eviction is governed independently by the cache provider's TTL and must outlive freshness. Otherwise, no validators
would survive to revalidate with. This is Renovate's [soft / hard TTL][renovate-soft-hard-cache] split.

### Negative responses

`404` and `410` are cached as bodyless entries under the resolver's freshness cap. Resolution starts from a PURL
asserted to exist upstream, so a not-found typically reflects a misconfigured or wrong registry, not a transient
state worth revalidating per call.

### Storage

The cache reuses the existing [`cache`](../../cache) module.
Validators are deliberately not added to `PACKAGE_METADATA` or `PACKAGE_ARTIFACT_METADATA`
(see [ADR-015](./015-package-metadata.md)) since those tables model domain data, not HTTP responses, and resolvers do not
all map one row to one URL.

### Resolver-side reuse of prior domain data

Domain tables (see [ADR-015](./015-package-metadata.md)) already persist publish timestamps and hashes for previously resolved versions.
For immutable artifacts those values cannot change, so refetching them per cycle is wasted work, even with conditional
revalidation in place.

The orchestration layer surfaces the prior artifact metadata to the resolver as an opt-in hint. Orchestration
owns repository identity: it only forwards the hint when the prior was resolved from the repository currently
being attempted, since publish timestamps can legitimately differ across mirrors. The resolver owns version
stability: it decides whether the hint is safe to reuse for the requested version.

This benefits ecosystems that split latest-version and per-version metadata into separate requests.
Ecosystems that fetch a single document containing both must still fetch on every cycle and ignore the hint.

The boundary with ADR-015 is preserved: domain tables carry no HTTP validators, and resolvers retain
request-shape knowledge. The trade-off being that a resolver bug that produced wrong values won't self-heal
on the next refresh, requiring a one-time re-resolution or row purge to recover. This risk is outweighed by
the benefit of fewer requests to public infrastructure.

### Adoption

All resolvers adopt conditional revalidation, except Nixpkgs, which fetches a single channel index per repository on a
fixed cadence and would not benefit.

### Stale-on-error

When revalidation fails transiently, the cached body is served instead of propagating the error. Package metadata is
not strongly consistent: it refreshes on a 24h cadence and drives checks against artifacts that are themselves
immutable. A previously validated entry is not less trustworthy because the registry is briefly unreachable, and
falling back converts outages from workflow churn into a no-op. Renovate ships the same behavior under
[`cacheHardTtlMinutes`][renovate-hard-ttl].

The fallback covers network errors and retryable upstream statuses only. Protocol violations propagate, and bodyless
negative entries do not participate (a stale "not found" during an outage would mislead callers). The freshness
deadline is not refreshed on fallback, so the next call still attempts revalidation. The eviction TTL alone bounds the
stale window. The [RFC 9111][rfc9111] `stale-if-error` directive is not parsed because major registries do not emit it
and the eviction TTL is already authoritative.

### Rate-limit backoff

`429`, `503`, and `504` gate the host until `Retry-After` elapses (default 30s, capped at 5m). `Retry-After` accepts
delay-seconds or an HTTP-date per [RFC 9110][rfc9110]. Calls during the window serve stale cached values when possible,
and otherwise surface a retryable failure.

The gate is in-memory. Singleton workflow execution (see [ADR-015]) makes cross-instance coordination unnecessary,
although we may revisit this in the future.

Failover loses gate state and can re-trigger one burst, which is acceptable for an anti-thrashing aid.
Renovate ships the same pattern in [`lib/util/http/retry-after.ts`][renovate-retry-after].

## Consequences

Refreshes that would have transferred a full metadata document now exchange a conditional request and a small `304`
when nothing has changed. This reduces bandwidth and avoids re-parsing unchanged bodies. Whether `304` responses
actually count against rate-limit quotas depends on each registry's implementation. The prior-resolution hint described
above is what eliminates the per-cycle request entirely for stable artifacts, independent of registry policy.

Each adopting resolver previously kept a short-lived cache of parsed metadata structures. That cache becomes
redundant once the URL cache is in place, since both cover the same access pattern. Adopting resolvers drop the parsed
cache and re-derive structures from the cached body on each call. This removes a class of drift bug between parsed and
raw representations. The cost is microseconds of redundant parsing work per duplicated PURL within a batch.

[ADR-015]: ./015-package-metadata.md
[open-not-costless]: https://www.sonatype.com/blog/open-is-not-costless-reclaiming-sustainable-infrastructure
[renovate-hard-ttl]: https://docs.renovatebot.com/self-hosted-configuration/#cachehardttlminutes
[renovate-pkg-cache]: https://github.com/renovatebot/renovate/blob/main/lib/util/http/cache/package-http-cache-provider.ts
[renovate-retry-after]: https://github.com/renovatebot/renovate/blob/main/lib/util/http/retry-after.ts
[renovate-soft-hard-cache]: https://docs.mend.io/wsk/renovate-soft-and-hard-package-cache-behavior
[rfc9110]: https://www.rfc-editor.org/rfc/rfc9110
[rfc9111]: https://www.rfc-editor.org/rfc/rfc9111
