# Portfolio Access Control

Portfolio Access Control (PAC) is an opt-in, row-level authorization mechanism for project-scoped data.
When PAC is enabled, a principal can only see and act on a project if a team they belong to is granted access to
that project or to one of its ancestors. The user-facing concepts (teams, project inheritance, configuration)
are documented on the [public concepts page].

This guide is for contributors. It covers how PAC is implemented, how to apply it correctly in new code,
and how to bypass it when that is the right thing to do.

> [!IMPORTANT]
> PAC controls **access**, not **permissions**. The set of permissions a principal holds is independent of which
> projects they can reach. There are no per-project permissions.

## Toggle and bypass permission

PAC is controlled by a single configuration property, `access-management.acl.enabled`,
defined as `ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED`. The default is `false`.
When the property is `false`, all enforcement layers below short-circuit and behave as if every
principal can access every project.

A principal that holds the `PORTFOLIO_ACCESS_CONTROL_BYPASS` permission bypasses PAC even when it is enabled.
This is meant for administrators and trusted automation.

## Data model

Three tables hold the access state:

* **`PROJECT_ACCESS_TEAMS` (PAT).** The source of truth. Each row pairs a project with a team that has been granted
  access to it. Users and API keys gain access through the teams they belong to.
* **`PROJECT_ACCESS_USERS` (PAU).** A denormalised view of PAT joined with `USERS_TEAMS`.
  It exists so that user-scoped queries can avoid an extra join. Triggers keep it in sync with PAT and `USERS_TEAMS`.
  Direct writes are blocked by the database trigger `prevent_direct_project_access_users_writes`.
* **`PROJECT_HIERARCHY` (PH).** A closure table over the `PROJECT` tree. Each project has a self-row at depth zero.
  Access on a parent is inherited by every descendant. The table is maintained by triggers on `PROJECT`.

The access predicate is the same in every layer: a row in PAT (for API keys) or PAU (for users) exists for some ancestor
of the target project, *including the project itself*, reachable through PH.

## Enforcement layers

Four independent layers enforce PAC.

### 1. JDBI list queries

`ApiRequestStatementCustomizer.defineProjectAclCondition` runs for every JDBI `Handle` opened with a non-`null`
`AlpineRequest`. It exposes a FreeMarker attribute called `apiProjectAclCondition` to the SQL template.
DAO methods interpolate the attribute in the `WHERE` clause, for example:

```java
@SqlQuery(/* language=InjectedFreeMarker */ """
        SELECT ${apiProjectAclCondition}
          FROM "PROJECT"
         WHERE "UUID" = :projectUuid
        """)
Boolean isAccessible(@Bind UUID projectUuid);
```

`apiProjectAclCondition` resolves to one of the following:

* `TRUE` when PAC is disabled, the principal holds the bypass permission, the request has no principal, or
  [`ProjectAccess.unrestricted`](#projectaccessunrestricted) is active. `TRUE` is effectively a no-op to the
  query planner and incurs no additional cost.
* An `EXISTS(...)` subquery against PAU and PH for a `User` principal.
* An `EXISTS(...)` subquery against `APIKEYS_TEAMS`, PAT and PH for an `ApiKey` principal.
* `FALSE` for any other (unknown) principal type. PAC fails closed.

> [!NOTE]
> `EXISTS(...)` was chosen intentionally. Postgres plans it as a semi-join and short-circuits on the first matching row,
> so with the existing indexes on PAU, PAT and PH the per-row cost stays roughly constant and does not scale with the
> size of the access tables.

The condition defaults to filtering by `"PROJECT"."ID"`. When the query joins the project table under a different alias,
retarget the condition with the `@DefineApiProjectAclCondition` annotation:

```java
@SqlQuery(/* language=InjectedFreeMarker */ """
        SELECT ${apiProjectAclCondition}
          FROM "COMPONENT"
         WHERE "UUID" = :componentUuid
        """)
@DefineApiProjectAclCondition(projectIdColumn = "\"PROJECT_ID\"")
Boolean isAccessible(@Bind UUID componentUuid);
```

For paged endpoints, use `PaginationSupport.getBoundedTotalCountWithProjectAcl` to compute totals.
It applies the same condition to the count query.

### 2. JDO list queries

For JDO queries whose candidate class is `Project`, or has exactly one `Project`-typed member,
call `ProjectQueryManager.preprocessACLs` before executing the query:

```java
preprocessACLs(query, filter, params);
query.setRange(0, 1);
final Project project = singleResult(query.executeWithMap(params));
```

`preprocessACLs` appends a JDOQL predicate using `Project.isAccessibleBy(...)`. For an `ApiKey` with no team membership,
the predicate degrades to `false`. For an unknown principal type, it is `false`. When PAC is bypassed
(i.e. feature disabled, bypass permission, `null` principal, `unrestricted` scope), the predicate is skipped entirely.

### 3. JDO per-row checks

`QueryManager.hasAccess(principal, project)` tests access to a single project. Resource code uses it through
`AbstractApiResource.requireAccess(qm, project, ...)`, which throws `ProjectAccessDeniedException` when access is
denied and writes a security log event on failure:

```java
final Project project = qm.getObjectByUuid(Project.class, uuid);
requireAccess(qm, project);
```

### 4. JDBI per-row checks

`ProjectDao.isAccessible(UUID)` and `ComponentDao.isAccessible(UUID)` return `null` if no row exists, `true` if the
principal has access, and `false` otherwise. Resource code uses them through
`AbstractApiResource.requireProjectAccess(handle, uuid)` and `requireComponentAccess(handle, uuid)`. These throw
`NoSuchElementException` when the row is missing and `ProjectAccessDeniedException` when access is denied.

`NoSuchElementException` and `ProjectAccessDeniedException` are transparently translated to `404` and `403`
responses respectively, and do not need to be caught manually.

## Using PAC in new code

Pick the layer that matches the shape of the endpoint or query.

* **JDBI list or single-row queries.** Open the handle with an `AlpineRequest`. In a REST resource that is
  `super.getAlpineRequest()`. Interpolate `${apiProjectAclCondition}` in the query and add `@DefineApiProjectAclCondition`
  if the project ID lives on a different column or alias. Use `getBoundedTotalCountWithProjectAcl` for paged totals.

  The no-argument overloads (`JdbiFactory.withJdbiHandle(handle -> ...)` etc.) resolve the condition to `TRUE` so
  that background tasks can run without a principal. Calling them from a REST endpoint that uses
  `${apiProjectAclCondition}` silently disables PAC. Always pass `getAlpineRequest()` in resource code.
* **Single-object REST endpoints.** Fetch the entity, then call `requireAccess(qm, project)`,
  `requireProjectAccess(handle, uuid)` or `requireComponentAccess(handle, uuid)` before returning anything to the client.
  Never return a freshly fetched project or component without one of these!
* **JDO list queries.** Call `preprocessACLs(query, filter, params)` before `executeWithMap(params)`. This applies to
  every query whose candidate reaches `Project`.
* **Embedded project collections.** JDO does not filter child collections on parent entities (for example
  `Policy.projects` or `NotificationRule.projects`). When a response embeds such a collection, filter it before
  serialization using `AbstractApiResource.filterAccessibleProjects(...)`. This is a stop-gap and is marked as such in
  the source. New endpoints should expose the child collection as a paged sub-resource instead.

> [!IMPORTANT]
> Any change that touches PAC-sensitive code **must** ship with tests. Tests are the most reliable defence against
> accidental misuse and silent regressions. Cover, at minimum:
>
> * the happy path with an accessible project,
> * a project the principal must not see (expect `403`),
> * the bypass permission (`PORTFOLIO_ACCESS_CONTROL_BYPASS`) where relevant.
>
> Enable PAC for the test by calling `enablePortfolioAccessControl()` in the test's setup.
> Existing resource tests (for example `PolicyViolationResourceTest`) show the pattern.

## Bypassing PAC

A request that does not apply a PAC filter is legitimate in four cases.

### Feature disabled globally

When `access-management.acl.enabled` is `false`, all four enforcement layers behave as if every principal can access
every project. This is the default state of the system.

### Bypass permission

A principal that holds `PORTFOLIO_ACCESS_CONTROL_BYPASS` is exempt from PAC at all four layers,
even when the feature is enabled. Use this for administrators and for trusted automation that operates
on the whole portfolio.

### System and background code

When there is no `AlpineRequest`, or the request carries no `Principal`, PAC is not applied.
This is how schedulers and durable execution activities operate on data they need to process.
System code is not authenticated against PAC.

The corresponding code pattern is to open a JDBI handle with the no-argument factory:

```java
JdbiFactory.withJdbiHandle(handle -> /* ... */);
```

This is safe in background code because there is no user-facing response.
It is **not** safe in REST endpoints, as called out above.

### `ProjectAccess.unrestricted`

`ProjectAccess` is a small utility providing a scope-bound bypass for a single block of code on the current thread,
using a thread-local flag:

```java
public static <T> T unrestricted(Supplier<T> supplier);
public static boolean isUnrestricted();
```

All four enforcement layers consult `ProjectAccess.isUnrestricted()` and treat a `true` result the same way as the
feature being disabled. The flag is automatically cleared when the supplier returns or throws.

Use `ProjectAccess.unrestricted` only when both of the following are true:

1. The endpoint needs to look at project state that the caller is not allowed to see, for a well-defined reason.
   The typical reason is detecting a name or version collision and producing a clean error instead of a misleading
   unique-constraint violation.
2. The endpoint can still produce an authorisation decision afterwards.

Wrap the **smallest possible** block and run the explicit access check **outside** the scope,
before returning data to the client. The pattern in `BomResource` is representative:

```java
Project project = ProjectAccess.unrestricted(() -> qm.getProject(name, version));
if (project != null) {
    requireAccess(qm, project, "Access to the target project is forbidden");
    // ...
}
```

[public concepts page]: https://dependencytrack.github.io/docs/next/concepts/access-control/#portfolio-access-control
