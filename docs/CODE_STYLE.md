# Code Style

`make format-java` handles formatting, import order, and unused imports.
See [`DEVELOPING.md`](../DEVELOPING.md#code-style).
This document covers conventions beyond what the formatter can enforce.

Apply them to code you write or change. Don't reformat untouched code to follow them.

## Java

### Variables

* Make classes `final` unless they are designed for extension.
* Make fields and local variables `final` unless they are reassigned. This includes `final var`.
* Don't mark methods or method parameters `final`.
* Use `var` only when the type is obvious from the right-hand side.
  `final var projects = new ArrayList<Project>();` is fine, `final var result = process();` is not.
* Return `List.copyOf(...)` or `Set.copyOf(...)` when handing out a collection backed by internal state.

### Control Flow

* Handle absent, invalid, and exceptional cases first, and return early.
  The main path then runs at the method's base indentation.
* In loops, `continue` on the skip condition instead of wrapping the body in an `if`.
* Don't use `else` after a block that returns or throws.
* A third level of nesting inside a method is a signal to extract a method.

### Strings

* Use `"...".formatted(...)` instead of `String.format(...)`.
* Concatenate only when the value goes at the very start or end, e.g. `"Project " + name`.

### Exceptions

* Throw `IllegalArgumentException` for bad input, and `IllegalStateException` for bad state.
* The message names the offending value, or states the expected and actual state:
  `throw new IllegalArgumentException("Page size must be positive, but was %d".formatted(pageSize));`

For `InterruptedException`, see [`INTERRUPTIBILITY.md`](INTERRUPTIBILITY.md).

### Javadoc

* Write Javadoc in [Markdown] (`///`).
* Add Javadoc to public API only, and only for what the signature doesn't say.
* Add `@since` to new public types and methods.
  It carries the version in `pom.xml` without `-SNAPSHOT`, e.g. `@since 5.3.0` for `5.3.0-SNAPSHOT`.

### Comments

Nothing checks comments against the code, so they drift and mislead.

* Write a comment only when a competent reader would otherwise misread the code, or "fix" it into a bug.
  Try a better name, type, or test first.
* Explain the non-obvious *why*, in one line. Don't restate the code, narrate the change, or reference the issue.
* Don't add `TODO` comments. Fix it now, or open an issue.
* When you change code, fix or delete the comments it invalidates.

## SQL

The main schema, managed in [`migration`](../migration), inherits its naming from Dependency-Track v4.
The [`dex`](../dex) schema uses PostgreSQL's native conventions. Follow the conventions of the schema you query.
New tables in the main schema use the main schema's naming.

|                        | Main schema                   | dex schema                           |
|:-----------------------|:------------------------------|:-------------------------------------|
| Keywords and functions | Uppercase                     | Lowercase                            |
| Tables and columns     | Quoted uppercase, `"PROJECT"` | Unquoted `snake_case`, `dex_` prefix |
| Aliases and CTE names  | Unquoted `snake_case`         | Unquoted `snake_case`                |
| Named parameters       | `camelCase`, `:projectId`     | `camelCase`, `:projectId`            |

### Formatting

Use river style. Right-align clause keywords to a common river, and let values start to its right.

* One column per line.
* Leading commas, aligned with the river.
* Indent subquery and CTE bodies two spaces.

Main schema:

```sql
WITH active_project AS (
  SELECT p."ID"
       , p."NAME"
    FROM "PROJECT" AS p
   WHERE p."INACTIVE_SINCE" IS NULL
)
SELECT ap."NAME" AS project_name
     , COUNT(c."ID") AS component_count
  FROM active_project AS ap
 INNER JOIN "COMPONENT" AS c
    ON c."PROJECT_ID" = ap."ID"
 GROUP BY ap."NAME"
HAVING COUNT(c."ID") >= :minComponentCount
 ORDER BY component_count DESC
 LIMIT :limit
```

dex schema:

```sql
select run.workflow_name
     , count(*) as run_count
  from dex_workflow_run as run
 where run.status = 'CREATED'
   and run.created_at < now() - cast(:maxAge as interval)
 group by run.workflow_name
```

### Naming

* Alias tables and columns explicitly with `AS`.

### Operators and Types

* `CAST(x AS type)` instead of `x::type`.
* `!=` instead of `<>`.
* Named parameters instead of positional ones.

### Query Design

* Check existence with `SELECT EXISTS(SELECT 1 FROM ... WHERE ...)`, never with `COUNT(*) > 0`.
* Use `RETURNING` instead of a follow-up `SELECT`.
* Prefer one statement over several round trips. A single query with CTEs can return several results.
* Start conditionally composed predicates with `WHERE TRUE`, followed by `AND ...`.
* Comment queries whose shape is driven by locking, index choice, or deferred constraints.

[Markdown]: https://openjdk.org/jeps/467
