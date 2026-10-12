# Persistence

Dependency-Track (currently) has two persistence layers:

* [JDO], implemented by [DataNucleus], is inherited from Dependency-Track v4 and [Alpine] framework.
* [JDBI] with raw SQL, which is what all new code uses.

The strategic goal is to remove JDO entirely. With JDO, [fetch groups] and lazy loading decide which queries run,
which often causes performance and correctness issues. JDO also needs [bytecode enhancement] at build time.

With JDBI, every query is hand-crafted, so round trips are visible and can be batched.
By writing SQL directly, we also get to tune queries, and leverage Postgres features that generic ORMs cannot.

JDO code is replaced step by step, as the surrounding code changes.

## Rules

* Write new persistence code with JDBI and raw SQL. Don't add JDO entities, JDOQL queries, or `QueryManager` methods.
* Code running inside a JDO transaction (`qm.callInTransaction`, `qm.runInTransaction`) must not open its own JDBI handle.
  A separate handle uses a separate connection. It can't see uncommitted JDO changes, doesn't roll back with the JDO transaction,
  and holds a second connection from the pool. Use `JdbiFactory.withJdbiHandle(qm, ...)` or `useJdbiHandle(qm, ...)`,
  which join the JDO transaction.
* Don't use `qm` inside the JDBI handle callback. After it, JDO objects loaded earlier don't reflect what JDBI wrote.
* The handle applies the `AlpineRequest` that `qm` was created with. In REST resources,
  create it with `new QueryManager(getAlpineRequest())`, so that [portfolio access control] applies.
* If the JDO side of a method only reads, don't mix the two. Port the whole method to a single JDBI transaction.

## References

* [`JdbiFactory`]
* [Portfolio access control]
* [JDBI developer guide]

[Alpine]: https://github.com/stevespringett/Alpine
[bytecode enhancement]: https://www.datanucleus.org/products/accessplatform_6_0/jdo/enhancer.html
[DataNucleus]: https://www.datanucleus.org/
[fetch groups]: https://www.datanucleus.org/products/accessplatform_6_0/jdo/persistence.html#fetch_groups
[JDBI developer guide]: https://jdbi.org/
[JDBI]: https://jdbi.org/
[JDO]: https://db.apache.org/jdo/
[REST API v1]: ../DEVELOPING.md#rest-api-v1-is-in-maintenance-mode
[`JdbiFactory`]: ../apiserver/src/main/java/org/dependencytrack/persistence/jdbi/JdbiFactory.java
[portfolio access control]: ./PORTFOLIO_ACCESS_CONTROL.md
