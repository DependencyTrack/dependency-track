# Interruptibility

The durable execution engine (dex) cancels a running activity by interrupting its thread.
It does so when the execution timeout of an attempt is exceeded, when the activity task lock
was lost to another worker, or when the application is shutting down. In all cases the result
of the execution can no longer be committed, so work that continues past the interrupt is wasted.
Long-running code must therefore react to interrupts. This practice was introduced via [ADR 034].

## Rules

* Never swallow `InterruptedException`. Either let it propagate, or restore the flag with
  `Thread.currentThread().interrupt()` and return.
* Let `InterruptedException` propagate out of `Activity#execute`. The worker abandons the task
  without consuming a retry. Any other exception is treated as a failed attempt.
* Check for interruption at batch boundaries, for example once per page or batch, not once per row.
  A batch should be short enough for cancellation to take effect within seconds.
* Use `Thread.interrupted()` when you throw right away, since it clears the flag you are about to
  represent as an exception. Use `Thread.currentThread().isInterrupted()` when callers above you
  still need the flag.
* Keep database work paginated. The PostgreSQL JDBC driver cancels the running query on interrupt,
  but a single large statement still has to be rolled back before the activity can stop.
* Where interrupts do not reach, use a timeout instead. CPU-bound loops without a check,
  work submitted to a `ForkJoinPool` or parallel stream, and most third-party I/O libraries
  are not interruptible.

## Example

```java
@Override
public @Nullable Void execute(ActivityContext ctx, @Nullable Void argument) throws InterruptedException {
    List<Component> components = fetchNextComponentsPage(null);
    while (!components.isEmpty()) {
        if (Thread.interrupted()) {
            throw new InterruptedException("Interrupted before all components could be processed");
        }

        process(components);
        components = fetchNextComponentsPage(components.getLast());
    }

    return null;
}
```

## References

* [`Thread#interrupt`] javadoc
* [Java Tutorials: Interrupts]

[ADR 034]: adr/034-auto-heartbeat-activity-locks.md
[Java Tutorials: Interrupts]: https://docs.oracle.com/javase/tutorial/essential/concurrency/interrupt.html
[`Thread#interrupt`]: https://docs.oracle.com/en/java/javase/25/docs//api/java.base/java/lang/Thread.html#interrupt()
