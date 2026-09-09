# Interruptibility

Long-running work must react to thread interrupts. A thread is interrupted when the task it is
running is canceled, when the executor it runs on is shut down, or when the application itself is
shutting down. In all cases the result of the work can no longer be used, so anything that
continues past the interrupt is wasted, and shutdown is held up until it finishes.

We want Dependency-Track to be a well-behaved citizen of Kubernetes clusters and the like,
which entails timely shutdown on `SIGTERM`. Interrupts are the way to achieve this.

## Rules

* Never swallow `InterruptedException`. Either let it propagate, or restore the flag with
  `Thread.currentThread().interrupt()` and return.
* Declare `throws InterruptedException` rather than wrapping it in a `RuntimeException`.
  Callers need to tell cancellation apart from failure, so that canceled work is not retried
  or reported as an error.
* Check for interruption at batch boundaries, for example once per page or batch, not once per row.
  A batch should be short enough for cancellation to take effect within seconds.
* Use `Thread.interrupted()` when you throw right away, since it clears the flag you are about to
  represent as an exception. Use `Thread.currentThread().isInterrupted()` when callers above you
  still need the flag.
* Keep database work paginated. The PostgreSQL JDBC driver cancels the running query on interrupt,
  but a single large statement still has to be rolled back before the work can stop.
* Where interrupts do not reach, use a timeout instead. CPU-bound loops without a check,
  work submitted to a `ForkJoinPool` or parallel stream, and most third-party I/O libraries
  are not interruptible.

## Example

```java
void processAllComponents() throws InterruptedException {
    List<Component> components = fetchNextComponentsPage(null);
    while (!components.isEmpty()) {
        if (Thread.interrupted()) {
            throw new InterruptedException("Interrupted before all components could be processed");
        }

        process(components);
        components = fetchNextComponentsPage(components.getLast());
    }
}
```

## References

* [`Thread#interrupt`] javadoc
* [Java Tutorials: Interrupts]

[Java Tutorials: Interrupts]: https://docs.oracle.com/javase/tutorial/essential/concurrency/interrupt.html
[`Thread#interrupt`]: https://docs.oracle.com/en/java/javase/25/docs//api/java.base/java/lang/Thread.html#interrupt()
