# dex

Embedded **d**urable **ex**ecution ("workflows-as-code") engine, optimized for PostgreSQL.

Heavily influenced by Microsoft's [Durable Task Framework](https://github.com/Azure/durabletask)
and [Temporal](https://github.com/temporalio/temporal).

## Structure

* [`api`](api) contains the public API for authoring durable workflows.
* [`benchmark`](benchmark) contains a simple benchmarking setup.
* [`engine-api`](engine-api) contains the public API for interacting with the engine.
* [`engine-migration`](engine-migration) contains database migrations of the engine.
* [`engine`](engine) contains the actual engine implementation.
* [`testing`](testing) contains supporting classes for testing workflows.

`api` and `engine-api` have been separated from the core engine to make the respective
API surfaces more obvious, and prevent internals from leaking into the API.
It is not intended that there exist other API implementations outside of `engine`.

The [Java module system](https://dev.java/learn/modules/intro/) is used to enforce strong encapsulation.

## Documentation

* [Architecture / design documentation](https://dependencytrack.github.io/docs/next/concepts/architecture/design/durable-execution/)

## Common patterns

### Chaining

Most workflows require the execution of steps to happen in sequence:

```mermaid
flowchart LR
    A@{ shape: circle, label: Start }
    B["Foo"]
    C["Bar"]
    D["Baz"]
    E@{ shape: dbl-circ, label: Stop }
    A --> B
    B --> C
    C --> D
    D --> E
```

With dex, this can be achieved by `await`ing step results for initiating the next step:

```java
@WorkflowSpec(name = "example")
class ExampleWorkflow implements Workflow<Void, Void> {

    public Void execute(WorkflowContext<Void> ctx, Void argument) {
        String fooResult = ctx.activity(FooActivity.class).call().await();
        String barResult = ctx.activity(BarActivity.class).call(fooResult).await();
        String bazResult = ctx.activity(BazActivity.class).call(barResult).await();
        ctx.logger().info("Baz result: {}", bazResult);
        return null;
    }

}
```

In the above example, activity calls are scheduled one-by-one, with successive
calls even depending on the result of preceding calls.

The same approach can be used for child workflows and timers.

### Scatter-Gather

Often it is desirable to perform multiple workflow steps concurrently:

```mermaid
flowchart LR
    A@{ shape: circle, label: Start }
    B["Foo"]
    C["Bar"]
    D["Baz"]
    E@{ shape: dbl-circ, label: Stop }
    A --> B
    A --> C
    A --> D
    B --> E
    C --> E
    D --> E
```

With dex, this can be achieved by collecting `Awaitable`s into a collection first,
and then awaiting all of them:

```java
@WorkflowSpec(name = "example")
class ExampleWorkflow implements Workflow<Void, Void> {

    public Void execute(WorkflowContext<Void> ctx, Void argument) {
        var awaitables = List.<Awaitable<String>>of(
            ctx.activity(FooActivity.class).call(),
            ctx.activity(BarActivity.class).call(),
            ctx.activity(BazActivity.class).call()    
        );

        var results = new ArrayList<String>();
        for (var awaitable : awaitables) {
            String result = awaitable.await();
            results.add(result);
        }

        ctx.logger().info("Results: {}", results);
        
        return null;
    }

}
```

In the above example, all activity calls are scheduled at once when the workflow first
becomes blocked (i.e., the first time `await` is called).

The same approach can be used for child workflows and timers.

### Singletons

Some workflows are intended to exist *at most once*. This is usually true for workflows that:

* are resource-intensive, or
* take a long time to complete, or
* modify some state (be it local or in external systems) in a way that is not concurrency-safe

In dex, this can be achieved using workflow instance IDs.

```java
UUID runId = dexEngine.createRun(
        new CreateWorkflowRunRequest<>(ExampleWorkflow.class)
                .withInstanceId("only-exists-once"));
if (runId == null) {
    // Another run with the same instance ID already exists in non-terminal state.
} else {
    // Run created successfully!
}
```

Multiple workflow runs can have the same instance ID,
but only a single run in non-terminal state can exist
for a given instance ID at any point in time.

> [!NOTE]
> Uniqueness of instance IDs is enforced across workflow types.
> Avoid overly generic instance IDs.

### Concurrency Control

When workflows access shared resources, there needs to be a way to serialize
their execution to prevent race conditions.

Holding a distributed lock for the entire duration of a workflow run is not feasible,
as a single run can potentially take hours to complete.

With dex, a *concurrency key* can be defined when creating a new workflow run:

```java
for (int i = 0; i < 100; i++) {
    dexEngine.createRun(
            new CreateWorkflowRunRequest<>(ExampleWorkflow.class)
                    .withConcurrencyKey("example:projectId"));
}
``` 

Instead of preventing creation of new runs, as done for [singletons](#singletons),
dex effectively allows runs to queue up, and will process them in order.

Each run will be executed until completion before the next run is started.

> [!NOTE]
> The order in which the runs will execute is determined by:
> * Their priority
> * Their creation timestamp
