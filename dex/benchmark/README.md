# dex-benchmark

A simple benchmarking setup that allows to observe engine performance under heavy load.

The setup consist of a single `DummyWorkflow`, which simply calls `DummyActivity` three times sequentially.
Each `DummyActivity` invocation is scheduled on a different task queue (`foo`, `bar`, `baz` respectively).
The activity itself is no-op. This allows the benchmark to focus entirely on engine overhead.

## Usage

1. Build the benchmark application:
    ```shell
    mvn -Pquick clean package
    ```
2. Start the benchmark setup:
    ```shell
    docker compose up -d --build
    ```
3. Navigate to Grafana at http://localhost:3000
4. Login with default credentials `admin:admin`
5. Open the `dex` dashboard

To test with multiple engine instances, run:

```shell
docker compose up -d --build --scale dex-engine=3
```

To tear everything down, run:

```shell
docker compose down --volumes
```

To change how many workflow runs are being created, modify the `NUM_RUNS` environment variable
of the `create-runs` service in `compose.yml`.

To customise the engine configuration:

1. Modify the `createDexEngine` method in the [`Application`](src/main/java/org/dependencytrack/dex/benchmark/Application.java) class
2. Repeat steps 1 & 2 from above.