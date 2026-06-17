/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.dex.benchmark;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.jvm.JvmGcMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmInfoMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmMemoryMetrics;
import io.micrometer.core.instrument.config.MeterFilter;
import io.micrometer.core.instrument.distribution.DistributionStatisticConfig;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.prometheus.metrics.exporter.httpserver.HTTPServer;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.DexEngineConfig;
import org.dependencytrack.dex.engine.api.DexEngineFactory;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.migration.MigrationExecutor;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.ServiceLoader;

import static java.util.Objects.requireNonNullElse;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;

public class Application {

    private static final Logger LOGGER = LoggerFactory.getLogger(Application.class);

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            throw new IllegalArgumentException("No command specified");
        }

        final String command = args[0];

        switch (command) {
            case "init":
                executeInitCommand();
                break;
            case "create-runs":
                executeCreateRunsCommand();
                break;
            case "start-engine":
                executeStartEngineCommand();
                break;
            default:
                throw new IllegalArgumentException("Unknown command: " + command);
        }
    }

    private static void executeInitCommand() throws Exception {
        final DataSource dataSource = createDataSource(null);

        LOGGER.info("Running database migrations");
        new MigrationExecutor(dataSource).execute();

        try (final DexEngine dexEngine = createDexEngine(dataSource, null)) {
            LOGGER.info("Creating task queues");
            dexEngine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 1000));
            dexEngine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "foo", 1000));
            dexEngine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "bar", 1000));
            dexEngine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "baz", 1000));
        }
    }

    private static void executeCreateRunsCommand() throws Exception {
        final int batchSize = Integer.parseInt(requireNonNullElse(System.getenv("BATCH_SIZE"), "100"));
        final int total = Integer.parseInt(requireNonNullElse(System.getenv("RUNS_COUNT"), "100000"));

        try (final DexEngine dexEngine = createDexEngine(createDataSource(null), null)) {
            LOGGER.info("Creating {} workflow runs", total);

            for (int i = 0; i < total; i += batchSize) {
                final int currentBatchSize = Math.min(batchSize, total - batchSize);
                final var currentBatch = new ArrayList<CreateWorkflowRunRequest<?>>(currentBatchSize);

                for (int j = 0; j < currentBatchSize; j++) {
                    currentBatch.add(new CreateWorkflowRunRequest<>(DummyWorkflow.class));
                }

                LOGGER.info("Creating batch of {} workflow runs", currentBatchSize);
                dexEngine.createRuns(currentBatch);
            }
        }
    }

    private static void executeStartEngineCommand() throws Exception {
        final PrometheusMeterRegistry meterRegistry = createMeterRegistry();
        final DataSource dataSource = createDataSource(meterRegistry);

        final DexEngine dexEngine = createDexEngine(dataSource, meterRegistry);

        dexEngine.registerTaskWorker(new TaskWorkerOptions(TaskType.WORKFLOW, "default", "default", 150));
        dexEngine.registerTaskWorker(new TaskWorkerOptions(TaskType.ACTIVITY, "foo-worker", "foo", 50));
        dexEngine.registerTaskWorker(new TaskWorkerOptions(TaskType.ACTIVITY, "bar-worker", "bar", 50));
        dexEngine.registerTaskWorker(new TaskWorkerOptions(TaskType.ACTIVITY, "baz-worker", "baz", 50));

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                dexEngine.close();
            } catch (IOException e) {
                LOGGER.error("Failed to shutdown dex engine", e);
            }
        }));

        dexEngine.start();

        startMetricsServer(meterRegistry);

        Thread.currentThread().join();
    }

    private static DataSource createDataSource(@Nullable MeterRegistry meterRegistry) {
        final var hikariConfig = new HikariConfig();
        hikariConfig.setDriverClassName(org.postgresql.Driver.class.getName());
        hikariConfig.setJdbcUrl(requireNonNullElse(System.getenv("DATABASE_URL"), "jdbc:postgresql://postgres:5432/dex"));
        hikariConfig.setUsername(requireNonNullElse(System.getenv("DATABASE_USERNAME"), "dex"));
        hikariConfig.setPassword(requireNonNullElse(System.getenv("DATABASE_PASSWORD"), "dex"));
        hikariConfig.setMaximumPoolSize(10);
        hikariConfig.setMinimumIdle(5);
        if (meterRegistry != null) {
            hikariConfig.setMetricRegistry(meterRegistry);
        }

        return new HikariDataSource(hikariConfig);
    }

    private static PrometheusMeterRegistry createMeterRegistry() {
        final var meterRegistry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);

        meterRegistry.config().meterFilter(new MeterFilter() {
            @Override
            public DistributionStatisticConfig configure(
                    Meter.Id id,
                    DistributionStatisticConfig config) {
                if (id.getName().startsWith("dt.dex.")) {
                    return DistributionStatisticConfig.builder()
                            .percentilesHistogram(true)
                            .build()
                            .merge(config);
                }
                return config;
            }
        });

        new JvmInfoMetrics().bindTo(meterRegistry);
        new JvmGcMetrics().bindTo(meterRegistry);
        new JvmMemoryMetrics().bindTo(meterRegistry);

        return meterRegistry;
    }

    private static DexEngine createDexEngine(DataSource dataSource, @Nullable MeterRegistry meterRegistry) {
        final var dexEngineConfig = new DexEngineConfig(dataSource);
        dexEngineConfig.taskEventBuffer().setMaxBatchSize(250);
        dexEngineConfig.taskEventBuffer().setFlushInterval(Duration.ofMillis(50));
        if (meterRegistry != null) {
            dexEngineConfig.metrics().setMeterRegistry(meterRegistry);
            dexEngineConfig.metrics().setCollectorEnabled(true);
            dexEngineConfig.metrics().setCollectorInitialDelay(Duration.ofSeconds(5));
            dexEngineConfig.metrics().setCollectorInterval(Duration.ofSeconds(10));
        } else {
            dexEngineConfig.metrics().setCollectorEnabled(false);
        }

        final var dexEngineFactory = ServiceLoader.load(DexEngineFactory.class).findFirst().orElseThrow();

        final DexEngine dexEngine = dexEngineFactory.create(dexEngineConfig);

        dexEngine.registerWorkflow(
                new DummyWorkflow(),
                voidConverter(),
                voidConverter(),
                Duration.ofSeconds(30));
        dexEngine.registerActivity(
                new DummyActivity(),
                voidConverter(),
                voidConverter(),
                Duration.ofSeconds(30));

        return dexEngine;
    }

    private static void startMetricsServer(PrometheusMeterRegistry meterRegistry) throws IOException {
        final var httpServer = HTTPServer.builder()
                .port(8080)
                .registry(meterRegistry.getPrometheusRegistry())
                .buildAndStart();
        Runtime.getRuntime().addShutdownHook(new Thread(httpServer::close));
    }

}
