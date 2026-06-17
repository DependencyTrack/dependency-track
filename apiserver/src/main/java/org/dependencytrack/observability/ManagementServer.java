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
package org.dependencytrack.observability;

import com.sun.net.httpserver.HttpServer;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.common.health.HealthCheckRegistry;
import org.eclipse.microprofile.config.Config;
import org.jspecify.annotations.Nullable;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public final class ManagementServer implements Closeable {

    private final String host;
    private final int port;
    private final HealthCheckRegistry healthCheckRegistry;
    private final PrometheusMeterRegistry meterRegistry;
    private final boolean metricsEnabled;
    private final @Nullable String basicAuthUsername;
    private final @Nullable String basicAuthPassword;
    private final AtomicBoolean started = new AtomicBoolean(false);
    private @Nullable HttpServer server;
    private @Nullable ExecutorService executor;

    public ManagementServer(
            String host,
            int port,
            HealthCheckRegistry healthCheckRegistry,
            PrometheusMeterRegistry meterRegistry,
            Config config) {
        this.host = requireNonNull(host, "host must not be null");
        this.port = port;
        this.healthCheckRegistry = requireNonNull(healthCheckRegistry, "healthCheckRegistry must not be null");
        this.meterRegistry = requireNonNull(meterRegistry, "meterRegistry must not be null");
        this.metricsEnabled = config
                .getOptionalValue(ConfigKeys.METRICS_ENABLED, boolean.class)
                .orElse(false);
        this.basicAuthUsername = config
                .getOptionalValue(ConfigKeys.METRICS_AUTH_USERNAME, String.class)
                .orElse(null);
        this.basicAuthPassword = config
                .getOptionalValue(ConfigKeys.METRICS_AUTH_PASSWORD, String.class)
                .orElse(null);
    }

    public void start() throws IOException {
        if (!started.compareAndSet(false, true)) {
            throw new IllegalStateException("Already started");
        }

        server = HttpServer.create(new InetSocketAddress(host, port), 0);
        executor = Executors.newVirtualThreadPerTaskExecutor();
        server.setExecutor(executor);

        server.createContext("/health", new HealthHandler(healthCheckRegistry));
        if (metricsEnabled) {
            server.createContext("/metrics", new MetricsHandler(meterRegistry, basicAuthUsername, basicAuthPassword));
        }

        server.start();
    }

    int getPort() {
        if (server == null) {
            throw new IllegalStateException("Server not started");
        }

        return server.getAddress().getPort();
    }

    @Override
    public void close() {
        if (!started.compareAndSet(true, false)) {
            return;
        }

        if (server != null) {
            server.stop(0);
        }
        if (executor != null) {
            executor.close();
        }
    }

}
