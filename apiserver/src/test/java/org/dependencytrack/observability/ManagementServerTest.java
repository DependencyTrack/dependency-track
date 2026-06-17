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

import io.micrometer.core.instrument.Gauge;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.smallrye.config.SmallRyeConfigBuilder;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.common.health.HealthCheckRegistry;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Liveness;
import org.eclipse.microprofile.health.Readiness;
import org.eclipse.microprofile.health.Startup;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

class ManagementServerTest {

    private ManagementServer managementServer;
    private HttpClient httpClient;
    private String baseUrl;

    @BeforeEach
    void beforeEach() {
        httpClient = HttpClient.newHttpClient();
    }

    @AfterEach
    void afterEach() {
        if (httpClient != null) {
            httpClient.close();
        }
        if (managementServer != null) {
            managementServer.close();
        }
    }

    @Test
    void shouldReportStatusUpWhenNoChecksAreRegistered() throws Exception {
        startServer(
                new HealthCheckRegistry(Collections.emptyList()),
                new PrometheusMeterRegistry(PrometheusConfig.DEFAULT),
                new SmallRyeConfigBuilder().build());

        final HttpResponse<String> response = get("/health");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Content-Type")).hasValue("application/json");
        assertThatJson(response.body()).isEqualTo(/* language=JSON */ """
                {
                  "status": "UP",
                  "checks": []
                }
                """);
    }

    @Test
    void shouldReportStatusUpWhenAllChecksAreUp() throws Exception {
        final var registry = new HealthCheckRegistry(List.of(
                new MockReadinessCheck(() -> HealthCheckResponse.up("foo")),
                new MockReadinessCheck(() -> HealthCheckResponse.up("bar"))));
        startServer(
                registry,
                new PrometheusMeterRegistry(PrometheusConfig.DEFAULT),
                new SmallRyeConfigBuilder().build());

        final HttpResponse<String> response = get("/health");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Content-Type")).hasValue("application/json");
        assertThatJson(response.body())
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "status": "UP",
                          "checks": [
                            {
                              "name": "foo",
                              "status": "UP",
                              "data": null
                            },
                            {
                              "name": "bar",
                              "status": "UP",
                              "data": null
                            }
                          ]
                        }
                        """);
    }

    @Test
    void shouldReportStatusDownWhenAtLeastOneCheckIsDown() throws Exception {
        final var registry = new HealthCheckRegistry(List.of(
                new MockReadinessCheck(() -> HealthCheckResponse.up("foo")),
                new MockReadinessCheck(() -> HealthCheckResponse.down("bar"))));
        startServer(
                registry,
                new PrometheusMeterRegistry(PrometheusConfig.DEFAULT),
                new SmallRyeConfigBuilder().build());

        final HttpResponse<String> response = get("/health");

        assertThat(response.statusCode()).isEqualTo(503);
        assertThat(response.headers().firstValue("Content-Type")).hasValue("application/json");
        assertThatJson(response.body())
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "status": "DOWN",
                          "checks": [
                            {
                              "name": "foo",
                              "status": "UP",
                              "data": null
                            },
                            {
                              "name": "bar",
                              "status": "DOWN",
                              "data": null
                            }
                          ]
                        }
                        """);
    }

    @Test
    void shouldReturnInternalServerErrorWhenCheckThrows() throws Exception {
        final var registry = new HealthCheckRegistry(List.of(
                new MockReadinessCheck(() -> HealthCheckResponse.up("foo")),
                new MockReadinessCheck(() -> {
                    throw new IllegalStateException("Simulated check exception");
                })));
        startServer(
                registry,
                new PrometheusMeterRegistry(PrometheusConfig.DEFAULT),
                new SmallRyeConfigBuilder().build());

        final HttpResponse<String> response = get("/health");

        assertThat(response.statusCode()).isEqualTo(500);
    }

    @Test
    void shouldFilterByLiveness() throws Exception {
        final var registry = new HealthCheckRegistry(List.of(
                new MockLivenessCheck(() -> HealthCheckResponse.up("live")),
                new MockReadinessCheck(() -> HealthCheckResponse.up("ready")),
                new MockStartupCheck(() -> HealthCheckResponse.up("start")),
                new MockAllTypesCheck(() -> HealthCheckResponse.up("all"))));
        startServer(
                registry,
                new PrometheusMeterRegistry(PrometheusConfig.DEFAULT),
                new SmallRyeConfigBuilder().build());

        final HttpResponse<String> response = get("/health/live");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThatJson(response.body())
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "status": "UP",
                          "checks": [
                            {
                              "name": "live",
                              "status": "UP",
                              "data": null
                            },
                            {
                              "name": "all",
                              "status": "UP",
                              "data": null
                            }
                          ]
                        }
                        """);
    }

    @Test
    void shouldFilterByReadiness() throws Exception {
        final var registry = new HealthCheckRegistry(List.of(
                new MockLivenessCheck(() -> HealthCheckResponse.up("live")),
                new MockReadinessCheck(() -> HealthCheckResponse.up("ready")),
                new MockStartupCheck(() -> HealthCheckResponse.up("start")),
                new MockAllTypesCheck(() -> HealthCheckResponse.up("all"))));
        startServer(
                registry,
                new PrometheusMeterRegistry(PrometheusConfig.DEFAULT),
                new SmallRyeConfigBuilder().build());

        final HttpResponse<String> response = get("/health/ready");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThatJson(response.body())
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "status": "UP",
                          "checks": [
                            {
                              "name": "ready",
                              "status": "UP",
                              "data": null
                            },
                            {
                              "name": "all",
                              "status": "UP",
                              "data": null
                            }
                          ]
                        }
                        """);
    }

    @Test
    void shouldFilterByStartup() throws Exception {
        final var registry = new HealthCheckRegistry(List.of(
                new MockLivenessCheck(() -> HealthCheckResponse.up("live")),
                new MockReadinessCheck(() -> HealthCheckResponse.up("ready")),
                new MockStartupCheck(() -> HealthCheckResponse.up("start")),
                new MockAllTypesCheck(() -> HealthCheckResponse.up("all"))));
        startServer(
                registry,
                new PrometheusMeterRegistry(PrometheusConfig.DEFAULT),
                new SmallRyeConfigBuilder().build());

        final HttpResponse<String> response = get("/health/started");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThatJson(response.body())
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "status": "UP",
                          "checks": [
                            {
                              "name": "start",
                              "status": "UP",
                              "data": null
                            },
                            {
                              "name": "all",
                              "status": "UP",
                              "data": null
                            }
                          ]
                        }
                        """);
    }

    @Test
    void shouldReturnAllChecks() throws Exception {
        final var registry = new HealthCheckRegistry(List.of(
                new MockLivenessCheck(() -> HealthCheckResponse.up("live")),
                new MockReadinessCheck(() -> HealthCheckResponse.up("ready")),
                new MockStartupCheck(() -> HealthCheckResponse.up("start")),
                new MockAllTypesCheck(() -> HealthCheckResponse.up("all"))));
        startServer(
                registry,
                new PrometheusMeterRegistry(PrometheusConfig.DEFAULT),
                new SmallRyeConfigBuilder().build());

        final HttpResponse<String> response = get("/health");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThatJson(response.body())
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "status": "UP",
                          "checks": [
                            {
                              "name": "live",
                              "status": "UP",
                              "data": null
                            },
                            {
                              "name": "ready",
                              "status": "UP",
                              "data": null
                            },
                            {
                              "name": "start",
                              "status": "UP",
                              "data": null
                            },
                            {
                              "name": "all",
                              "status": "UP",
                              "data": null
                            }
                          ]
                        }
                        """);
    }

    @Test
    void shouldRespondWithMetricsWhenEnabled() throws Exception {
        final var meterRegistry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        Gauge.builder("alpine.foo.bar", () -> 666).register(meterRegistry);
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.metrics.enabled", "true")
                .build();
        startServer(new HealthCheckRegistry(), meterRegistry, config);

        final HttpResponse<String> response = get("/metrics");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Content-Type"))
                .hasValueSatisfying(ct -> assertThat(ct).contains("text/plain"));
        assertThat(response.body()).contains("alpine_foo_bar 666.0");
    }

    @Test
    void shouldRespondWithNotFoundWhenMetricsNotEnabled() throws Exception {
        startServer(
                new HealthCheckRegistry(),
                new PrometheusMeterRegistry(PrometheusConfig.DEFAULT),
                new SmallRyeConfigBuilder().build());

        final HttpResponse<String> response = get("/metrics");

        assertThat(response.statusCode()).isEqualTo(404);
    }

    @Test
    void shouldRespondWithMetricsWhenAuthenticated() throws Exception {
        final var meterRegistry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        Gauge.builder("alpine.foo.bar", () -> 666).register(meterRegistry);
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.metrics.enabled", "true")
                .withDefaultValue("dt.metrics.auth.username", "metrics-user")
                .withDefaultValue("dt.metrics.auth.password", "metrics-password")
                .build();
        startServer(new HealthCheckRegistry(), meterRegistry, config);

        final String credentials = Base64.getEncoder()
                .encodeToString("metrics-user:metrics-password".getBytes(UTF_8));
        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/metrics"))
                .header("Authorization", "Basic " + credentials)
                .GET()
                .build();
        final HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("alpine_foo_bar 666.0");
    }

    @Test
    void shouldRespondWithUnauthorizedWhenAuthFailed() throws Exception {
        final var meterRegistry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.metrics.enabled", "true")
                .withDefaultValue("dt.metrics.auth.username", "metrics-user")
                .withDefaultValue("dt.metrics.auth.password", "metrics-password")
                .build();
        startServer(new HealthCheckRegistry(), meterRegistry, config);

        final String credentials = Base64.getEncoder()
                .encodeToString("foo:bar".getBytes(UTF_8));
        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/metrics"))
                .header("Authorization", "Basic " + credentials)
                .GET()
                .build();
        final HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.headers().firstValue("Www-authenticate"))
                .hasValue("Basic realm=\"metrics\"");
    }

    private void startServer(
            HealthCheckRegistry registry,
            PrometheusMeterRegistry meterRegistry,
            Config config) throws Exception {
        managementServer = new ManagementServer("127.0.0.1", 0, registry, meterRegistry, config);
        managementServer.start();
        baseUrl = "http://localhost:" + managementServer.getPort();
    }

    private HttpResponse<String> get(String path) throws Exception {
        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .GET()
                .build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private abstract static class AbstractMockCheck implements HealthCheck {

        private final Supplier<HealthCheckResponse> responseSupplier;

        private AbstractMockCheck(Supplier<HealthCheckResponse> responseSupplier) {
            this.responseSupplier = responseSupplier;
        }

        @Override
        public HealthCheckResponse call() {
            return responseSupplier.get();
        }

    }

    @Liveness
    private static class MockLivenessCheck extends AbstractMockCheck {

        private MockLivenessCheck(Supplier<HealthCheckResponse> responseSupplier) {
            super(responseSupplier);
        }

    }

    @Readiness
    private static class MockReadinessCheck extends AbstractMockCheck {

        private MockReadinessCheck(Supplier<HealthCheckResponse> responseSupplier) {
            super(responseSupplier);
        }

    }

    @Startup
    private static class MockStartupCheck extends AbstractMockCheck {

        private MockStartupCheck(Supplier<HealthCheckResponse> responseSupplier) {
            super(responseSupplier);
        }

    }

    @Liveness
    @Readiness
    @Startup
    private static class MockAllTypesCheck extends AbstractMockCheck {

        private MockAllTypesCheck(Supplier<HealthCheckResponse> responseSupplier) {
            super(responseSupplier);
        }

    }

}
