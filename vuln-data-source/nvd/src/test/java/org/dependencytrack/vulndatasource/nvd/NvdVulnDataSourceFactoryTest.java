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
package org.dependencytrack.vulndatasource.nvd;

import com.github.tomakehurst.wiremock.http.Fault;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.dependencytrack.plugin.api.ExtensionTestCheck;
import org.dependencytrack.plugin.api.ExtensionTestResult;
import org.dependencytrack.plugin.api.MutableServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.dependencytrack.plugin.testing.AbstractExtensionFactoryTest;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.plugin.testing.MockKeyValueStore;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

class NvdVulnDataSourceFactoryTest extends AbstractExtensionFactoryTest<@NonNull VulnDataSource, @NonNull NvdVulnDataSourceFactory> {

    protected NvdVulnDataSourceFactoryTest() {
        super(NvdVulnDataSourceFactory.class);
    }

    @Nested
    @WireMockTest
    class TestMethodTest {

        @Test
        void shouldPassConnectivityAndFeedFormatCheck(WireMockRuntimeInfo wmRuntimeInfo) {
            stubFor(get(urlPathEqualTo("/json/cve/2.0/nvdcve-2.0-modified.meta"))
                    .willReturn(aResponse()
                            .withBody("""
                                    lastModifiedDate:2026-01-19T16:00:01-05:00
                                    size:15114674
                                    zipSize:1674794
                                    gzSize:1674650
                                    sha256:482399306951B6FF9E00E3EC72A7EED8D927FB2DB4F4E61F2D6218CF67133CC0
                                    """)));

            factory.init(
                    new MutableServiceRegistry()
                            .register(ConfigRegistry.class, new MockConfigRegistry(
                                    Map.of("allow-local-connections", "true")))
                            .register(HttpClient.class, HttpClient.newHttpClient())
                            .register(KeyValueStore.class, new MockKeyValueStore()));

            final var runtimeConfig = new NvdVulnDataSourceConfigV1()
                    .withEnabled(true)
                    .withCveFeedsUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()));

            final ExtensionTestResult testResult = factory.test(runtimeConfig);

            assertThat(testResult.isFailed()).isFalse();
            assertThat(testResult.checks()).satisfiesExactly(
                    check -> {
                        assertThat(check.name()).isEqualTo("connection");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.PASSED);
                        assertThat(check.message()).isNull();
                    },
                    check -> {
                        assertThat(check.name()).isEqualTo("feed_format");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.PASSED);
                        assertThat(check.message()).isNull();
                    });
        }

        @Test
        void shouldReportConnectionFailure(WireMockRuntimeInfo wmRuntimeInfo) {
            stubFor(get(urlPathEqualTo("/json/cve/2.0/nvdcve-2.0-modified.meta"))
                    .willReturn(aResponse()
                            .withFault(Fault.CONNECTION_RESET_BY_PEER)));

            factory.init(
                    new MutableServiceRegistry()
                            .register(ConfigRegistry.class, new MockConfigRegistry(
                                    Map.of("allow-local-connections", "true")))
                            .register(HttpClient.class, HttpClient.newHttpClient())
                            .register(KeyValueStore.class, new MockKeyValueStore()));

            final var runtimeConfig = new NvdVulnDataSourceConfigV1()
                    .withEnabled(true)
                    .withCveFeedsUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()));

            final ExtensionTestResult testResult = factory.test(runtimeConfig);

            assertThat(testResult.isFailed()).isTrue();
            assertThat(testResult.checks()).satisfiesExactly(
                    check -> {
                        assertThat(check.name()).isEqualTo("connection");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.FAILED);
                        assertThat(check.message()).isEqualTo("Connection failed, check logs for details");
                    },
                    check -> {
                        assertThat(check.name()).isEqualTo("feed_format");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.SKIPPED);
                        assertThat(check.message()).isNull();
                    });
        }

        @Test
        void shouldReportConnectionFailureWhenLocalConnectionsAreDisallowed(WireMockRuntimeInfo wmRuntimeInfo) {
            factory.init(
                    new MutableServiceRegistry()
                            .register(ConfigRegistry.class, new MockConfigRegistry(
                                    Map.of("allow-local-connections", "false")))
                            .register(HttpClient.class, HttpClient.newHttpClient())
                            .register(KeyValueStore.class, new MockKeyValueStore()));

            final var runtimeConfig = new NvdVulnDataSourceConfigV1()
                    .withEnabled(true)
                    .withCveFeedsUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()));

            final ExtensionTestResult testResult = factory.test(runtimeConfig);

            assertThat(testResult.isFailed()).isTrue();
            assertThat(testResult.checks()).satisfiesExactly(
                    check -> {
                        assertThat(check.name()).isEqualTo("connection");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.FAILED);
                        assertThat(check.message()).isEqualTo("Connection to local hosts is not allowed");
                    },
                    check -> {
                        assertThat(check.name()).isEqualTo("feed_format");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.SKIPPED);
                        assertThat(check.message()).isNull();
                    });
        }

        @Test
        void shouldReportInvalidFeedFormatFailure(WireMockRuntimeInfo wmRuntimeInfo) {
            stubFor(get(urlPathEqualTo("/json/cve/2.0/nvdcve-2.0-modified.meta"))
                    .willReturn(aResponse()
                            .withBody("invalid")));

            factory.init(
                    new MutableServiceRegistry()
                            .register(ConfigRegistry.class, new MockConfigRegistry(
                                    Map.of("allow-local-connections", "true")))
                            .register(HttpClient.class, HttpClient.newHttpClient())
                            .register(KeyValueStore.class, new MockKeyValueStore()));

            final var runtimeConfig = new NvdVulnDataSourceConfigV1()
                    .withEnabled(true)
                    .withCveFeedsUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()));

            final ExtensionTestResult testResult = factory.test(runtimeConfig);

            assertThat(testResult.isFailed()).isTrue();
            assertThat(testResult.checks()).satisfiesExactly(
                    check -> {
                        assertThat(check.name()).isEqualTo("connection");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.PASSED);
                        assertThat(check.message()).isNull();
                    },
                    check -> {
                        assertThat(check.name()).isEqualTo("feed_format");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.FAILED);
                        assertThat(check.message()).isEqualTo("Failed to parse feed metadata, check logs for details");
                    });
        }

        @Test
        void shouldReportAllChecksSkippedWhenDisabled(WireMockRuntimeInfo wmRuntimeInfo) {
            factory.init(
                    new MutableServiceRegistry()
                            .register(ConfigRegistry.class, new MockConfigRegistry(
                                    Map.of("allow-local-connections", "true")))
                            .register(HttpClient.class, HttpClient.newHttpClient())
                            .register(KeyValueStore.class, new MockKeyValueStore()));

            final var runtimeConfig = new NvdVulnDataSourceConfigV1()
                    .withEnabled(false)
                    .withCveFeedsUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()));

            final ExtensionTestResult testResult = factory.test(runtimeConfig);

            assertThat(testResult.isFailed()).isFalse();
            assertThat(testResult.checks()).satisfiesExactly(
                    check -> {
                        assertThat(check.name()).isEqualTo("connection");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.SKIPPED);
                        assertThat(check.message()).isNull();
                    },
                    check -> {
                        assertThat(check.name()).isEqualTo("feed_format");
                        assertThat(check.status()).isEqualTo(ExtensionTestCheck.Status.SKIPPED);
                        assertThat(check.message()).isNull();
                    });
        }

    }

}