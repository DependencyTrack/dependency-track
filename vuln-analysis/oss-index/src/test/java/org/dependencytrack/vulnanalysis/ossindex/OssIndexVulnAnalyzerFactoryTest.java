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
package org.dependencytrack.vulnanalysis.ossindex;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.memory.MemoryCacheProvider;
import org.dependencytrack.plugin.api.ExtensionTestCheck.Status;
import org.dependencytrack.plugin.api.ExtensionTestResult;
import org.dependencytrack.plugin.api.MutableServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.testing.AbstractExtensionFactoryTest;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class OssIndexVulnAnalyzerFactoryTest extends AbstractExtensionFactoryTest<VulnAnalyzer, OssIndexVulnAnalyzerFactory> {

    OssIndexVulnAnalyzerFactoryTest() {
        super(OssIndexVulnAnalyzerFactory.class);
    }

    @Nested
    @WireMockTest
    class TestMethodTest {

        @ParameterizedTest
        @ValueSource(ints = {200, 402, 429})
        void shouldPassForSuccessStatusCodes(int statusCode, WireMockRuntimeInfo wmRuntimeInfo) {
            stubFor(post(urlPathEqualTo("/api/v3/component-report"))
                    .willReturn(aResponse()
                            .withStatus(statusCode)
                            .withBody("[]")));

            final OssIndexVulnAnalyzerFactory factory = createFactory();
            final OssIndexVulnAnalyzerConfigV1 config = createConfig(wmRuntimeInfo);
            final ExtensionTestResult result = factory.test(config);

            assertThat(result.isFailed()).isFalse();
            assertThat(result.checks()).satisfiesExactly(
                    check -> {
                        assertThat(check.name()).isEqualTo("connection");
                        assertThat(check.status()).isEqualTo(Status.PASSED);
                    },
                    check -> {
                        assertThat(check.name()).isEqualTo("authentication");
                        assertThat(check.status()).isEqualTo(Status.PASSED);
                    });
        }

        @Test
        void shouldFailAuthenticationForStatus401(WireMockRuntimeInfo wmRuntimeInfo) {
            stubFor(post(urlPathEqualTo("/api/v3/component-report"))
                    .willReturn(aResponse().withStatus(401)));

            final OssIndexVulnAnalyzerFactory factory = createFactory();
            final OssIndexVulnAnalyzerConfigV1 config = createConfig(wmRuntimeInfo);
            final ExtensionTestResult result = factory.test(config);

            assertThat(result.isFailed()).isTrue();
            assertThat(result.checks()).satisfiesExactly(
                    check -> {
                        assertThat(check.name()).isEqualTo("connection");
                        assertThat(check.status()).isEqualTo(Status.PASSED);
                    },
                    check -> {
                        assertThat(check.name()).isEqualTo("authentication");
                        assertThat(check.status()).isEqualTo(Status.FAILED);
                        assertThat(check.message()).contains("401");
                    });
        }

        @Test
        void shouldFailConnectionForUnexpectedStatusCode(WireMockRuntimeInfo wmRuntimeInfo) {
            stubFor(post(urlPathEqualTo("/api/v3/component-report"))
                    .willReturn(aResponse().withStatus(500)));

            final OssIndexVulnAnalyzerFactory factory = createFactory();
            final OssIndexVulnAnalyzerConfigV1 config = createConfig(wmRuntimeInfo);
            final ExtensionTestResult result = factory.test(config);

            assertThat(result.isFailed()).isTrue();
            assertThat(result.checks()).satisfiesExactly(
                    check -> {
                        assertThat(check.name()).isEqualTo("connection");
                        assertThat(check.status()).isEqualTo(Status.FAILED);
                        assertThat(check.message()).contains("500");
                    },
                    check -> {
                        assertThat(check.name()).isEqualTo("authentication");
                        assertThat(check.status()).isEqualTo(Status.SKIPPED);
                    });
        }

        @Test
        void shouldSkipAllChecksWhenDisabled() {
            final OssIndexVulnAnalyzerFactory factory = createFactory();
            final var config = new OssIndexVulnAnalyzerConfigV1()
                    .withEnabled(false);

            final ExtensionTestResult result = factory.test(config);

            assertThat(result.isFailed()).isFalse();
            assertThat(result.checks()).satisfiesExactly(
                    check -> {
                        assertThat(check.name()).isEqualTo("connection");
                        assertThat(check.status()).isEqualTo(Status.SKIPPED);
                    },
                    check -> {
                        assertThat(check.name()).isEqualTo("authentication");
                        assertThat(check.status()).isEqualTo(Status.SKIPPED);
                    });
        }

        @Test
        void shouldFailConnectionOnConnectionError() {
            final var factory = new OssIndexVulnAnalyzerFactory();
            final var configRegistry = new MockConfigRegistry(
                    Map.of("allow-local-connections", "true"),
                    factory.runtimeConfigSpec(),
                    null,
                    null);
            factory.init(createServiceRegistry(configRegistry));

            final var config = new OssIndexVulnAnalyzerConfigV1()
                    .withEnabled(true)
                    .withApiUrl(URI.create("http://127.0.0.1:1"))
                    .withUsername("foo@example.com")
                    .withApiToken("test-token");

            final ExtensionTestResult result = factory.test(config);

            assertThat(result.isFailed()).isTrue();
            assertThat(result.checks()).satisfiesExactly(
                    check -> {
                        assertThat(check.name()).isEqualTo("connection");
                        assertThat(check.status()).isEqualTo(Status.FAILED);
                    },
                    check -> {
                        assertThat(check.name()).isEqualTo("authentication");
                        assertThat(check.status()).isEqualTo(Status.SKIPPED);
                    });
        }

        @Test
        void shouldUseBasicAuthHeaderWhenUsernameIsPresent(WireMockRuntimeInfo wmRuntimeInfo) {
            stubFor(post(urlPathEqualTo("/api/v3/component-report"))
                    .willReturn(aResponse().withStatus(200).withBody("[]")));

            final OssIndexVulnAnalyzerFactory factory = createFactory();
            final OssIndexVulnAnalyzerConfigV1 config = new OssIndexVulnAnalyzerConfigV1()
                    .withEnabled(true)
                    .withApiUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()))
                    .withUsername("foo@example.com")
                    .withApiToken("test-token");

            final ExtensionTestResult result = factory.test(config);
            assertThat(result.isFailed()).isFalse();

            final String expected = "Basic " + Base64.getEncoder().encodeToString(
                    "foo@example.com:test-token".getBytes(StandardCharsets.UTF_8));
            verify(postRequestedFor(urlPathEqualTo("/api/v3/component-report"))
                    .withHeader("Authorization", equalTo(expected)));
        }

        @Test
        void shouldUseBearerAuthHeaderWhenUsernameIsAbsent(WireMockRuntimeInfo wmRuntimeInfo) {
            stubFor(post(urlPathEqualTo("/api/v3/component-report"))
                    .willReturn(aResponse().withStatus(200).withBody("[]")));

            final OssIndexVulnAnalyzerFactory factory = createFactory();
            final OssIndexVulnAnalyzerConfigV1 config = new OssIndexVulnAnalyzerConfigV1()
                    .withEnabled(true)
                    .withApiUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()))
                    .withApiToken("sonatype_pat_test");

            final ExtensionTestResult result = factory.test(config);
            assertThat(result.isFailed()).isFalse();

            verify(postRequestedFor(urlPathEqualTo("/api/v3/component-report"))
                    .withHeader("Authorization", equalTo("Bearer sonatype_pat_test")));
        }

        @Test
        void shouldFailConnectionForLocalAddress() {
            final var factory = new OssIndexVulnAnalyzerFactory();
            final var configRegistry = new MockConfigRegistry(
                    Collections.emptyMap(),
                    factory.runtimeConfigSpec(),
                    null,
                    null);
            factory.init(createServiceRegistry(configRegistry));

            final var config = new OssIndexVulnAnalyzerConfigV1()
                    .withEnabled(true)
                    .withApiUrl(URI.create("http://127.0.0.1"))
                    .withUsername("foo@example.com")
                    .withApiToken("test-token");

            final ExtensionTestResult result = factory.test(config);

            assertThat(result.isFailed()).isTrue();
            assertThat(result.checks()).satisfiesExactly(
                    check -> {
                        assertThat(check.name()).isEqualTo("connection");
                        assertThat(check.status()).isEqualTo(Status.FAILED);
                        assertThat(check.message()).contains("local address");
                    },
                    check -> {
                        assertThat(check.name()).isEqualTo("authentication");
                        assertThat(check.status()).isEqualTo(Status.SKIPPED);
                    });
        }

        private OssIndexVulnAnalyzerFactory createFactory() {
            final var factory = new OssIndexVulnAnalyzerFactory();

            final var effectiveDeploymentConfigs = Map.of("allow-local-connections", "true");

            final var configRegistry = new MockConfigRegistry(
                    effectiveDeploymentConfigs,
                    factory.runtimeConfigSpec(),
                    null,
                    null);
            factory.init(createServiceRegistry(configRegistry));
            return factory;
        }

        private MutableServiceRegistry createServiceRegistry(ConfigRegistry configRegistry) {
            final var cacheProvider = new MemoryCacheProvider(new SmallRyeConfigBuilder().build());
            return new MutableServiceRegistry()
                    .register(ConfigRegistry.class, configRegistry)
                    .register(CacheManager.class, cacheProvider.create())
                    .register(HttpClient.class, HttpClient.newHttpClient());
        }

        private OssIndexVulnAnalyzerConfigV1 createConfig(WireMockRuntimeInfo wmRuntimeInfo) {
            return new OssIndexVulnAnalyzerConfigV1()
                    .withEnabled(true)
                    .withApiUrl(URI.create(wmRuntimeInfo.getHttpBaseUrl()))
                    .withUsername("foo@example.com")
                    .withApiToken("test-token");
        }

    }

    @Nested
    class RuntimeConfigValidationTest {

        @Test
        void shouldSkipValidationWhenDisabled() {
            try (final var factory = new OssIndexVulnAnalyzerFactory()) {
                final RuntimeConfigSpec spec = factory.runtimeConfigSpec();
                final var config = (OssIndexVulnAnalyzerConfigV1) spec.defaultConfig();

                assertThatNoException().isThrownBy(() -> spec.validator().validate(config));
            }
        }

        @Test
        void shouldRejectConfigWithoutApiUrl() {
            try (final var factory = new OssIndexVulnAnalyzerFactory()) {
                final RuntimeConfigSpec spec = factory.runtimeConfigSpec();
                final var config = (OssIndexVulnAnalyzerConfigV1) spec.defaultConfig();
                config.withEnabled(true).withApiUrl(null);

                assertThatExceptionOfType(InvalidRuntimeConfigException.class)
                        .isThrownBy(() -> spec.validator().validate(config))
                        .withMessageContaining("No API URL provided");
            }
        }

        @Test
        void shouldRejectConfigWithoutApiToken() {
            try (final var factory = new OssIndexVulnAnalyzerFactory()) {
                final RuntimeConfigSpec spec = factory.runtimeConfigSpec();
                final var config = (OssIndexVulnAnalyzerConfigV1) spec.defaultConfig();
                config.withEnabled(true).withUsername("foo@example.com");

                assertThatExceptionOfType(InvalidRuntimeConfigException.class)
                        .isThrownBy(() -> spec.validator().validate(config))
                        .withMessageContaining("No API token provided");
            }
        }

        @Test
        void shouldRejectConfigWithoutUsernameWhenTokenIsNotPat() {
            try (final var factory = new OssIndexVulnAnalyzerFactory()) {
                final RuntimeConfigSpec spec = factory.runtimeConfigSpec();
                final var config = (OssIndexVulnAnalyzerConfigV1) spec.defaultConfig();
                config.withEnabled(true).withApiToken("some-token");

                assertThatExceptionOfType(InvalidRuntimeConfigException.class)
                        .isThrownBy(() -> spec.validator().validate(config))
                        .withMessageContaining("No username provided");
            }
        }

        @Test
        void shouldAcceptConfigWithoutUsernameWhenTokenIsPat() {
            try (final var factory = new OssIndexVulnAnalyzerFactory()) {
                final RuntimeConfigSpec spec = factory.runtimeConfigSpec();
                final var config = (OssIndexVulnAnalyzerConfigV1) spec.defaultConfig();
                config.withEnabled(true).withApiToken("sonatype_pat_test");

                assertThatNoException().isThrownBy(() -> spec.validator().validate(config));
            }
        }

        @Test
        void shouldAcceptConfigWithUsernameAndToken() {
            try (final var factory = new OssIndexVulnAnalyzerFactory()) {
                final RuntimeConfigSpec spec = factory.runtimeConfigSpec();
                final var config = (OssIndexVulnAnalyzerConfigV1) spec.defaultConfig();
                config.withEnabled(true)
                        .withUsername("foo@example.com")
                        .withApiToken("test-token");

                assertThatNoException().isThrownBy(() -> spec.validator().validate(config));
            }
        }

    }

}
