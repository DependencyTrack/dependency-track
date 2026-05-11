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
package org.dependencytrack.pkgmetadata.resolution.gomodules;

import com.github.packageurl.PackageURLBuilder;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.api.RetryableResolutionException;
import org.dependencytrack.plugin.api.MutableServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@WireMockTest
class GoModulesPackageMetadataResolverTest {

    private GoModulesPackageMetadataResolverFactory resolverFactory;
    private PackageMetadataResolver resolver;

    @BeforeEach
    void beforeEach() {
        resolverFactory = new GoModulesPackageMetadataResolverFactory();
        resolverFactory.init(new MutableServiceRegistry()
                .register(CacheManager.class, new NoopCacheManager())
                .register(ConfigRegistry.class, new MockConfigRegistry(Map.of(), null, null, null))
                .register(HttpClient.class, HttpClient.newHttpClient()));
        resolver = resolverFactory.create();
    }

    @AfterEach
    void afterEach() {
        if (resolverFactory != null) {
            resolverFactory.close();
        }
    }

    @Test
    void shouldResolveLatestVersionAndPublishedAt(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/golang.org/x/text/@latest"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "Version": "v0.21.0",
                          "Time": "2024-10-01T12:00:00Z"
                        }
                        """)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("golang")
                .withNamespace("golang.org/x")
                .withName("text")
                .withVersion("v0.21.0")
                .build();

        final var repo = new PackageRepository("go-proxy", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v0.21.0");
        assertThat(result.latestVersionPublishedAt())
                .isEqualTo(Instant.parse("2024-10-01T12:00:00Z"));
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2024-10-01T12:00:00Z"));
    }

    @Test
    void shouldResolvePublishedAtForOlderVersion(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/golang.org/x/text/@latest"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "Version": "v0.21.0",
                          "Time": "2024-10-01T12:00:00Z"
                        }
                        """)));

        stubFor(get(urlPathEqualTo("/golang.org/x/text/@v/v0.19.0.info"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "Version": "v0.19.0",
                          "Time": "2024-06-15T08:00:00Z"
                        }
                        """)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("golang")
                .withNamespace("golang.org/x")
                .withName("text")
                .withVersion("v0.19.0")
                .build();

        final var repo = new PackageRepository("go-proxy", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v0.21.0");
        assertThat(result.latestVersionPublishedAt())
                .isEqualTo(Instant.parse("2024-10-01T12:00:00Z"));
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2024-06-15T08:00:00Z"));
    }

    @Test
    void shouldReturnNullWhenModuleNotFound(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/golang.org/x/nonexistent/@latest"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("golang")
                .withNamespace("golang.org/x")
                .withName("nonexistent")
                .withVersion("v1.0.0")
                .build();

        final var repo = new PackageRepository("go-proxy", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNull();
    }

    @Test
    void shouldThrowWhenRepositoryIsNull() throws Exception {
        final var purl = PackageURLBuilder.aPackageURL()
                .withType("golang")
                .withNamespace("golang.org/x")
                .withName("text")
                .withVersion("v1.0.0")
                .build();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> resolver.resolve(purl, null));
    }

    @Test
    void shouldThrowRetryableExceptionWhenRateLimited(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/golang.org/x/text/@latest"))
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "30")));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("golang")
                .withNamespace("golang.org/x")
                .withName("text")
                .withVersion("v1.0.0")
                .build();

        final var repo = new PackageRepository("go-proxy", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo))
                .satisfies(e -> assertThat(e.retryAfter()).hasSeconds(30));
    }

    @Test
    void shouldThrowRetryableExceptionOnServerError(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/golang.org/x/text/@latest"))
                .willReturn(aResponse().withStatus(503)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("golang")
                .withNamespace("golang.org/x")
                .withName("text")
                .withVersion("v1.0.0")
                .build();

        final var repo = new PackageRepository("go-proxy", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo));
    }

    @Test
    void shouldUseBasicAuthWhenUsernameAndPasswordProvided(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/golang.org/x/text/@latest"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {"Version": "v1.0.0", "Time": "2024-01-01T00:00:00Z"}
                        """)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("golang")
                .withNamespace("golang.org/x")
                .withName("text")
                .withVersion("v1.0.0")
                .build();

        final var repo = new PackageRepository("go-proxy", wmRuntimeInfo.getHttpBaseUrl(), "user", "secret");
        assertThat(resolver.resolve(purl, repo)).isNotNull();

        final String expected = "Basic " + Base64.getEncoder().encodeToString(
                "user:secret".getBytes(StandardCharsets.UTF_8));
        verify(getRequestedFor(urlPathEqualTo("/golang.org/x/text/@latest"))
                .withHeader("Authorization", equalTo(expected)));
    }

    @Test
    void shouldUseBearerAuthWhenOnlyPasswordProvided(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/golang.org/x/text/@latest"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {"Version": "v1.0.0", "Time": "2024-01-01T00:00:00Z"}
                        """)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("golang")
                .withNamespace("golang.org/x")
                .withName("text")
                .withVersion("v1.0.0")
                .build();

        final var repo = new PackageRepository("go-proxy", wmRuntimeInfo.getHttpBaseUrl(), null, "token");
        assertThat(resolver.resolve(purl, repo)).isNotNull();

        verify(getRequestedFor(urlPathEqualTo("/golang.org/x/text/@latest"))
                .withHeader("Authorization", equalTo("Bearer token")));
    }

}
