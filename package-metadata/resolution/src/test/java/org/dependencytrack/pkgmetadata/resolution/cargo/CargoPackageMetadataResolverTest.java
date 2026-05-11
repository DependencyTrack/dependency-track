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
package org.dependencytrack.pkgmetadata.resolution.cargo;

import com.github.packageurl.PackageURLBuilder;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.pkgmetadata.resolution.api.HashAlgorithm;
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
class CargoPackageMetadataResolverTest {

    private CargoPackageMetadataResolverFactory resolverFactory;
    private PackageMetadataResolver resolver;

    @BeforeEach
    void beforeEach() {
        resolverFactory = new CargoPackageMetadataResolverFactory();
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
    void shouldResolveLatestVersionWithArtifactMetadata(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/api/v1/crates/serde"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                {
                  "crate": { "newest_version": "1.0.200" },
                  "versions": [
                    {
                      "num": "1.0.200",
                      "created_at": "2024-01-15T10:30:00Z",
                      "checksum": "0e0580d37234d8aeb18c8d2ce6b5e093366c3a52fb7eb5a2f7d2100635122b07"
                    },
                    {
                      "num": "1.0.199",
                      "created_at": "2023-12-01T08:00:00Z",
                      "checksum": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    }
                  ]
                }
                """)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.200")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.200");
        assertThat(result.latestVersionPublishedAt())
                .isEqualTo(Instant.parse("2024-01-15T10:30:00Z"));
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2024-01-15T10:30:00Z"));
        assertThat(result.artifactMetadata().hashes())
                .containsOnly(Map.entry(HashAlgorithm.SHA256,
                        "0e0580d37234d8aeb18c8d2ce6b5e093366c3a52fb7eb5a2f7d2100635122b07"));
    }

    @Test
    void shouldResolveOlderArtifactMetadata(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/api/v1/crates/serde"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                {
                  "crate": { "newest_version": "1.0.200" },
                  "versions": [
                    {
                      "num": "1.0.200",
                      "created_at": "2024-01-15T10:30:00Z",
                      "checksum": "0e0580d37234d8aeb18c8d2ce6b5e093366c3a52fb7eb5a2f7d2100635122b07"
                    },
                    {
                      "num": "1.0.150",
                      "created_at": "2023-06-01T12:00:00Z",
                      "checksum": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    }
                  ]
                }
                """)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.150")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.200");
        assertThat(result.latestVersionPublishedAt())
                .isEqualTo(Instant.parse("2024-01-15T10:30:00Z"));
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2023-06-01T12:00:00Z"));
        assertThat(result.artifactMetadata().hashes())
                .containsOnly(Map.entry(HashAlgorithm.SHA256,
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
    }

    @Test
    void shouldReturnNullArtifactMetadataWhenVersionNotInResponse(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/api/v1/crates/serde"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                {
                  "crate": { "newest_version": "1.0.200" },
                  "versions": [
                    { "num": "1.0.200", "created_at": "2024-01-15T10:30:00Z", "checksum": "0e0580d37234d8aeb18c8d2ce6b5e093366c3a52fb7eb5a2f7d2100635122b07" }
                  ]
                }
                """)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("0.9.0")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.200");
        assertThat(result.latestVersionPublishedAt())
                .isEqualTo(Instant.parse("2024-01-15T10:30:00Z"));
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldReturnNullWhenCrateNotFound(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/api/v1/crates/nonexistent"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("cargo")
                .withName("nonexistent")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNull();
    }

    @Test
    void shouldThrowWhenRepositoryIsNull() throws Exception {
        final var purl = PackageURLBuilder.aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.0")
                .build();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> resolver.resolve(purl, null));
    }

    @Test
    void shouldHandleVersionWithoutChecksum(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/api/v1/crates/serde"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                {
                  "crate": { "newest_version": "1.0.200" },
                  "versions": [
                    { "num": "1.0.200", "created_at": "2024-01-15T10:30:00Z" }
                  ]
                }
                """)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.200")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2024-01-15T10:30:00Z"));
        assertThat(result.artifactMetadata().hashes()).isEmpty();
    }

    @Test
    void shouldHandleInvalidChecksum(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/api/v1/crates/serde"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                {
                  "crate": { "newest_version": "1.0.200" },
                  "versions": [
                    { "num": "1.0.200", "created_at": "2024-01-15T10:30:00Z", "checksum": "not-a-valid-hash" }
                  ]
                }
                """)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.200")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().hashes()).isEmpty();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2024-01-15T10:30:00Z"));
    }

    @Test
    void shouldThrowRetryableExceptionWhenRateLimited(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/api/v1/crates/serde"))
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "30")));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo))
                .satisfies(e -> assertThat(e.retryAfter()).hasSeconds(30));
    }

    @Test
    void shouldThrowRetryableExceptionOnServerError(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/api/v1/crates/serde"))
                .willReturn(aResponse().withStatus(503)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo));
    }

    @Test
    void shouldReturnNullNewestVersionWhenMissing(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/api/v1/crates/serde"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                {
                  "crate": {},
                  "versions": []
                }
                """)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNull();
    }

    @Test
    void shouldUseBasicAuthWhenUsernameAndPasswordProvided(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/api/v1/crates/serde"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {"crate": {"newest_version": "1.0.0"}, "versions": []}
                        """)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("cargo").withName("serde").withVersion("1.0.0").build();

        final var repo = new PackageRepository("crates", wmRuntimeInfo.getHttpBaseUrl(), "user", "secret");
        assertThat(resolver.resolve(purl, repo)).isNotNull();

        final String expected = "Basic " + Base64.getEncoder().encodeToString(
                "user:secret".getBytes(StandardCharsets.UTF_8));
        verify(getRequestedFor(urlPathEqualTo("/api/v1/crates/serde"))
                .withHeader("Authorization", equalTo(expected)));
    }

    @Test
    void shouldUseBearerAuthWhenOnlyPasswordProvided(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/api/v1/crates/serde"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {"crate": {"newest_version": "1.0.0"}, "versions": []}
                        """)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("cargo").withName("serde").withVersion("1.0.0").build();

        final var repo = new PackageRepository("crates", wmRuntimeInfo.getHttpBaseUrl(), null, "token");
        assertThat(resolver.resolve(purl, repo)).isNotNull();

        verify(getRequestedFor(urlPathEqualTo("/api/v1/crates/serde"))
                .withHeader("Authorization", equalTo("Bearer token")));
    }

}
