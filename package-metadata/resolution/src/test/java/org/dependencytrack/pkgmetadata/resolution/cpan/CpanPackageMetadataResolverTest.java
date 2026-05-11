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
package org.dependencytrack.pkgmetadata.resolution.cpan;

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
import java.time.Instant;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@WireMockTest
class CpanPackageMetadataResolverTest {

    private CpanPackageMetadataResolverFactory resolverFactory;
    private PackageMetadataResolver resolver;

    @BeforeEach
    void beforeEach() {
        resolverFactory = new CpanPackageMetadataResolverFactory();
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
    void shouldResolveLatestVersionAndArtifactMetadata(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/release/Moose"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "version": "2.2206",
                          "date": "2022-06-02T18:29:43",
                          "checksum_sha256": "a856e36cbe1f56e1b8dbc1b083619aa9c002be2ae64e9613be8f37e0be1527c3"
                        }
                        """)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("cpan")
                .withName("Moose")
                .withVersion("2.2206")
                .build();

        final var repo = new PackageRepository("cpan", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.2206");
        assertThat(result.latestVersionPublishedAt())
                .isEqualTo(Instant.parse("2022-06-02T18:29:43Z"));
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2022-06-02T18:29:43Z"));
        assertThat(result.artifactMetadata().hashes())
                .containsOnly(Map.entry(HashAlgorithm.SHA256,
                        "a856e36cbe1f56e1b8dbc1b083619aa9c002be2ae64e9613be8f37e0be1527c3"));
    }

    @Test
    void shouldResolveLatestVersionWithoutArtifactMetadataWhenVersionDiffers(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/release/Moose"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "version": "2.2206",
                          "date": "2022-06-02T18:29:43",
                          "checksum_sha256": "a856e36cbe1f56e1b8dbc1b083619aa9c002be2ae64e9613be8f37e0be1527c3"
                        }
                        """)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("cpan")
                .withName("Moose")
                .withVersion("2.2200")
                .build();

        final var repo = new PackageRepository("cpan", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.2206");
        assertThat(result.latestVersionPublishedAt())
                .isEqualTo(Instant.parse("2022-06-02T18:29:43Z"));
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldReturnNullWhenPackageNotFound(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/release/Nonexistent"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("cpan")
                .withName("Nonexistent")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("cpan", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNull();
    }

    @Test
    void shouldThrowWhenRepositoryIsNull() throws Exception {
        final var purl = PackageURLBuilder.aPackageURL()
                .withType("cpan")
                .withName("Moose")
                .withVersion("1.0.0")
                .build();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> resolver.resolve(purl, null));
    }

    @Test
    void shouldThrowRetryableExceptionWhenRateLimited(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/release/Moose"))
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "30")));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("cpan")
                .withName("Moose")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("cpan", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo))
                .satisfies(e -> assertThat(e.retryAfter()).hasSeconds(30));
    }

    @Test
    void shouldThrowRetryableExceptionOnServerError(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/v1/release/Moose"))
                .willReturn(aResponse().withStatus(503)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("cpan")
                .withName("Moose")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("cpan", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo));
    }

}
