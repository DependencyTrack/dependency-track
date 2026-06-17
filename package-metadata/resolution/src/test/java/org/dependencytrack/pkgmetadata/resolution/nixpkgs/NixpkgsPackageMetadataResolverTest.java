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
package org.dependencytrack.pkgmetadata.resolution.nixpkgs;

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
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@WireMockTest
class NixpkgsPackageMetadataResolverTest {

    private NixpkgsPackageMetadataResolverFactory resolverFactory;
    private PackageMetadataResolver resolver;

    @BeforeEach
    void beforeEach() {
        resolverFactory = new NixpkgsPackageMetadataResolverFactory();
        resolverFactory.init(
                new MutableServiceRegistry()
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
    void shouldResolveLatestVersion(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/packages.json.br"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBodyFile("nixpkgs/packages.json.br")));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("nixpkgs")
                .withName("curl")
                .withVersion("8.5.0")
                .build();

        final var repo = new PackageRepository("nixpkgs",
                wmRuntimeInfo.getHttpBaseUrl() + "/packages.json.br", null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("8.7.1");
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldReturnNullWhenPackageNotFound(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/packages.json.br"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBodyFile("nixpkgs/packages.json.br")));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("nixpkgs")
                .withName("nonexistent")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("nixpkgs",
                wmRuntimeInfo.getHttpBaseUrl() + "/packages.json.br", null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNull();
    }

    @Test
    void shouldNotRedownloadWithinRefreshInterval(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/packages.json.br"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBodyFile("nixpkgs/packages.json.br")));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("nixpkgs")
                .withName("curl")
                .withVersion("8.5.0")
                .build();

        final var repo = new PackageRepository("nixpkgs",
                wmRuntimeInfo.getHttpBaseUrl() + "/packages.json.br", null, null);

        resolver.resolve(purl, repo, null);

        final var purl2 = PackageURLBuilder.aPackageURL()
                .withType("nixpkgs")
                .withName("git")
                .withVersion("2.40.0")
                .build();

        final PackageMetadata result = resolver.resolve(purl2, repo, null);
        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.44.0");

        verify(1, getRequestedFor(urlPathEqualTo("/packages.json.br")));
    }

    @Test
    void shouldThrowWhenRepositoryIsNull() throws Exception {
        final var purl = PackageURLBuilder.aPackageURL()
                .withType("nixpkgs")
                .withName("curl")
                .withVersion("1.0.0")
                .build();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> resolver.resolve(purl, null, null));
    }

    @Test
    void shouldThrowRetryableExceptionWhenRateLimited(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/packages.json.br"))
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "30")));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("nixpkgs")
                .withName("curl")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("nixpkgs",
                wmRuntimeInfo.getHttpBaseUrl() + "/packages.json.br", null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo, null))
                .satisfies(e -> assertThat(e.retryAfter()).hasSeconds(30));
    }

    @Test
    void shouldDownloadSeparatelyForDifferentRepoUrls(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/channel-a/packages.json.br"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBodyFile("nixpkgs/packages.json.br")));
        stubFor(get(urlPathEqualTo("/channel-b/packages.json.br"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBodyFile("nixpkgs/packages.json.br")));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("nixpkgs")
                .withName("curl")
                .withVersion("8.5.0")
                .build();

        final var repoA = new PackageRepository("nixpkgs",
                wmRuntimeInfo.getHttpBaseUrl() + "/channel-a/packages.json.br", null, null);
        final var repoB = new PackageRepository("nixpkgs",
                wmRuntimeInfo.getHttpBaseUrl() + "/channel-b/packages.json.br", null, null);

        final PackageMetadata resultA = resolver.resolve(purl, repoA, null);
        assertThat(resultA).isNotNull();
        assertThat(resultA.latestVersion()).isEqualTo("8.7.1");

        final PackageMetadata resultB = resolver.resolve(purl, repoB, null);
        assertThat(resultB).isNotNull();
        assertThat(resultB.latestVersion()).isEqualTo("8.7.1");

        verify(1, getRequestedFor(urlPathEqualTo("/channel-a/packages.json.br")));
        verify(1, getRequestedFor(urlPathEqualTo("/channel-b/packages.json.br")));
    }

    @Test
    void shouldThrowRetryableExceptionOnServerError(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/packages.json.br"))
                .willReturn(aResponse().withStatus(503)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("nixpkgs")
                .withName("curl")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("nixpkgs",
                wmRuntimeInfo.getHttpBaseUrl() + "/packages.json.br", null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo, null));
    }

}
