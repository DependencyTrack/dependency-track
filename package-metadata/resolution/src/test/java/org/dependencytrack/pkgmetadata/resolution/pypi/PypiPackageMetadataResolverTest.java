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
package org.dependencytrack.pkgmetadata.resolution.pypi;

import com.github.packageurl.PackageURLBuilder;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.memory.MemoryCacheProvider;
import org.dependencytrack.pkgmetadata.resolution.api.HashAlgorithm;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.api.RetryableResolutionException;
import org.dependencytrack.plugin.api.MutableServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.plugin.testing.MockKeyValueStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.time.Instant;
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
class PypiPackageMetadataResolverTest {

    private static final String PYPI_RESPONSE = /* language=JSON */ """
            {
              "info": {
                "version": "2.0.0"
              },
              "releases": {
                "1.0.0": [{
                  "filename": "mypackage-1.0.0.tar.gz",
                  "upload_time_iso_8601": "2015-06-14T14:38:05.875222Z",
                  "digests": {
                    "md5": "aaaa1111bbbb2222cccc3333dddd4444",
                    "sha256": "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"
                  }
                }, {
                  "filename": "mypackage-1.0.0-py3-none-any.whl",
                  "upload_time_iso_8601": "2015-06-14T14:37:56.383366Z",
                  "digests": {
                    "md5": "bbbb2222cccc3333dddd4444eeee5555",
                    "sha256": "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333"
                  }
                }],
                "2.0.0": [{
                  "filename": "mypackage-2.0.0.tar.gz",
                  "upload_time_iso_8601": "2024-11-06T22:37:09.220617Z",
                  "digests": {
                    "md5": "1111222233334444555566667777aaaa",
                    "sha256": "1111222233334444555566667777aaaa8888bbbb9999cccc0000ddddeeee1111"
                  }
                }]
              }
            }
            """;

    private CacheManager cacheManager;
    private PypiPackageMetadataResolverFactory factory;
    private PackageMetadataResolver resolver;

    @BeforeEach
    void beforeEach() {
        final var cacheProvider = new MemoryCacheProvider(new SmallRyeConfigBuilder().build());
        cacheManager = cacheProvider.create();

        factory = new PypiPackageMetadataResolverFactory();
        factory.init(
                new MutableServiceRegistry()
                        .register(ConfigRegistry.class, new MockConfigRegistry(Map.of(), null, null, null))
                        .register(CacheManager.class, cacheManager)
                        .register(HttpClient.class, HttpClient.newHttpClient())
                        .register(KeyValueStore.class, new MockKeyValueStore()));
        resolver = factory.create();
    }

    @AfterEach
    void afterEach() throws Exception {
        if (factory != null) {
            factory.close();
        }
        if (cacheManager != null) {
            cacheManager.close();
        }
    }

    @Test
    void shouldResolveHashesWhenFileNameQualifierMatches(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/pypi/mypackage/json"))
                .willReturn(aResponse().withStatus(200).withBody(PYPI_RESPONSE)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
                .withName("mypackage")
                .withVersion("1.0.0")
                .withQualifier("file_name", "mypackage-1.0.0.tar.gz")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.latestVersionPublishedAt()).isEqualTo(Instant.parse("2024-11-06T22:37:09.220617Z"));
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().hashes())
                .containsEntry(HashAlgorithm.MD5, "aaaa1111bbbb2222cccc3333dddd4444")
                .containsEntry(HashAlgorithm.SHA256, "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222");
    }

    @Test
    void shouldResolveHashesForCorrectFileWhenMultipleFilesExist(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/pypi/mypackage/json"))
                .willReturn(aResponse().withStatus(200).withBody(PYPI_RESPONSE)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
                .withName("mypackage")
                .withVersion("1.0.0")
                .withQualifier("file_name", "mypackage-1.0.0-py3-none-any.whl")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.latestVersionPublishedAt()).isEqualTo(Instant.parse("2024-11-06T22:37:09.220617Z"));
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().hashes())
                .containsEntry(HashAlgorithm.MD5, "bbbb2222cccc3333dddd4444eeee5555")
                .containsEntry(HashAlgorithm.SHA256, "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333");
    }

    @Test
    void shouldNotResolveHashesWhenNoFileNameQualifier(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/pypi/mypackage/json"))
                .willReturn(aResponse().withStatus(200).withBody(PYPI_RESPONSE)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
                .withName("mypackage")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.latestVersionPublishedAt()).isEqualTo(Instant.parse("2024-11-06T22:37:09.220617Z"));
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldNotResolveHashesWhenFileNameDoesNotMatch(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/pypi/mypackage/json"))
                .willReturn(aResponse().withStatus(200).withBody(PYPI_RESPONSE)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
                .withName("mypackage")
                .withVersion("1.0.0")
                .withQualifier("file_name", "nonexistent-file.tar.gz")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.latestVersionPublishedAt()).isEqualTo(Instant.parse("2024-11-06T22:37:09.220617Z"));
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldNegativeCacheUnmatchedFileName(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/pypi/mypackage/json"))
                .willReturn(aResponse().withStatus(200).withBody(PYPI_RESPONSE)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
                .withName("mypackage")
                .withVersion("1.0.0")
                .withQualifier("file_name", "nonexistent-file.tar.gz")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        resolver.resolve(purl, repo);

        final PackageMetadata secondResult = resolver.resolve(purl, repo);
        assertThat(secondResult).isNotNull();
        assertThat(secondResult.latestVersion()).isEqualTo("2.0.0");
        assertThat(secondResult.latestVersionPublishedAt()).isEqualTo(Instant.parse("2024-11-06T22:37:09.220617Z"));
        assertThat(secondResult.artifactMetadata()).isNull();

        verify(1, getRequestedFor(urlPathEqualTo("/pypi/mypackage/json")));
    }

    @Test
    void shouldReturnNullWhenPackageNotFound(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/pypi/nonexistent/json"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
                .withName("nonexistent")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNull();
    }

    @Test
    void shouldThrowWhenRepositoryIsNull() throws Exception {
        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
                .withName("mypackage")
                .withVersion("1.0.0")
                .build();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> resolver.resolve(purl, null));
    }

    @Test
    void shouldThrowRetryableExceptionWhenRateLimited(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/pypi/mypackage/json"))
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "15")));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
                .withName("mypackage")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo))
                .satisfies(e -> assertThat(e.retryAfter()).hasSeconds(15));
    }

    @Test
    void shouldThrowRetryableExceptionOnServerError(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/pypi/mypackage/json"))
                .willReturn(aResponse().withStatus(503)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
                .withName("mypackage")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo));
    }

    @Test
    void shouldReturnNoHashesWhenVersionNotInReleases(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/pypi/mypackage/json"))
                .willReturn(aResponse().withStatus(200).withBody(PYPI_RESPONSE)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("pypi")
                .withName("mypackage")
                .withVersion("99.99.99")
                .withQualifier("file_name", "mypackage-99.99.99.tar.gz")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.latestVersionPublishedAt()).isEqualTo(Instant.parse("2024-11-06T22:37:09.220617Z"));
        assertThat(result.artifactMetadata()).isNull();
    }

}
