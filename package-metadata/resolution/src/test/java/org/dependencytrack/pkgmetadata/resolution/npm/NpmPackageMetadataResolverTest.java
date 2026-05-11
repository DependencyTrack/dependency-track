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
package org.dependencytrack.pkgmetadata.resolution.npm;

import com.github.packageurl.PackageURLBuilder;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.pkgmetadata.resolution.api.HashAlgorithm;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
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
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@WireMockTest
class NpmPackageMetadataResolverTest {

    private static final String ABBREVIATED_DOC = /* language=JSON */ """
            {
              "dist-tags": {"latest": "2.0.0"},
              "time": {
                "created": "2020-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
                "1.0.0": "2023-06-15T10:30:00.000Z",
                "2.0.0": "2024-01-01T12:00:00.000Z"
              },
              "versions": {
                "1.0.0": {
                  "dist": {
                    "shasum": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
                  }
                },
                "2.0.0": {
                  "dist": {
                    "shasum": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
                    "integrity": "sha512-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw=="
                  }
                }
              }
            }
            """;

    private NpmPackageMetadataResolverFactory factory;
    private NpmPackageMetadataResolver resolver;

    @BeforeEach
    void beforeEach() {
        factory = new NpmPackageMetadataResolverFactory();
        factory.init(
                new MutableServiceRegistry()
                        .register(CacheManager.class, new NoopCacheManager())
                        .register(ConfigRegistry.class, new MockConfigRegistry(Map.of(), null, null, null))
                        .register(HttpClient.class, HttpClient.newHttpClient()));
        resolver = (NpmPackageMetadataResolver) factory.create();
    }

    @AfterEach
    void afterEach() {
        if (factory != null) {
            factory.close();
        }
    }

    @Test
    void shouldResolveLatestVersionAndHashes(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/mypackage"))
                .willReturn(aResponse().withStatus(200).withBody(ABBREVIATED_DOC)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("npm")
                .withName("mypackage")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.latestVersionPublishedAt()).isEqualTo("2024-01-01T12:00:00.000Z");
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt()).isNotNull();
        assertThat(result.artifactMetadata().hashes()).containsKey(HashAlgorithm.SHA1);
    }

    @Test
    void shouldReturnNullWhenPackageNotFound(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/nonexistent"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("npm")
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
                .withType("npm")
                .withName("mypackage")
                .withVersion("1.0.0")
                .build();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> resolver.resolve(purl, null));
    }

    @Test
    void shouldResolveScopedPackage(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/@scope%2Fmypackage"))
                .willReturn(aResponse().withStatus(200).withBody(ABBREVIATED_DOC)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("npm")
                .withNamespace("@scope")
                .withName("mypackage")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.latestVersionPublishedAt()).isEqualTo("2024-01-01T12:00:00.000Z");
    }

    @Test
    void shouldReturnNullWhenVersionNotInDocument(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/mypackage"))
                .willReturn(aResponse().withStatus(200).withBody(ABBREVIATED_DOC)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("npm")
                .withName("mypackage")
                .withVersion("99.99.99")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.latestVersionPublishedAt()).isEqualTo("2024-01-01T12:00:00.000Z");
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldIgnoreUnknownFieldsInDocument(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/mypackage"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "name": "mypackage",
                          "description": "A test package",
                          "readme": "# mypackage\\nSome long readme content...",
                          "maintainers": [{"name": "someone", "email": "someone@example.com"}],
                          "license": "MIT",
                          "dist-tags": {"latest": "2.0.0", "next": "3.0.0-beta.1"},
                          "time": {
                            "created": "2020-01-01T00:00:00.000Z",
                            "modified": "2024-01-01T00:00:00.000Z",
                            "1.0.0": "2023-06-15T10:30:00.000Z",
                            "2.0.0": "2024-01-01T12:00:00.000Z"
                          },
                          "versions": {
                            "1.0.0": {
                              "name": "mypackage",
                              "version": "1.0.0",
                              "dependencies": {"some-dep": "^1.0.0"},
                              "dist": {
                                "shasum": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                                "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
                                "tarball": "https://registry.npmjs.org/mypackage/-/mypackage-1.0.0.tgz"
                              }
                            },
                            "2.0.0": {
                              "name": "mypackage",
                              "version": "2.0.0",
                              "dist": {
                                "shasum": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
                                "integrity": "sha512-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==",
                                "tarball": "https://registry.npmjs.org/mypackage/-/mypackage-2.0.0.tgz"
                              }
                            }
                          }
                        }
                        """)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("npm")
                .withName("mypackage")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.latestVersionPublishedAt()).isEqualTo("2024-01-01T12:00:00.000Z");
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt()).isEqualTo("2023-06-15T10:30:00Z");
        assertThat(result.artifactMetadata().hashes())
                .containsEntry(HashAlgorithm.SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assertThat(result.artifactMetadata().hashes()).containsKey(HashAlgorithm.SHA512);
    }

    @Test
    void shouldThrowRetryableExceptionWhenRateLimited(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/mypackage"))
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "60")));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("npm")
                .withName("mypackage")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo))
                .satisfies(e -> assertThat(e.retryAfter()).hasSeconds(60));
    }

    @Test
    void shouldThrowRetryableExceptionOnServerError(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/mypackage"))
                .willReturn(aResponse().withStatus(503)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("npm")
                .withName("mypackage")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo));
    }

    @Test
    void shouldSendAuthorizationHeader(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/mypackage"))
                .willReturn(aResponse().withStatus(200).withBody(ABBREVIATED_DOC)));

        final var purl = PackageURLBuilder.aPackageURL()
                .withType("npm")
                .withName("mypackage")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, "my-token");
        resolver.resolve(purl, repo);

        verify(getRequestedFor(urlPathEqualTo("/mypackage"))
                .withHeader("Authorization", equalTo("Bearer my-token")));
    }

}
