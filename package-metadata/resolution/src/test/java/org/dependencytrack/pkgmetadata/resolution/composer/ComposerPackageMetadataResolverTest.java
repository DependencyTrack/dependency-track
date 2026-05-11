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
package org.dependencytrack.pkgmetadata.resolution.composer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.memory.MemoryCacheProvider;
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

import java.io.UncheckedIOException;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static com.github.packageurl.PackageURLBuilder.aPackageURL;
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
class ComposerPackageMetadataResolverTest {

    private CacheManager cacheManager;
    private ComposerPackageMetadataResolverFactory resolverFactory;
    private PackageMetadataResolver resolver;

    @BeforeEach
    void beforeEach() {
        final var cacheProvider = new MemoryCacheProvider(new SmallRyeConfigBuilder().build());
        cacheManager = cacheProvider.create();

        resolverFactory = new ComposerPackageMetadataResolverFactory();
        resolverFactory.init(
                new MutableServiceRegistry()
                        .register(ConfigRegistry.class, new MockConfigRegistry(Map.of(), null, null, null))
                        .register(CacheManager.class, cacheManager)
                        .register(HttpClient.class, HttpClient.newHttpClient())
                        .register(KeyValueStore.class, new MockKeyValueStore()));
        resolver = resolverFactory.create();
    }

    @AfterEach
    void afterEach() throws Exception {
        if (resolverFactory != null) {
            resolverFactory.close();
        }
        if (cacheManager != null) {
            cacheManager.close();
        }
    }

    @Test
    void shouldResolveViaV2MetadataUrl(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/packagist-v2-packages.json");
        stubJsonFile("/p2/typo3/class-alias-loader.json", "composer/typo3-class-alias-loader.json");

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("typo3")
                .withName("class-alias-loader")
                .withVersion("v1.1.0")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v1.2.0");
        assertThat(result.latestVersionPublishedAt()).isEqualTo("2024-10-11T08:11:39Z");
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt()).isEqualTo("2020-04-29T19:51:20Z");
    }

    @Test
    void shouldResolveViaV1FallbackUrl(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/packagist-v1-packages.json");
        stubFor(get(urlPathEqualTo("/p/vendor/package.json"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "packages": {
                            "vendor/package": {
                              "3.8.1": {"version": "3.8.1", "time": "2024-12-05T17:15:07+00:00"},
                              "3.7.0": {"version": "3.7.0", "time": "2024-11-01T10:00:00+00:00"},
                              "dev-main": {"version": "dev-main"}
                            }
                          }
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("package")
                .withVersion("3.7.0")
                .build();

        final var repo = new PackageRepository("v1", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("3.8.1");
        assertThat(result.latestVersionPublishedAt()).isEqualTo("2024-12-05T17:15:07Z");
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt()).isEqualTo("2024-11-01T10:00:00Z");
    }

    @Test
    void shouldResolveArtifactMetadataWithMixedVPrefix(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/packagist-v2-packages.json");
        stubFor(get(urlPathEqualTo("/p2/vendor/package.json"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "packages": {
                            "vendor/package": [
                              {"version": "v2.0.0", "time": "2024-10-11T08:11:39+00:00"},
                              {"version": "v1.0.0", "time": "2024-01-01T00:00:00+00:00"}
                            ]
                          }
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("package")
                .withVersion("2.0.0")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v2.0.0");
        assertThat(result.latestVersionPublishedAt()).isEqualTo("2024-10-11T08:11:39Z");
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt()).isEqualTo("2024-10-11T08:11:39Z");
    }

    @Test
    void shouldResolveFromInlinePackages(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/therepo/packages.json", "composer/inline-packages.json");

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("dummyspace")
                .withName("base")
                .withVersion("1.1.0")
                .build();

        final var repo = new PackageRepository("dummy", wmRuntimeInfo.getHttpBaseUrl() + "/therepo", null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.18.0");
        assertThat(result.artifactMetadata()).isNull();

        verify(1, getRequestedFor(urlPathEqualTo("/therepo/packages.json")));

        final var purl2 = aPackageURL()
                .withType("composer")
                .withNamespace("something")
                .withName("something")
                .withVersion("1.0.0")
                .build();
        assertThat(resolver.resolve(purl2, repo)).isNull();

        verify(1, getRequestedFor(urlPathEqualTo("/therepo/packages.json")));
    }

    @Test
    void shouldResolveFromIncludes(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/includes-packages.json");
        stubJsonFile("/include/all$10dbe443e5265bcae424f7fb60cd9d01b78a1b60.json",
                "composer/include-data.json");

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("space")
                .withName("cowboy")
                .withVersion("2.3.7")
                .build();

        final var repo = new PackageRepository("includes-repo", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.3.8");
        assertThat(result.latestVersionPublishedAt()).isEqualTo("2024-12-20T06:16:51Z");
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt()).isEqualTo("2024-12-10T12:14:27Z");

        verify(1, getRequestedFor(urlPathEqualTo("/packages.json")));
        verify(1, getRequestedFor(
                urlPathEqualTo("/include/all$10dbe443e5265bcae424f7fb60cd9d01b78a1b60.json")));
    }

    @Test
    void shouldPreferMetadataUrlOverIncludes(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/includes-with-metadata-url-packages.json");
        stubJsonFile("/include/all$10dbe443e5265bcae424f7fb60cd9d01b78a1b60.json", "composer/include-data.json");
        stubJsonFile("/p2/space/cowboy.json", "composer/metadata-url-space-cowboy.json");

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("space")
                .withName("cowboy")
                .withVersion("1.0.1")
                .build();

        final var repo = new PackageRepository("metadata-repo", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("6.6.6");

        verify(1, getRequestedFor(urlPathEqualTo("/packages.json")));
        verify(1, getRequestedFor(urlPathEqualTo("/p2/space/cowboy.json")));
        verify(0, getRequestedFor(
                urlPathEqualTo("/include/all$10dbe443e5265bcae424f7fb60cd9d01b78a1b60.json")));
    }

    @Test
    void shouldCachePackagesJson(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/packagist-v2-packages.json");
        stubJsonFile("/p2/typo3/class-alias-loader.json", "composer/typo3-class-alias-loader.json");

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("typo3")
                .withName("class-alias-loader")
                .withVersion("v1.1.0")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);

        resolver.resolve(purl, repo);
        verify(1, getRequestedFor(urlPathEqualTo("/packages.json")));

        resolver.resolve(purl, repo);
        verify(1, getRequestedFor(urlPathEqualTo("/packages.json")));
        verify(1, getRequestedFor(urlPathEqualTo("/p2/typo3/class-alias-loader.json")));
    }

    @Test
    void shouldReturnNullForEmptyRepoRoot(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/packages.json"))
                .willReturn(aResponse().withStatus(200).withBody("{}")));
        stubFor(get(urlPathEqualTo("/p/empty/root.json"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("empty")
                .withName("root")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("empty", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThat(resolver.resolve(purl, repo)).isNull();

        assertThat(resolver.resolve(purl, repo)).isNull();
        verify(1, getRequestedFor(urlPathEqualTo("/packages.json")));
    }

    @Test
    void shouldFilterByAvailablePackagePatterns(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/drupal-packages.json");
        stubFor(get(urlPathEqualTo("/files/packages/8/p2/drupal/mollie.json"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "packages": {
                            "drupal/mollie": [
                              {"version": "2.2.1", "version_normalized": "2.2.1.0"},
                              {"version": "2.1.0", "version_normalized": "2.1.0.0"}
                            ]
                          }
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("drupal")
                .withName("mollie")
                .withVersion("2.0.0")
                .build();

        final var repo = new PackageRepository("drupal", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThat(resolver.resolve(purl, repo)).isNotNull()
                .satisfies(r -> assertThat(r.latestVersion()).isEqualTo("2.2.1"));

        final var nonMatching = aPackageURL()
                .withType("composer")
                .withNamespace("phpunit")
                .withName("phpunit")
                .withVersion("1.0.0")
                .build();
        assertThat(resolver.resolve(nonMatching, repo)).isNull();

        verify(1, getRequestedFor(urlPathEqualTo("/packages.json")));
        verify(1, getRequestedFor(urlPathEqualTo("/files/packages/8/p2/drupal/mollie.json")));
    }

    @Test
    void shouldFilterByAvailablePackages(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/available-packages.json");
        stubFor(get(urlPathEqualTo("/repository/p2/io/captain-hook.json"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "minified": "composer/2.0",
                          "packages": {
                            "io/captain-hook": [
                              {"version": "v1.2.0", "time": "2024-10-11T08:11:39+00:00"},
                              {"version": "v1.1.0", "time": "2024-05-01T12:00:00+00:00"}
                            ]
                          }
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("io")
                .withName("captain-hook")
                .withVersion("v1.0.0")
                .build();

        final var repo = new PackageRepository("available", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThat(resolver.resolve(purl, repo)).isNotNull()
                .satisfies(r -> assertThat(r.latestVersion()).isEqualTo("v1.2.0"));

        final var nonListed = aPackageURL()
                .withType("composer")
                .withNamespace("phpunit")
                .withName("phpunit")
                .withVersion("1.0.0")
                .build();
        assertThat(resolver.resolve(nonListed, repo)).isNull();

        verify(1, getRequestedFor(urlPathEqualTo("/packages.json")));
        verify(1, getRequestedFor(urlPathEqualTo("/repository/p2/io/captain-hook.json")));
    }

    @Test
    void shouldFilterByAvailablePackagesWithPatternsFallback(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/available-packages-with-patterns.json");
        stubFor(get(urlPathEqualTo("/repository/p2/io/captain-hook.json"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "minified": "composer/2.0",
                          "packages": {
                            "io/captain-hook": [
                              {"version": "v1.2.0", "time": "2024-10-11T08:11:39+00:00"},
                              {"version": "v1.1.0", "time": "2024-05-01T12:00:00+00:00"}
                            ]
                          }
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("io")
                .withName("captain-hook")
                .withVersion("v1.0.0")
                .build();

        final var repo = new PackageRepository("patterns", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThat(resolver.resolve(purl, repo)).isNotNull()
                .satisfies(r -> assertThat(r.latestVersion()).isEqualTo("v1.2.0"));

        final var nonMatching = aPackageURL()
                .withType("composer")
                .withNamespace("io2")
                .withName("phpunit")
                .withVersion("1.0.0")
                .build();
        assertThat(resolver.resolve(nonMatching, repo)).isNull();
    }

    @Test
    void shouldReturnNullWhenPackageNotInResponse(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/packagist-v2-packages.json");
        stubFor(get(urlPathEqualTo("/p2/vendor/nonexistent.json"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {"packages": {"vendor/other": [{"version": "1.0.0"}]}}
                        """)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("nonexistent")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThat(resolver.resolve(purl, repo)).isNull();
    }

    @Test
    void shouldHandleV2MinifiedArrayFormat(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/includes-with-metadata-url-packages.json");
        stubJsonFile("/p2/galaxy/cow.json", "composer/galaxy-cow-array.json");

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("galaxy")
                .withName("cow")
                .withVersion("9.8.8")
                .build();

        final var repo = new PackageRepository("metadata-repo", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("9.9.9");
        assertThat(result.latestVersionPublishedAt()).isEqualTo("2025-01-01T00:00:00Z");
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt()).isEqualTo("2024-12-01T12:00:00Z");
    }

    @Test
    void shouldFallBackToUnstableWhenAllVersionsArePreRelease(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/packagist-v2-packages.json");
        stubFor(get(urlPathEqualTo("/p2/vendor/package.json"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "packages": {
                            "vendor/package": [
                              {"version": "v2.0.0-beta.2", "time": "2024-11-01T10:00:00+00:00"},
                              {"version": "v2.0.0-beta.1", "time": "2024-10-01T10:00:00+00:00"}
                            ]
                          }
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("package")
                .withVersion("v2.0.0-beta.1")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v2.0.0-beta.2");
    }

    @Test
    void shouldReturnNullWhenAllVersionsAreDevBranches(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/packagist-v2-packages.json");
        stubFor(get(urlPathEqualTo("/p2/vendor/package.json"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "packages": {
                            "vendor/package": [
                              {"version": "dev-main"},
                              {"version": "dev-feature/foo"},
                              {"version": "1.0.x-dev"}
                            ]
                          }
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("package")
                .withVersion("dev-main")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThat(resolver.resolve(purl, repo)).isNull();
    }

    @Test
    void shouldReturnNullFor404(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/packagist-v2-packages.json");
        stubFor(get(urlPathEqualTo("/p2/vendor/nonexistent.json"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("nonexistent")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThat(resolver.resolve(purl, repo)).isNull();
    }

    @Test
    void shouldThrowRetryableExceptionWhenRateLimited(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/packagist-v2-packages.json");
        stubFor(get(urlPathEqualTo("/p2/vendor/package.json"))
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "30")));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("package")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo))
                .satisfies(e -> assertThat(e.retryAfter()).hasSeconds(30));
    }

    @Test
    void shouldThrowRetryableExceptionOnServerError(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/packagist-v2-packages.json");
        stubFor(get(urlPathEqualTo("/p2/vendor/package.json"))
                .willReturn(aResponse().withStatus(503)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("package")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo));
    }

    @Test
    void shouldThrowWhenRepositoryIsNull() throws Exception {
        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("package")
                .withVersion("1.0.0")
                .build();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> resolver.resolve(purl, null));
    }

    @Test
    void shouldReturnNullArtifactMetadataWhenVersionNotFound(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/packagist-v2-packages.json");
        stubFor(get(urlPathEqualTo("/p2/vendor/package.json"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {"packages": {"vendor/package": [{"version": "v2.0.0", "time": "2024-10-11T08:11:39+00:00"}]}}
                        """)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("package")
                .withVersion("v1.0.0")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v2.0.0");
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldFindHighestVersionFromUnorderedObject(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/packagist-v2-packages.json");
        stubFor(get(urlPathEqualTo("/p2/vendor/package.json"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "packages": {
                            "vendor/package": {
                              "1.0.0": {"version": "1.0.0", "time": "2020-01-01T00:00:00+00:00"},
                              "2.5.0": {"version": "2.5.0", "time": "2023-06-01T00:00:00+00:00"},
                              "1.5.0": {"version": "1.5.0", "time": "2021-01-01T00:00:00+00:00"},
                              "dev-main": {"version": "dev-main"},
                              "2.0.0": {"version": "2.0.0", "time": "2022-01-01T00:00:00+00:00"}
                            }
                          }
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("package")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.5.0");
        assertThat(result.latestVersionPublishedAt()).isEqualTo("2023-06-01T00:00:00Z");
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt()).isEqualTo("2020-01-01T00:00:00Z");
    }

    @Test
    void shouldThrowWhenPackagesJsonReturns500(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/packages.json"))
                .willReturn(aResponse().withStatus(500)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("package")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("broken", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(UncheckedIOException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo));

        verify(1, getRequestedFor(urlPathEqualTo("/packages.json")));
    }

    @Test
    void shouldReturnNullArtifactMetadataWhenTimestampIsNonIso(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/packagist-v2-packages.json");
        stubFor(get(urlPathEqualTo("/p2/vendor/package.json"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "packages": {
                            "vendor/package": [
                              {"version": "1.0.0", "time": "2024-12-10 12:14:27"}
                            ]
                          }
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("package")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.0");
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldReturnNullWhenV1ResponseMissesPackage(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/packagist-v1-packages.json");
        stubFor(get(urlPathEqualTo("/p/magento/adobe-ims.json"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "packages": {
                            "other/package": {
                              "1.0.0": {"version": "1.0.0"}
                            }
                          }
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("magento")
                .withName("adobe-ims")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("v1", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThat(resolver.resolve(purl, repo)).isNull();
    }

    @Test
    void shouldNegativeCache404WithinFreshnessWindow(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/includes-with-metadata-url-packages.json");
        stubFor(get(urlPathEqualTo("/p2/space/cowboy.json"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("space")
                .withName("cowboy")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("repo", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThat(resolver.resolve(purl, repo)).isNull();
        assertThat(resolver.resolve(purl, repo)).isNull();

        verify(1, getRequestedFor(urlPathEqualTo("/p2/space/cowboy.json")));
        verify(1, getRequestedFor(urlPathEqualTo("/packages.json")));
    }

    @Test
    void shouldResolveFromIncludesWhenInlinePackagesExistButDontContainTarget(
            WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/inline-with-includes-packages.json");
        stubJsonFile("/include/all.json", "composer/include-data.json");

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("space")
                .withName("cowboy")
                .withVersion("2.3.7")
                .build();

        final var repo = new PackageRepository("mixed", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.3.8");

        verify(1, getRequestedFor(urlPathEqualTo("/packages.json")));
        verify(1, getRequestedFor(urlPathEqualTo("/include/all.json")));
    }

    @Test
    void shouldAllowPackageInAvailablePackagesEvenWhenPatternsExistButDontMatch(
            WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/available-packages-with-patterns.json");
        stubFor(get(urlPathEqualTo("/repository/p2/io2/captain-hook.json"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "packages": {
                            "io2/captain-hook": [
                              {"version": "1.0.0", "time": "2024-01-01T00:00:00+00:00"}
                            ]
                          }
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("io2")
                .withName("captain-hook")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("patterns", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.0");
    }

    @Test
    void shouldRejectMetadataUrlWithDifferentOrigin(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/packages.json"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {"metadata-url": "http://169.254.169.254/%package%.json"}
                        """)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("latest")
                .withName("meta-data")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("evil", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThat(resolver.resolve(purl, repo)).isNull();
    }

    @Test
    void shouldRejectIncludeWithPathTraversal(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/packages.json"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "includes": {
                            "../../etc/passwd": {"sha1": "abc"},
                            "https://attacker.com/config.json": {"sha1": "def"}
                          }
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("vendor")
                .withName("package")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("evil", wmRuntimeInfo.getHttpBaseUrl(), null, null);

        stubFor(get(urlPathEqualTo("/p/vendor/package.json"))
                .willReturn(aResponse().withStatus(404)));
        assertThat(resolver.resolve(purl, repo)).isNull();

        verify(0, getRequestedFor(urlPathEqualTo("/etc/passwd")));
        verify(0, getRequestedFor(urlPathEqualTo("../../etc/passwd")));
    }

    @Test
    void shouldRejectOversizedResponse(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        final var smallResolver = new ComposerPackageMetadataResolver(
                new ObjectMapper(),
                new org.dependencytrack.pkgmetadata.resolution.cache.CachingHttpClient(
                        HttpClient.newHttpClient(),
                        cacheManager.getCache("small-test"),
                        java.time.Duration.ofHours(1),
                        1024));

        stubJsonFile("/packages.json", "composer/packagist-v2-packages.json");

        stubFor(get(urlPathEqualTo("/p2/vendor/big.json"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("{\"packages\":{\"vendor/big\":["
                                + "{\"version\":\"1.0.0\"},".repeat(200)
                                + "{\"version\":\"2.0.0\"}]}}")));

        final var purl = aPackageURL()
                .withType("composer").withNamespace("vendor")
                .withName("big").withVersion("1.0.0").build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(UncheckedIOException.class)
                .isThrownBy(() -> smallResolver.resolve(purl, repo));
    }

    @Test
    void shouldUseBasicAuthWhenUsernameAndPasswordProvided(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/packagist-v2-packages.json");
        stubJsonFile("/p2/typo3/class-alias-loader.json", "composer/typo3-class-alias-loader.json");

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("typo3")
                .withName("class-alias-loader")
                .withVersion("v1.1.0")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), "user", "secret");
        assertThat(resolver.resolve(purl, repo)).isNotNull();

        final String expected = "Basic " + Base64.getEncoder().encodeToString(
                "user:secret".getBytes(StandardCharsets.UTF_8));
        verify(getRequestedFor(urlPathEqualTo("/packages.json"))
                .withHeader("Authorization", equalTo(expected)));
        verify(getRequestedFor(urlPathEqualTo("/p2/typo3/class-alias-loader.json"))
                .withHeader("Authorization", equalTo(expected)));
    }

    @Test
    void shouldUseBearerAuthWhenOnlyPasswordProvided(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubJsonFile("/packages.json", "composer/packagist-v2-packages.json");
        stubJsonFile("/p2/typo3/class-alias-loader.json", "composer/typo3-class-alias-loader.json");

        final var purl = aPackageURL()
                .withType("composer")
                .withNamespace("typo3")
                .withName("class-alias-loader")
                .withVersion("v1.1.0")
                .build();

        final var repo = new PackageRepository("packagist", wmRuntimeInfo.getHttpBaseUrl(), null, "token");
        assertThat(resolver.resolve(purl, repo)).isNotNull();

        verify(getRequestedFor(urlPathEqualTo("/packages.json"))
                .withHeader("Authorization", equalTo("Bearer token")));
        verify(getRequestedFor(urlPathEqualTo("/p2/typo3/class-alias-loader.json"))
                .withHeader("Authorization", equalTo("Bearer token")));
    }

    private static void stubJsonFile(String path, String bodyFile) {
        stubFor(get(urlPathEqualTo(path))
                .willReturn(aResponse().withStatus(200).withBodyFile(bodyFile)));
    }

}
