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
package org.dependencytrack.pkgmetadata.resolution.maven;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.memory.MemoryCacheProvider;
import org.dependencytrack.pkgmetadata.resolution.api.HashAlgorithm;
import org.dependencytrack.pkgmetadata.resolution.api.PackageArtifactMetadata;
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import static com.github.packageurl.PackageURLBuilder.aPackageURL;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.head;
import static com.github.tomakehurst.wiremock.client.WireMock.headRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.pkgmetadata.resolution.maven.MavenPackageMetadataResolver.isSnapshotVersion;

@WireMockTest
class MavenPackageMetadataResolverTest {

    private CacheManager cacheManager;
    private MavenPackageMetadataResolverFactory factory;
    private PackageMetadataResolver resolver;

    @BeforeEach
    void beforeEach() {
        final var cacheProvider = new MemoryCacheProvider(new SmallRyeConfigBuilder().build());
        cacheManager = cacheProvider.create();

        factory = new MavenPackageMetadataResolverFactory();
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
    void shouldResolveLatestVersionHashAndPublishedAt(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=XML */ """
                        <?xml version="1.0" encoding="UTF-8"?>
                        <metadata>
                          <groupId>com.example</groupId>
                          <artifactId>mylib</artifactId>
                          <versioning>
                            <latest>2.0.0</latest>
                          </versioning>
                        </metadata>
                        """)));
        stubFor(head(urlPathEqualTo("/com/example/mylib/2.0.0/mylib-2.0.0.jar"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Last-Modified", "Sat, 04 Nov 2023 12:00:00 GMT")));
        stubFor(get(urlPathEqualTo("/com/example/mylib/2.0.0/mylib-2.0.0.jar.sha1"))
                .willReturn(aResponse().withStatus(200)
                        .withBody("da39a3ee5e6b4b0d3255bfef95601890afd80709")));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .withVersion("2.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.latestVersionPublishedAt())
                .isEqualTo(Instant.parse("2023-11-04T12:00:00Z"));
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2023-11-04T12:00:00Z"));
        assertThat(result.artifactMetadata().hashes())
                .containsOnly(Map.entry(HashAlgorithm.SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    }

    @Test
    void shouldResolveWithoutPublishedAtWhenHeadFails(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=XML */ """
                        <?xml version="1.0" encoding="UTF-8"?>
                        <metadata>
                          <groupId>com.example</groupId>
                          <artifactId>mylib</artifactId>
                          <versioning>
                            <latest>1.0.0</latest>
                          </versioning>
                        </metadata>
                        """)));
        stubFor(head(urlPathEqualTo("/com/example/mylib/1.0.0/mylib-1.0.0.jar"))
                .willReturn(aResponse().withStatus(404)));
        stubFor(get(urlPathEqualTo("/com/example/mylib/1.0.0/mylib-1.0.0.jar.sha1"))
                .willReturn(aResponse().withStatus(200)
                        .withBody("da39a3ee5e6b4b0d3255bfef95601890afd80709")));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersionPublishedAt()).isNull();
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt()).isNull();
        assertThat(result.artifactMetadata().hashes())
                .containsEntry(HashAlgorithm.SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    @Test
    void shouldResolveWithVersionDifferentFromLatest(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=XML */ """
                        <?xml version="1.0" encoding="UTF-8"?>
                        <metadata>
                          <groupId>com.example</groupId>
                          <artifactId>mylib</artifactId>
                          <versioning>
                            <latest>3.0.0</latest>
                            <versions>
                              <version>1.5.0</version>
                              <version>3.0.0</version>
                            </versions>
                          </versioning>
                        </metadata>
                        """)));
        stubFor(head(urlPathEqualTo("/com/example/mylib/1.5.0/mylib-1.5.0.jar"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Last-Modified", "Wed, 01 Mar 2023 10:00:00 GMT")));
        stubFor(get(urlPathEqualTo("/com/example/mylib/1.5.0/mylib-1.5.0.jar.sha1"))
                .willReturn(aResponse().withStatus(200)
                        .withBody("da39a3ee5e6b4b0d3255bfef95601890afd80709")));
        stubFor(head(urlPathEqualTo("/com/example/mylib/3.0.0/mylib-3.0.0.jar"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Last-Modified", "Thu, 02 Mar 2023 10:00:00 GMT")));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .withVersion("1.5.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("3.0.0");
        assertThat(result.latestVersionPublishedAt())
                .isEqualTo(Instant.parse("2023-03-02T10:00:00Z"));
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2023-03-01T10:00:00Z"));
        assertThat(result.artifactMetadata().hashes())
                .containsEntry(HashAlgorithm.SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    @Test
    void shouldFallBackToLastVersionWhenNoLatestElement(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=XML */ """
                        <?xml version="1.0" encoding="UTF-8"?>
                        <metadata>
                          <groupId>com.example</groupId>
                          <artifactId>mylib</artifactId>
                          <versioning>
                            <versions>
                              <version>1.0.0</version>
                              <version>2.0.0</version>
                            </versions>
                          </versioning>
                        </metadata>
                        """)));
        stubFor(head(urlPathEqualTo("/com/example/mylib/2.0.0/mylib-2.0.0.jar"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Last-Modified", "Wed, 01 Mar 2023 10:00:00 GMT")));
        stubFor(get(urlPathEqualTo("/com/example/mylib/2.0.0/mylib-2.0.0.jar.sha1"))
                .willReturn(aResponse().withStatus(200)
                        .withBody("da39a3ee5e6b4b0d3255bfef95601890afd80709")));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .withVersion("2.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.latestVersionPublishedAt())
                .isEqualTo(Instant.parse("2023-03-01T10:00:00Z"));
    }

    @Test
    void shouldPreferHighestStableVersionOverUnstableLatest(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/io/micrometer/micrometer-observation/maven-metadata.xml"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(/* language=XML */ """
                                <?xml version="1.0" encoding="UTF-8"?>
                                <metadata>
                                  <groupId>io.micrometer</groupId>
                                  <artifactId>micrometer-observation</artifactId>
                                  <versioning>
                                    <latest>1.17.0-RC1</latest>
                                    <release>1.17.0-RC1</release>
                                    <versions>
                                      <version>1.16.4</version>
                                      <version>1.16.5</version>
                                      <version>1.17.0-M1</version>
                                      <version>1.17.0-M2</version>
                                      <version>1.17.0-RC1</version>
                                    </versions>
                                  </versioning>
                                </metadata>
                                """)));
        stubFor(head(urlPathEqualTo("/io/micrometer/micrometer-observation/1.16.5/micrometer-observation-1.16.5.jar"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Last-Modified", "Mon, 14 Apr 2025 09:00:00 GMT")));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("io.micrometer")
                .withName("micrometer-observation")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.16.5");
        assertThat(result.latestVersionPublishedAt())
                .isEqualTo(Instant.parse("2025-04-14T09:00:00Z"));
    }

    @Test
    void shouldFallBackToLatestWhenAllVersionsAreUnstable(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=XML */ """
                        <?xml version="1.0" encoding="UTF-8"?>
                        <metadata>
                          <groupId>com.example</groupId>
                          <artifactId>mylib</artifactId>
                          <versioning>
                            <latest>2.0.0-RC1</latest>
                            <versions>
                              <version>2.0.0-M1</version>
                              <version>2.0.0-RC1</version>
                            </versions>
                          </versioning>
                        </metadata>
                        """)));
        stubFor(head(urlPathEqualTo("/com/example/mylib/2.0.0-RC1/mylib-2.0.0-RC1.jar"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0-RC1");
    }

    @Test
    void shouldReturnNullWhenMetadataXmlNotFound(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNull();
    }

    @Test
    void shouldThrowWhenRepositoryIsNull() throws Exception {
        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .withVersion("1.0.0")
                .build();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> resolver.resolve(purl, null, null));
    }

    @Test
    void shouldHandleBsdStyleChecksumFormat(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=XML */ """
                        <?xml version="1.0" encoding="UTF-8"?>
                        <metadata>
                          <groupId>com.example</groupId>
                          <artifactId>mylib</artifactId>
                          <versioning>
                            <latest>1.0.0</latest>
                          </versioning>
                        </metadata>
                        """)));
        stubFor(head(urlPathEqualTo("/com/example/mylib/1.0.0/mylib-1.0.0.jar"))
                .willReturn(aResponse().withStatus(200)));
        stubFor(get(urlPathEqualTo("/com/example/mylib/1.0.0/mylib-1.0.0.jar.sha1"))
                .willReturn(aResponse().withStatus(200)
                        .withBody("da39a3ee5e6b4b0d3255bfef95601890afd80709  mylib-1.0.0.jar")));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().hashes())
                .containsEntry(HashAlgorithm.SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    @Test
    void shouldIgnoreInvalidHashValues(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=XML */ """
                        <?xml version="1.0" encoding="UTF-8"?>
                        <metadata>
                          <groupId>com.example</groupId>
                          <artifactId>mylib</artifactId>
                          <versioning>
                            <latest>1.0.0</latest>
                          </versioning>
                        </metadata>
                        """)));
        stubFor(head(urlPathEqualTo("/com/example/mylib/1.0.0/mylib-1.0.0.jar"))
                .willReturn(aResponse().withStatus(200)));
        stubFor(get(urlPathEqualTo("/com/example/mylib/1.0.0/mylib-1.0.0.jar.sha1"))
                .willReturn(aResponse().withStatus(200).withBody("abc123")));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.0");
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldResolveWithClassifierQualifier(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=XML */ """
                        <?xml version="1.0" encoding="UTF-8"?>
                        <metadata>
                          <groupId>com.example</groupId>
                          <artifactId>mylib</artifactId>
                          <versioning>
                            <latest>1.0.0</latest>
                          </versioning>
                        </metadata>
                        """)));
        stubFor(head(urlPathEqualTo("/com/example/mylib/1.0.0/mylib-1.0.0-sources.jar"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Last-Modified", "Sat, 04 Nov 2023 12:00:00 GMT")));
        stubFor(get(urlPathEqualTo("/com/example/mylib/1.0.0/mylib-1.0.0-sources.jar.sha1"))
                .willReturn(aResponse().withStatus(200)
                        .withBody("da39a3ee5e6b4b0d3255bfef95601890afd80709")));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .withVersion("1.0.0")
                .withQualifier("classifier", "sources")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.0");
        assertThat(result.latestVersionPublishedAt())
                .isEqualTo(Instant.parse("2023-11-04T12:00:00Z"));
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2023-11-04T12:00:00Z"));
        assertThat(result.artifactMetadata().hashes())
                .containsEntry(HashAlgorithm.SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    @Test
    void shouldThrowRetryableExceptionWhenRateLimited(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "20")));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo, null))
                .satisfies(e -> assertThat(e.retryAfter()).hasSeconds(20));
    }

    @Test
    void shouldThrowRetryableExceptionOnServerError(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .willReturn(aResponse().withStatus(503)));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo, null));
    }

    @Test
    void shouldUseCachedMetadataOnSecondResolve(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=XML */ """
                        <?xml version="1.0" encoding="UTF-8"?>
                        <metadata>
                          <groupId>com.example</groupId>
                          <artifactId>mylib</artifactId>
                          <versioning>
                            <latest>2.0.0</latest>
                          </versioning>
                        </metadata>
                        """)));
        stubFor(head(urlPathEqualTo("/com/example/mylib/2.0.0/mylib-2.0.0.jar"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Last-Modified", "Sat, 04 Nov 2023 12:00:00 GMT")));
        stubFor(get(urlPathEqualTo("/com/example/mylib/2.0.0/mylib-2.0.0.jar.sha1"))
                .willReturn(aResponse().withStatus(200)
                        .withBody("da39a3ee5e6b4b0d3255bfef95601890afd80709")));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .withVersion("2.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata firstResult = resolver.resolve(purl, repo, null);
        final PackageMetadata secondResult = resolver.resolve(purl, repo, null);

        assertThat(firstResult).isNotNull();
        assertThat(firstResult.latestVersion()).isEqualTo("2.0.0");
        assertThat(firstResult.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2023-11-04T12:00:00Z"));
        assertThat(secondResult).isNotNull();
        assertThat(secondResult.latestVersion()).isEqualTo("2.0.0");

        // Second resolution reuses the cached body without contacting upstream.
        verify(1, getRequestedFor(urlPathEqualTo("/com/example/mylib/maven-metadata.xml")));
        verify(1, headRequestedFor(urlPathEqualTo("/com/example/mylib/2.0.0/mylib-2.0.0.jar")));
        verify(1, getRequestedFor(urlPathEqualTo("/com/example/mylib/2.0.0/mylib-2.0.0.jar.sha1")));
    }

    @Test
    void shouldResolveWithoutVersionWhenPurlHasNoVersion(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=XML */ """
                        <?xml version="1.0" encoding="UTF-8"?>
                        <metadata>
                          <groupId>com.example</groupId>
                          <artifactId>mylib</artifactId>
                          <versioning>
                            <latest>2.0.0</latest>
                          </versioning>
                        </metadata>
                        """)));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("2.0.0");
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldUseBasicAuthWhenUsernameAndPasswordProvided(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=XML */ """
                        <?xml version="1.0" encoding="UTF-8"?>
                        <metadata>
                          <versioning><latest>1.0.0</latest></versioning>
                        </metadata>
                        """)));
        stubFor(head(urlPathEqualTo("/com/example/mylib/1.0.0/mylib-1.0.0.jar"))
                .willReturn(aResponse().withStatus(404)));
        stubFor(get(urlPathEqualTo("/com/example/mylib/1.0.0/mylib-1.0.0.jar.sha1"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), "user", "secret");
        assertThat(resolver.resolve(purl, repo, null)).isNotNull();

        final String expected = "Basic " + Base64.getEncoder().encodeToString(
                "user:secret".getBytes(StandardCharsets.UTF_8));
        verify(getRequestedFor(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .withHeader("Authorization", equalTo(expected)));
    }

    @Test
    void shouldUseBearerAuthWhenOnlyPasswordProvided(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=XML */ """
                        <?xml version="1.0" encoding="UTF-8"?>
                        <metadata>
                          <versioning><latest>1.0.0</latest></versioning>
                        </metadata>
                        """)));
        stubFor(head(urlPathEqualTo("/com/example/mylib/1.0.0/mylib-1.0.0.jar"))
                .willReturn(aResponse().withStatus(404)));
        stubFor(get(urlPathEqualTo("/com/example/mylib/1.0.0/mylib-1.0.0.jar.sha1"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, "token");
        assertThat(resolver.resolve(purl, repo, null)).isNotNull();

        verify(getRequestedFor(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .withHeader("Authorization", equalTo("Bearer token")));
    }

    @Test
    void shouldUsePriorPublishedAtAndSha1WhenAvailable(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=XML */ """
                        <?xml version="1.0" encoding="UTF-8"?>
                        <metadata>
                          <versioning><latest>2.0.0</latest></versioning>
                        </metadata>
                        """)));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .withVersion("1.0.0")
                .build();
        final var prior = new PackageArtifactMetadata(
                Instant.parse("2023-01-01T00:00:00Z"),
                Instant.parse("2023-06-15T12:00:00Z"),
                Map.of(HashAlgorithm.SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709"));

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, prior);

        assertThat(result).isNotNull();
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2023-06-15T12:00:00Z"));
        assertThat(result.artifactMetadata().hashes())
                .containsEntry(HashAlgorithm.SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

        verify(0, headRequestedFor(urlPathEqualTo("/com/example/mylib/1.0.0/mylib-1.0.0.jar")));
        verify(0, getRequestedFor(urlPathEqualTo("/com/example/mylib/1.0.0/mylib-1.0.0.jar.sha1")));
    }

    @Test
    void shouldRefetchSnapshotVersionsEvenWithPrior(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=XML */ """
                        <?xml version="1.0" encoding="UTF-8"?>
                        <metadata>
                          <versioning><latest>2.0.0</latest></versioning>
                        </metadata>
                        """)));
        stubFor(head(urlPathEqualTo("/com/example/mylib/1.0-SNAPSHOT/mylib-1.0-SNAPSHOT.jar"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Last-Modified", "Sat, 04 Nov 2023 12:00:00 GMT")));
        stubFor(get(urlPathEqualTo("/com/example/mylib/1.0-SNAPSHOT/mylib-1.0-SNAPSHOT.jar.sha1"))
                .willReturn(aResponse().withStatus(200)
                        .withBody("da39a3ee5e6b4b0d3255bfef95601890afd80709")));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .withVersion("1.0-SNAPSHOT")
                .build();
        final var prior = new PackageArtifactMetadata(
                Instant.parse("2023-01-01T00:00:00Z"),
                Instant.parse("2023-01-01T00:00:00Z"),
                Map.of(HashAlgorithm.SHA1, "0000000000000000000000000000000000000000"));

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        resolver.resolve(purl, repo, prior);

        verify(1, headRequestedFor(urlPathEqualTo("/com/example/mylib/1.0-SNAPSHOT/mylib-1.0-SNAPSHOT.jar")));
        verify(1, getRequestedFor(urlPathEqualTo("/com/example/mylib/1.0-SNAPSHOT/mylib-1.0-SNAPSHOT.jar.sha1")));
    }

    @Test
    void shouldRefetchSha1WhenPriorMissesIt(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/com/example/mylib/maven-metadata.xml"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=XML */ """
                        <?xml version="1.0" encoding="UTF-8"?>
                        <metadata>
                          <versioning><latest>2.0.0</latest></versioning>
                        </metadata>
                        """)));
        stubFor(get(urlPathEqualTo("/com/example/mylib/1.0.0/mylib-1.0.0.jar.sha1"))
                .willReturn(aResponse().withStatus(200)
                        .withBody("da39a3ee5e6b4b0d3255bfef95601890afd80709")));

        final var purl = aPackageURL()
                .withType("maven")
                .withNamespace("com.example")
                .withName("mylib")
                .withVersion("1.0.0")
                .build();
        final var prior = new PackageArtifactMetadata(
                Instant.parse("2023-01-01T00:00:00Z"),
                Instant.parse("2023-06-15T12:00:00Z"),
                Map.of() /* no SHA1 */);

        final var repo = new PackageRepository("test", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        resolver.resolve(purl, repo, prior);

        verify(0, headRequestedFor(urlPathEqualTo("/com/example/mylib/1.0.0/mylib-1.0.0.jar")));
        verify(1, getRequestedFor(urlPathEqualTo("/com/example/mylib/1.0.0/mylib-1.0.0.jar.sha1")));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "1.0-SNAPSHOT",
            "1.2.3-SNAPSHOT",
            "1.0-snapshot",
            "1.0-Snapshot"
    })
    void shouldClassifySnapshotVersions(String version) {
        assertThat(isSnapshotVersion(version)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "1.0",
            "1.2.3",
            "5.7.0",
            "1.0-1",
            "1.0-alpha",
            "2.0.0-rc1",
            "1.0.0.Final",
            "1.0-20231215.123456-1"
    })
    void shouldClassifyNonSnapshotVersions(String version) {
        assertThat(isSnapshotVersion(version)).isFalse();
    }

}
