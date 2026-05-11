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
package org.dependencytrack.pkgmetadata.resolution.github;

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
import java.time.Instant;
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
class GithubPackageMetadataResolverTest {

    private GithubPackageMetadataResolverFactory resolverFactory;
    private PackageMetadataResolver resolver;

    @BeforeEach
    void beforeEach() {
        resolverFactory = new GithubPackageMetadataResolverFactory();
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
        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/latest"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "tag_name": "v1.5.0",
                          "published_at": "2024-03-15T12:00:00Z"
                        }
                        """)));

        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/tags/v1.4.0"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "tag_name": "v1.4.0",
                          "published_at": "2024-02-10T08:00:00Z"
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("github")
                .withNamespace("acme")
                .withName("project")
                .withVersion("v1.4.0")
                .build();

        final var repo = new PackageRepository("github", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v1.5.0");
        assertThat(result.latestVersionPublishedAt())
                .isEqualTo(Instant.parse("2024-03-15T12:00:00Z"));
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2024-02-10T08:00:00Z"));
    }

    @Test
    void shouldResolveArtifactMetadataFromLatestWhenVersionMatches(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/latest"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "tag_name": "v1.5.0",
                          "published_at": "2024-03-15T12:00:00Z"
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("github")
                .withNamespace("acme")
                .withName("project")
                .withVersion("v1.5.0")
                .build();

        final var repo = new PackageRepository("github", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v1.5.0");
        assertThat(result.latestVersionPublishedAt())
                .isEqualTo(Instant.parse("2024-03-15T12:00:00Z"));
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2024-03-15T12:00:00Z"));

        verify(0, getRequestedFor(urlPathEqualTo("/repos/acme/project/releases/tags/v1.5.0")));
    }

    @Test
    void shouldReturnNullArtifactMetadataWhenVersionNotFoundAsRelease(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/latest"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "tag_name": "v1.5.0",
                          "published_at": "2024-03-15T12:00:00Z"
                        }
                        """)));

        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/tags/v1.3.0"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = aPackageURL()
                .withType("github")
                .withNamespace("acme")
                .withName("project")
                .withVersion("v1.3.0")
                .build();

        final var repo = new PackageRepository("github", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v1.5.0");
        assertThat(result.latestVersionPublishedAt())
                .isEqualTo(Instant.parse("2024-03-15T12:00:00Z"));
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldReturnNullArtifactMetadataWhenPurlHasNoVersion(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/latest"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "tag_name": "v1.5.0",
                          "published_at": "2024-03-15T12:00:00Z"
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("github")
                .withNamespace("acme")
                .withName("project")
                .build();

        final var repo = new PackageRepository("github", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v1.5.0");
        assertThat(result.latestVersionPublishedAt())
                .isEqualTo(Instant.parse("2024-03-15T12:00:00Z"));
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldSendAuthorizationHeaderWhenTokenProvided(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/latest"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "tag_name": "v1.5.0",
                          "published_at": "2024-03-15T12:00:00Z"
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("github")
                .withNamespace("acme")
                .withName("project")
                .withVersion("v1.5.0")
                .build();

        final var repo = new PackageRepository("github", wmRuntimeInfo.getHttpBaseUrl(), null, "ghp_testtoken123");
        resolver.resolve(purl, repo);

        verify(getRequestedFor(urlPathEqualTo("/repos/acme/project/releases/latest"))
                .withHeader("Authorization", equalTo("Bearer ghp_testtoken123")));
    }

    @Test
    void shouldThrowWhenRepositoryIsNull() throws Exception {
        final var purl = aPackageURL()
                .withType("github")
                .withNamespace("acme")
                .withName("project")
                .withVersion("v1.0.0")
                .build();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> resolver.resolve(purl, null));
    }

    @Test
    void shouldReturnNullWhenReleaseNotFound(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/nonexistent/releases/latest"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = aPackageURL()
                .withType("github")
                .withNamespace("acme")
                .withName("nonexistent")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("github", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNull();
    }

    @Test
    void shouldThrowRetryableExceptionWhenRateLimited(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/latest"))
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "60")));

        final var purl = aPackageURL()
                .withType("github")
                .withNamespace("acme")
                .withName("project")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("github", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo))
                .satisfies(e -> assertThat(e.retryAfter()).hasSeconds(60));
    }

    @Test
    void shouldResolveCommitArtifactMetadataWhenVersionIsFullSha(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/latest"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "tag_name": "v1.5.0",
                          "published_at": "2024-03-15T12:00:00Z"
                        }
                        """)));

        stubFor(get(urlPathEqualTo("/repos/acme/project/commits/4359dee1b7bd29ee25bc78e358a1254a0277ee96"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "sha": "4359dee1b7bd29ee25bc78e358a1254a0277ee96",
                          "commit": {
                            "author": {"date": "2024-01-05T09:00:00Z"},
                            "committer": {"date": "2024-01-06T10:00:00Z"}
                          }
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("github")
                .withNamespace("acme")
                .withName("project")
                .withVersion("4359dee1b7bd29ee25bc78e358a1254a0277ee96")
                .build();

        final var repo = new PackageRepository("github", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v1.5.0");
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2024-01-05T09:00:00Z"));

        verify(0, getRequestedFor(urlPathEqualTo(
                "/repos/acme/project/releases/tags/4359dee1b7bd29ee25bc78e358a1254a0277ee96")));
    }

    @Test
    void shouldResolveCommitArtifactMetadataWhenVersionIsShortSha(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/latest"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "tag_name": "v1.5.0",
                          "published_at": "2024-03-15T12:00:00Z"
                        }
                        """)));

        stubFor(get(urlPathEqualTo("/repos/acme/project/commits/4359dee"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "sha": "4359dee1b7bd29ee25bc78e358a1254a0277ee96",
                          "commit": {
                            "author": {"date": "2024-01-05T09:00:00Z"}
                          }
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("github")
                .withNamespace("acme")
                .withName("project")
                .withVersion("4359dee")
                .build();

        final var repo = new PackageRepository("github", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v1.5.0");
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2024-01-05T09:00:00Z"));
    }

    @Test
    void shouldFallBackToCommitterDateWhenAuthorDateMissing(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/latest"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {"tag_name": "v1.5.0", "published_at": "2024-03-15T12:00:00Z"}
                        """)));

        stubFor(get(urlPathEqualTo("/repos/acme/project/commits/4359dee1b7bd29ee25bc78e358a1254a0277ee96"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "sha": "4359dee1b7bd29ee25bc78e358a1254a0277ee96",
                          "commit": {
                            "committer": {"date": "2024-01-06T10:00:00Z"}
                          }
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("github")
                .withNamespace("acme")
                .withName("project")
                .withVersion("4359dee1b7bd29ee25bc78e358a1254a0277ee96")
                .build();

        final var repo = new PackageRepository("github", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2024-01-06T10:00:00Z"));
    }

    @Test
    void shouldReturnNullArtifactMetadataWhenAuthorAndCommitterDatesMissing(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/latest"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {"tag_name": "v1.5.0", "published_at": "2024-03-15T12:00:00Z"}
                        """)));

        stubFor(get(urlPathEqualTo("/repos/acme/project/commits/4359dee1b7bd29ee25bc78e358a1254a0277ee96"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {
                          "sha": "4359dee1b7bd29ee25bc78e358a1254a0277ee96",
                          "commit": {
                            "author": null,
                            "committer": null
                          }
                        }
                        """)));

        final var purl = aPackageURL()
                .withType("github")
                .withNamespace("acme")
                .withName("project")
                .withVersion("4359dee1b7bd29ee25bc78e358a1254a0277ee96")
                .build();

        final var repo = new PackageRepository("github", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v1.5.0");
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldReturnNullArtifactMetadataWhenNeitherCommitNorTagFound(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/latest"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {"tag_name": "v1.5.0", "published_at": "2024-03-15T12:00:00Z"}
                        """)));

        stubFor(get(urlPathEqualTo("/repos/acme/project/commits/0000000"))
                .willReturn(aResponse().withStatus(404)));
        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/tags/0000000"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = aPackageURL()
                .withType("github")
                .withNamespace("acme")
                .withName("project")
                .withVersion("0000000")
                .build();

        final var repo = new PackageRepository("github", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v1.5.0");
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldFallBackToReleaseTagWhenShaShapedVersionIsActuallyATag(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/latest"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {"tag_name": "v2.0.0", "published_at": "2024-06-01T00:00:00Z"}
                        """)));

        stubFor(get(urlPathEqualTo("/repos/acme/project/commits/deadbeef"))
                .willReturn(aResponse().withStatus(404)));
        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/tags/deadbeef"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {"tag_name": "deadbeef", "published_at": "2024-04-01T00:00:00Z"}
                        """)));

        final var purl = aPackageURL()
                .withType("github")
                .withNamespace("acme")
                .withName("project")
                .withVersion("deadbeef")
                .build();

        final var repo = new PackageRepository("github", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v2.0.0");
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2024-04-01T00:00:00Z"));
    }

    @Test
    void shouldNotTreatNonShaVersionAsCommit(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/latest"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {"tag_name": "v1.5.0", "published_at": "2024-03-15T12:00:00Z"}
                        """)));

        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/tags/invalid-release"))
                .willReturn(aResponse().withStatus(404)));

        final var purl = aPackageURL()
                .withType("github")
                .withNamespace("acme")
                .withName("project")
                .withVersion("invalid-release")
                .build();

        final var repo = new PackageRepository("github", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("v1.5.0");
        assertThat(result.artifactMetadata()).isNull();
        verify(0, getRequestedFor(urlPathEqualTo("/repos/acme/project/commits/invalid-release")));
    }

    @Test
    void shouldPreferReleaseTagMatchOverShaShape(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/latest"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {"tag_name": "abcdef1", "published_at": "2024-03-15T12:00:00Z"}
                        """)));

        final var purl = aPackageURL()
                .withType("github")
                .withNamespace("acme")
                .withName("project")
                .withVersion("abcdef1")
                .build();

        final var repo = new PackageRepository("github", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("abcdef1");
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2024-03-15T12:00:00Z"));
        verify(0, getRequestedFor(urlPathEqualTo("/repos/acme/project/commits/abcdef1")));
    }

    @Test
    void shouldSendAuthorizationHeaderOnCommitsEndpoint(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/latest"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {"tag_name": "v1.5.0", "published_at": "2024-03-15T12:00:00Z"}
                        """)));

        stubFor(get(urlPathEqualTo("/repos/acme/project/commits/4359dee1b7bd29ee25bc78e358a1254a0277ee96"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSON */ """
                        {"sha": "4359dee1b7bd29ee25bc78e358a1254a0277ee96",
                         "commit": {"committer": {"date": "2024-01-06T10:00:00Z"}}}
                        """)));

        final var purl = aPackageURL()
                .withType("github")
                .withNamespace("acme")
                .withName("project")
                .withVersion("4359dee1b7bd29ee25bc78e358a1254a0277ee96")
                .build();

        final var repo = new PackageRepository("github", wmRuntimeInfo.getHttpBaseUrl(), null, "ghp_testtoken123");
        resolver.resolve(purl, repo);

        verify(getRequestedFor(urlPathEqualTo("/repos/acme/project/commits/4359dee1b7bd29ee25bc78e358a1254a0277ee96"))
                .withHeader("Authorization", equalTo("Bearer ghp_testtoken123")));
    }

    @Test
    void shouldThrowRetryableExceptionOnServerError(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/project/releases/latest"))
                .willReturn(aResponse().withStatus(503)));

        final var purl = aPackageURL()
                .withType("github")
                .withNamespace("acme")
                .withName("project")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("github", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo));
    }

}
