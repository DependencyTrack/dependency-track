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

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.dependencytrack.pkgmetadata.resolution.api.HashAlgorithm;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.api.RetryableResolutionException;
import org.dependencytrack.plugin.testing.ExtensionContextBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
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
class CargoPackageMetadataResolverTest {

    private CargoPackageMetadataResolverFactory resolverFactory;
    private PackageMetadataResolver resolver;

    @BeforeEach
    void beforeEach() {
        resolverFactory = new CargoPackageMetadataResolverFactory();
        resolverFactory.init(new ExtensionContextBuilder().build());
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
        stubFor(get(urlPathEqualTo("/se/rd/serde"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSONL */ """
                    {"name":"serde","vers":"1.0.199","deps":[],"cksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","features":{},"yanked":false,"pubtime":"2023-12-01T08:00:00Z"}
                    {"name":"serde","vers":"1.0.200","deps":[],"cksum":"0e0580d37234d8aeb18c8d2ce6b5e093366c3a52fb7eb5a2f7d2100635122b07","features":{},"yanked":false,"pubtime":"2024-01-15T10:30:00Z"}
                    """)));

        final var purl = aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.200")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.200");
        assertThat(result.latestVersionPublishedAt()).isEqualTo(Instant.parse("2024-01-15T10:30:00Z"));
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt()).isEqualTo(Instant.parse("2024-01-15T10:30:00Z"));
        assertThat(result.artifactMetadata().hashes())
                .containsOnly(Map.entry(
                        HashAlgorithm.SHA256, "0e0580d37234d8aeb18c8d2ce6b5e093366c3a52fb7eb5a2f7d2100635122b07"));
    }

    @Test
    void shouldResolveOlderArtifactMetadata(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/se/rd/serde"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSONL */ """
                    {"name":"serde","vers":"1.0.150","deps":[],"cksum":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","features":{},"yanked":false,"pubtime":"2023-06-01T12:00:00Z"}
                    {"name":"serde","vers":"1.0.200","deps":[],"cksum":"0e0580d37234d8aeb18c8d2ce6b5e093366c3a52fb7eb5a2f7d2100635122b07","features":{},"yanked":false,"pubtime":"2024-01-15T10:30:00Z"}
                    """)));

        final var purl = aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.150")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.200");
        assertThat(result.latestVersionPublishedAt()).isEqualTo(Instant.parse("2024-01-15T10:30:00Z"));
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt()).isEqualTo(Instant.parse("2023-06-01T12:00:00Z"));
        assertThat(result.artifactMetadata().hashes())
                .containsOnly(Map.entry(
                        HashAlgorithm.SHA256, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
    }

    @Test
    void shouldReturnNullArtifactMetadataWhenVersionNotInIndex(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/se/rd/serde"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSONL */ """
                    {"name":"serde","vers":"1.0.200","deps":[],"cksum":"0e0580d37234d8aeb18c8d2ce6b5e093366c3a52fb7eb5a2f7d2100635122b07","features":{},"yanked":false,"pubtime":"2024-01-15T10:30:00Z"}
                    """)));

        final var purl = aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("0.9.0")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.200");
        assertThat(result.latestVersionPublishedAt()).isEqualTo(Instant.parse("2024-01-15T10:30:00Z"));
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldPreferStableVersionOverPreRelease(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/be/vy/bevy"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSONL */ """
                    {"name":"bevy","vers":"0.18.1","deps":[],"cksum":"0e0580d37234d8aeb18c8d2ce6b5e093366c3a52fb7eb5a2f7d2100635122b07","features":{},"yanked":false,"pubtime":"2025-01-10T10:00:00Z"}
                    {"name":"bevy","vers":"0.19.0-rc.2","deps":[],"cksum":"0e0580d37234d8aeb18c8d2ce6b5e093366c3a52fb7eb5a2f7d2100635122b07","features":{},"yanked":false,"pubtime":"2025-02-10T10:00:00Z"}
                    """)));

        final var purl = aPackageURL()
                .withType("cargo")
                .withName("bevy")
                .withVersion("0.18.1")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("0.18.1");
        assertThat(result.latestVersionPublishedAt()).isEqualTo(Instant.parse("2025-01-10T10:00:00Z"));
    }

    @Test
    void shouldFallBackToPreReleaseWhenNoStableExists(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/ea/rl/early-bird"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSONL */ """
                    {"name":"early-bird","vers":"0.1.0-alpha","deps":[],"cksum":"0e0580d37234d8aeb18c8d2ce6b5e093366c3a52fb7eb5a2f7d2100635122b07","features":{},"yanked":false,"pubtime":"2025-01-10T10:00:00Z"}
                    """)));

        final var purl = aPackageURL()
                .withType("cargo")
                .withName("early-bird")
                .withVersion("0.1.0-alpha")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("0.1.0-alpha");
    }

    @ParameterizedTest
    @CsvSource({
        "a, /1/a",
        "ab, /2/ab",
        "abc, /3/a/abc",
        "abcd, /ab/cd/abcd",
        "Serde_JSON, /se/rd/serde_json",
    })
    void shouldRequestIndexFileAtSparseIndexPath(String name, String expectedPath, WireMockRuntimeInfo wmRuntimeInfo)
            throws Exception {
        stubFor(get(urlPathEqualTo(expectedPath))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSONL */ """
                    {"name":"%s","vers":"1.0.0","deps":[],"cksum":"0e0580d37234d8aeb18c8d2ce6b5e093366c3a52fb7eb5a2f7d2100635122b07","features":{},"yanked":false}
                    """.formatted(name))));

        final var purl = aPackageURL()
                .withType("cargo")
                .withName(name)
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.0");
    }

    @Test
    void shouldDetermineLatestVersionBySemverPrecedenceRatherThanPublishOrder(WireMockRuntimeInfo wmRuntimeInfo)
            throws Exception {
        stubFor(get(urlPathEqualTo("/to/ki/tokio"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSONL */ """
                    {"name":"tokio","vers":"1.0.9","deps":[],"cksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","features":{},"yanked":false,"pubtime":"2024-01-01T00:00:00Z"}
                    {"name":"tokio","vers":"1.0.10","deps":[],"cksum":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","features":{},"yanked":false,"pubtime":"2024-02-01T00:00:00Z"}
                    {"name":"tokio","vers":"0.9.5","deps":[],"cksum":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","features":{},"yanked":false,"pubtime":"2024-03-01T00:00:00Z"}
                    """)));

        final var purl = aPackageURL()
                .withType("cargo")
                .withName("tokio")
                .withVersion("0.9.5")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.10");
        assertThat(result.latestVersionPublishedAt()).isEqualTo(Instant.parse("2024-02-01T00:00:00Z"));
    }

    @Test
    void shouldIgnoreYankedVersionsForLatestVersion(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/se/rd/serde"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSONL */ """
                    {"name":"serde","vers":"1.0.0","deps":[],"cksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","features":{},"yanked":false,"pubtime":"2024-01-15T10:30:00Z"}
                    {"name":"serde","vers":"1.0.1","deps":[],"cksum":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","features":{},"yanked":true,"pubtime":"2024-02-15T10:30:00Z"}
                    """)));

        final var purl = aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.1")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.0");
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt()).isEqualTo(Instant.parse("2024-02-15T10:30:00Z"));
    }

    @Test
    void shouldIgnoreUnparseableVersionsForLatestVersion(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/se/rd/serde"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSONL */ """
                    {"name":"serde","vers":"1.0.0","deps":[],"cksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","features":{},"yanked":false,"pubtime":"2024-01-15T10:30:00Z"}
                    {"name":"serde","vers":"not-a-version","deps":[],"cksum":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","features":{},"yanked":false,"pubtime":"2024-02-15T10:30:00Z"}
                    """)));

        final var purl = aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.0");
        assertThat(result.latestVersionPublishedAt()).isEqualTo(Instant.parse("2024-01-15T10:30:00Z"));
    }

    @Test
    void shouldReturnNullWhenCrateNotFound(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/no/ne/nonexistent")).willReturn(aResponse().withStatus(404)));

        final var purl = aPackageURL()
                .withType("cargo")
                .withName("nonexistent")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNull();
    }

    @Test
    void shouldThrowWhenRepositoryIsNull() throws Exception {
        final var purl = aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.0")
                .build();

        assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> resolver.resolve(purl, null, null));
    }

    @Test
    void shouldHandleVersionWithoutPubtime(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/se/rd/serde"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSONL */ """
                    {"name":"serde","vers":"1.0.200","deps":[],"cksum":"0e0580d37234d8aeb18c8d2ce6b5e093366c3a52fb7eb5a2f7d2100635122b07","features":{},"yanked":false}
                    """)));

        final var purl = aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.200")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.200");
        assertThat(result.latestVersionPublishedAt()).isNull();
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt()).isNull();
        assertThat(result.artifactMetadata().hashes())
                .containsOnly(Map.entry(
                        HashAlgorithm.SHA256, "0e0580d37234d8aeb18c8d2ce6b5e093366c3a52fb7eb5a2f7d2100635122b07"));
    }

    @Test
    void shouldHandleInvalidChecksum(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/se/rd/serde"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSONL */ """
                    {"name":"serde","vers":"1.0.200","deps":[],"cksum":"not-a-valid-hash","features":{},"yanked":false,"pubtime":"2024-01-15T10:30:00Z"}
                    """)));

        final var purl = aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.200")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNotNull();
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().hashes()).isEmpty();
        assertThat(result.artifactMetadata().publishedAt()).isEqualTo(Instant.parse("2024-01-15T10:30:00Z"));
    }

    @Test
    void shouldThrowRetryableExceptionWhenRateLimited(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/se/rd/serde"))
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "30")));

        final var purl = aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo, null))
                .satisfies(e -> assertThat(e.retryAfter()).hasSeconds(30));
    }

    @Test
    void shouldThrowRetryableExceptionOnServerError(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/se/rd/serde")).willReturn(aResponse().withStatus(503)));

        final var purl = aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(purl, repo, null));
    }

    @Test
    void shouldReturnNullWhenIndexFileIsEmpty(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/se/rd/serde"))
                .willReturn(aResponse().withStatus(200).withBody("")));

        final var purl = aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("crates-io", wmRuntimeInfo.getHttpBaseUrl(), null, null);
        final PackageMetadata result = resolver.resolve(purl, repo, null);

        assertThat(result).isNull();
    }

    @Test
    void shouldUseBasicAuthWhenUsernameAndPasswordProvided(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/se/rd/serde"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSONL */ """
                    {"name":"serde","vers":"1.0.0","deps":[],"cksum":"0e0580d37234d8aeb18c8d2ce6b5e093366c3a52fb7eb5a2f7d2100635122b07","features":{},"yanked":false}
                    """)));

        final var purl = aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("crates", wmRuntimeInfo.getHttpBaseUrl(), "user", "secret");
        assertThat(resolver.resolve(purl, repo, null)).isNotNull();

        final String expected =
                "Basic " + Base64.getEncoder().encodeToString("user:secret".getBytes(StandardCharsets.UTF_8));
        verify(getRequestedFor(urlPathEqualTo("/se/rd/serde")).withHeader("Authorization", equalTo(expected)));
    }

    @Test
    void shouldSendTokenVerbatimWhenOnlyPasswordProvided(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo("/se/rd/serde"))
                .willReturn(aResponse().withStatus(200).withBody(/* language=JSONL */ """
                    {"name":"serde","vers":"1.0.0","deps":[],"cksum":"0e0580d37234d8aeb18c8d2ce6b5e093366c3a52fb7eb5a2f7d2100635122b07","features":{},"yanked":false}
                    """)));

        final var purl = aPackageURL()
                .withType("cargo")
                .withName("serde")
                .withVersion("1.0.0")
                .build();

        final var repo = new PackageRepository("crates", wmRuntimeInfo.getHttpBaseUrl(), null, "token");
        assertThat(resolver.resolve(purl, repo, null)).isNotNull();

        verify(getRequestedFor(urlPathEqualTo("/se/rd/serde")).withHeader("Authorization", equalTo("token")));
    }
}
