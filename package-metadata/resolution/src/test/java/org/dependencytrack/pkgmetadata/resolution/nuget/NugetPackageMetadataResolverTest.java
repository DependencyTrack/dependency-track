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
package org.dependencytrack.pkgmetadata.resolution.nuget;

import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.pkgmetadata.resolution.api.PackageArtifactMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.api.RetryableResolutionException;
import org.dependencytrack.plugin.api.MutableServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.exactly;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class NugetPackageMetadataResolverTest {

    @RegisterExtension
    static final WireMockExtension wm = WireMockExtension.newInstance()
            .options(wireMockConfig().dynamicPort().globalTemplating(true))
            .configureStaticDsl(true)
            .build();

    private static final String ARTIFACTORY_REG_PATH = "/artifactory/api/nuget/v3/nuget-repo/registration-semver2/microsoft.data.sqlclient";
    private static final String ARTIFACTORY_PAGE1 = "page/1.0.19123.2-preview/5.1.0";
    private static final String ARTIFACTORY_PAGE2 = "page/5.1.1/6.1.0";

    private NugetPackageMetadataResolverFactory factory;
    private NugetPackageMetadataResolver resolver;

    @BeforeEach
    void beforeEach() {
        factory = new NugetPackageMetadataResolverFactory();
        factory.init(
                new MutableServiceRegistry()
                        .register(CacheManager.class, new NoopCacheManager())
                        .register(ConfigRegistry.class, new MockConfigRegistry(Map.of(), null, null, null))
                        .register(HttpClient.class, HttpClient.newHttpClient()));
        resolver = (NugetPackageMetadataResolver) factory.create();
    }

    @AfterEach
    void afterEach() {
        if (factory != null) {
            factory.close();
        }
    }

    @Test
    void shouldResolveLatestStableSkippingUnlistedAndPreReleaseWithInlinePages() throws Exception {
        stubFor(get(urlPathEqualTo("/v3/index.json"))
                .willReturn(aResponse().withStatus(200).withBodyFile("nuget/https---nuget.org.v3-index.json")));
        stubFor(get(urlPathEqualTo("/v3/registration5-gz-semver2/microsoft.data.sqlclient/index.json"))
                .willReturn(aResponse().withStatus(200).withBodyFile(
                        "nuget/https---nuget.org.registration-semver2.mds.index-inline-pages.json")));

        final PackageMetadata result = resolver.resolve(nugetPurl("Microsoft.Data.SqlClient", "5.0.1"),
                new PackageRepository("test", wm.baseUrl(), null, null), null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("6.0.2");
    }

    @Test
    void shouldResolveLatestAcrossPagedRegistrationsViaIdReference() throws Exception {
        stubArtifactoryServiceAndIndex();
        stubArtifactoryPage(ARTIFACTORY_PAGE1, "page1");
        stubArtifactoryPage(ARTIFACTORY_PAGE2, "page2");

        final PackageMetadata result = resolver.resolve(
                nugetPurl("Microsoft.Data.SqlClient", "5.1.0"), artifactoryRepo(), null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("6.0.2");
        assertThat(result.artifactMetadata()).isNull();
    }

    @Test
    void shouldIgnorePreReleaseAndUnlistedOnLatestPage() throws Exception {
        stubArtifactoryServiceAndIndex();
        stubArtifactoryPage(ARTIFACTORY_PAGE2, "page2-check-pre-release");

        final PackageMetadata result = resolver.resolve(
                nugetPurl("Microsoft.Data.SqlClient", "5.1.0"), artifactoryRepo(), null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("5.1.2");
    }

    @Test
    void shouldFallBackToPreviousPageWhenLatestPageAllUnlisted() throws Exception {
        stubArtifactoryServiceAndIndex();
        stubArtifactoryPage(ARTIFACTORY_PAGE2, "page2-all-unlisted");
        stubArtifactoryPage(ARTIFACTORY_PAGE1, "page1");

        final PackageMetadata result = resolver.resolve(
                nugetPurl("Microsoft.Data.SqlClient", "5.1.0"), artifactoryRepo(), null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("5.1.0");
    }

    @Test
    void shouldFallBackToPreviousPageWhenLatestPageAllPreRelease() throws Exception {
        stubArtifactoryServiceAndIndex();
        stubArtifactoryPage(ARTIFACTORY_PAGE2, "page2-all-pre-release");
        stubArtifactoryPage(ARTIFACTORY_PAGE1, "page1");

        final PackageMetadata result = resolver.resolve(
                nugetPurl("Microsoft.Data.SqlClient", "5.1.0"), artifactoryRepo(), null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("5.1.0");
    }

    @Test
    void shouldReturnLatestPreReleaseWhenNoStableExists() throws Exception {
        stubFor(get(urlPathEqualTo("/v3/index.json"))
                .willReturn(aResponse().withStatus(200).withBodyFile("nuget/https---nuget.org.v3-index.json")));
        stubFor(get(urlPathEqualTo("/v3/registration5-gz-semver2/opentelemetry.instrumentation.sqlclient/index.json"))
                .willReturn(aResponse().withStatus(200).withBodyFile(
                        "nuget/https---nuget.org.registration-semver2.beta-releases-only.index-inline-pages.json")));

        final PackageMetadata result = resolver.resolve(
                nugetPurl("OpenTelemetry.Instrumentation.SqlClient", "1.12.0-beta.2"),
                new PackageRepository("test", wm.baseUrl(), null, null), null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.12.0-beta.2");
    }

    @Test
    void shouldReturnNullWhenPageRequestFails() {
        stubArtifactoryServiceAndIndex();
        stubFor(get(urlPathEqualTo(ARTIFACTORY_REG_PATH + "/" + ARTIFACTORY_PAGE2 + ".json"))
                .willReturn(aResponse().withStatus(401)));
        stubArtifactoryPage(ARTIFACTORY_PAGE1, "page1");

        assertThatExceptionOfType(RuntimeException.class).isThrownBy(() ->
                resolver.resolve(nugetPurl("Microsoft.Data.SqlClient", "5.1.0"), artifactoryRepo(), null));
    }

    @Test
    void shouldUseSemver1RegistrationsBaseUrlWhenSemver2Unavailable() throws Exception {
        stubFor(get(urlPathEqualTo("/v3/index.json"))
                .willReturn(aResponse().withStatus(200).withBody("""
                        {
                          "version": "3.0.0",
                          "resources": [
                            {
                              "@id": "{{request.baseUrl}}/v3/registration5-semver1/",
                              "@type": "RegistrationsBaseUrl"
                            }
                          ]
                        }
                        """)));
        stubFor(get(urlPathEqualTo("/v3/registration5-semver1/mypackage/index.json"))
                .willReturn(aResponse().withStatus(200).withBody("""
                        {
                          "items": [{
                            "upper": "1.0.0",
                            "items": [
                              {"catalogEntry": {"version": "1.0.0", "listed": true, "published": "2024-01-01T00:00:00Z"}}
                            ]
                          }]
                        }
                        """)));

        final PackageMetadata result = resolver.resolve(nugetPurl("MyPackage", "1.0.0"),
                new PackageRepository("test", wm.baseUrl(), null, null), null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.0");
    }

    @Test
    void shouldPreferSemver2RegistrationsBaseUrl() throws Exception {
        stubFor(get(urlPathEqualTo("/v3/index.json"))
                .willReturn(aResponse().withStatus(200).withBody("""
                        {
                          "resources": [
                            {"@id": "{{request.baseUrl}}/plain/", "@type": "RegistrationsBaseUrl"},
                            {"@id": "{{request.baseUrl}}/gz-semver2/", "@type": "RegistrationsBaseUrl/3.6.0"},
                            {"@id": "{{request.baseUrl}}/gz-semver1/", "@type": "RegistrationsBaseUrl/3.4.0"}
                          ]
                        }
                        """)));
        stubFor(get(urlPathEqualTo("/gz-semver2/mypackage/index.json"))
                .willReturn(aResponse().withStatus(200).withBody("""
                        {"items":[{"upper":"1.0.0","items":[{"catalogEntry":{"version":"1.0.0","listed":true}}]}]}
                        """)));

        final PackageMetadata result = resolver.resolve(nugetPurl("MyPackage", "1.0.0"),
                new PackageRepository("test", wm.baseUrl(), null, null), null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.0");
        verify(exactly(1), getRequestedFor(urlPathEqualTo("/gz-semver2/mypackage/index.json")));
    }

    @Test
    void shouldUseFullyQualifiedRepositoryUrl() throws Exception {
        stubFor(get(urlPathEqualTo("/custom/v3/index.json"))
                .willReturn(aResponse().withStatus(200).withBody("""
                        {"resources":[{"@id":"{{request.baseUrl}}/reg/","@type":"RegistrationsBaseUrl/3.6.0"}]}
                        """)));
        stubFor(get(urlPathEqualTo("/reg/mypackage/index.json"))
                .willReturn(aResponse().withStatus(200).withBody("""
                        {"items":[{"upper":"1.0.0","items":[{"catalogEntry":{"version":"1.0.0","listed":true}}]}]}
                        """)));

        final PackageMetadata result = resolver.resolve(nugetPurl("MyPackage", "1.0.0"),
                new PackageRepository("test", wm.baseUrl() + "/custom/v3/index.json", null, null), null);

        assertThat(result).isNotNull();
        assertThat(result.latestVersion()).isEqualTo("1.0.0");
    }

    @Test
    void shouldReturnNullWhenPackageNotFound() throws Exception {
        stubFor(get(urlPathEqualTo("/v3/index.json"))
                .willReturn(aResponse().withStatus(200).withBodyFile("nuget/https---nuget.org.v3-index.json")));
        stubFor(get(urlPathEqualTo("/v3/registration5-gz-semver2/nonexistent/index.json"))
                .willReturn(aResponse().withStatus(404)));

        final PackageMetadata result = resolver.resolve(nugetPurl("nonexistent", "1.0.0"),
                new PackageRepository("test", wm.baseUrl(), null, null), null);

        assertThat(result).isNull();
    }

    @Test
    void shouldReturnNullWhenServiceIndexLacksRegistrationsBaseUrl() throws Exception {
        stubFor(get(urlPathEqualTo("/v3/index.json"))
                .willReturn(aResponse().withStatus(200).withBody("{\"resources\":[]}")));

        final PackageMetadata result = resolver.resolve(nugetPurl("MyPackage", "1.0.0"),
                new PackageRepository("test", wm.baseUrl(), null, null), null);

        assertThat(result).isNull();
    }

    @Test
    void shouldThrowWhenRepositoryIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> resolver.resolve(nugetPurl("MyPackage", "1.0.0"), null, null));
    }

    @Test
    void shouldThrowRetryableExceptionWhenRateLimited() {
        stubFor(get(urlPathEqualTo("/v3/index.json"))
                .willReturn(aResponse().withStatus(429).withHeader("Retry-After", "10")));

        final PackageRepository repo = new PackageRepository("test", wm.baseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(nugetPurl("MyPackage", "1.0.0"), repo, null))
                .satisfies(e -> assertThat(e.retryAfter()).hasSeconds(10));
    }

    @Test
    void shouldThrowRetryableExceptionOnServerError() {
        stubFor(get(urlPathEqualTo("/v3/index.json"))
                .willReturn(aResponse().withStatus(504)));

        final PackageRepository repo = new PackageRepository("test", wm.baseUrl(), null, null);
        assertThatExceptionOfType(RetryableResolutionException.class)
                .isThrownBy(() -> resolver.resolve(nugetPurl("MyPackage", "1.0.0"), repo, null));
    }

    @Test
    void shouldSendBasicAuthHeaderWhenUsernameAndPasswordSet() throws Exception {
        stubFor(get(urlPathEqualTo("/v3/index.json"))
                .willReturn(aResponse().withStatus(200).withBodyFile("nuget/https---nuget.org.v3-index.json")));
        stubFor(get(urlPathEqualTo("/v3/registration5-gz-semver2/mypackage/index.json"))
                .willReturn(aResponse().withStatus(200).withBody("""
                        {"items":[{"upper":"1.0.0","items":[{"catalogEntry":{"version":"1.0.0","listed":true}}]}]}
                        """)));

        final PackageRepository repo = new PackageRepository("test", wm.baseUrl(), "user", "pass");
        resolver.resolve(nugetPurl("MyPackage", "1.0.0"), repo, null);

        final String expected = "Basic " + Base64.getEncoder()
                .encodeToString("user:pass".getBytes(StandardCharsets.UTF_8));
        verify(getRequestedFor(urlPathEqualTo("/v3/index.json"))
                .withHeader("Authorization", equalTo(expected)));
        verify(getRequestedFor(urlPathEqualTo("/v3/registration5-gz-semver2/mypackage/index.json"))
                .withHeader("Authorization", equalTo(expected)));
    }

    @Test
    void shouldSendBearerAuthHeaderWhenOnlyPasswordSet() throws Exception {
        stubFor(get(urlPathEqualTo("/v3/index.json"))
                .willReturn(aResponse().withStatus(200).withBodyFile("nuget/https---nuget.org.v3-index.json")));
        stubFor(get(urlPathEqualTo("/v3/registration5-gz-semver2/mypackage/index.json"))
                .willReturn(aResponse().withStatus(200).withBody("""
                        {"items":[{"upper":"1.0.0","items":[{"catalogEntry":{"version":"1.0.0","listed":true}}]}]}
                        """)));

        final PackageRepository repo = new PackageRepository("test", wm.baseUrl(), null, "tkn");
        resolver.resolve(nugetPurl("MyPackage", "1.0.0"), repo, null);

        verify(getRequestedFor(urlPathEqualTo("/v3/registration5-gz-semver2/mypackage/index.json"))
                .withHeader("Authorization", equalTo("Bearer tkn")));
    }

    @Test
    void shouldNotLeakAuthHeaderToCrossOriginIdReference() throws Exception {
        // Start a second WireMock instance on its own port to act as a *cross-origin*
        // registry. The primary repo advertises a RegistrationsBaseUrl pointing at it,
        // and the resolver must follow the link but must NOT carry the configured credential
        // to the foreign origin.
        final WireMockServer foreignWm = new WireMockServer(wireMockConfig().dynamicPort());
        foreignWm.start();
        try {
            stubFor(get(urlPathEqualTo("/v3/index.json"))
                    .willReturn(aResponse().withStatus(200).withBody("""
                            {"resources":[{"@id":"%s/reg/","@type":"RegistrationsBaseUrl/3.6.0"}]}
                            """.formatted(foreignWm.baseUrl()))));
            foreignWm.stubFor(get(urlPathEqualTo("/reg/mypackage/index.json"))
                    .willReturn(aResponse().withStatus(200).withBody("""
                            {"items":[{"upper":"1.0.0","items":[{"catalogEntry":{"version":"1.0.0","listed":true}}]}]}
                            """)));

            final PackageRepository repo = new PackageRepository("test", wm.baseUrl(), null, "tkn");
            final PackageMetadata result = resolver.resolve(nugetPurl("MyPackage", "1.0.0"), repo, null);

            assertThat(result).isNotNull();
            assertThat(result.latestVersion()).isEqualTo("1.0.0");

            // Same-origin service index call carries the bearer token.
            verify(getRequestedFor(urlPathEqualTo("/v3/index.json"))
                    .withHeader("Authorization", equalTo("Bearer tkn")));

            // Cross-origin registration call must NOT carry the bearer token.
            foreignWm.verify(getRequestedFor(urlPathEqualTo("/reg/mypackage/index.json"))
                    .withoutHeader("Authorization"));
        } finally {
            foreignWm.stop();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "1900-01-01T00:00:00+00:00",
            "2025-08-13T23:22:21.20+01:00",
            "2025-08-13T23:22:21Z",
            "2020-08-04T10:39:03.7136823",
            "2025-08-13T23:22:21",
            "2023-03-28T22:26:40.43+00:00",
            "2025-08-14T08:12:23.8207879Z"
    })
    void shouldParseValidPublishedDateFormats(String input) {
        assertThat(NugetPackageMetadataResolver.parsePublished(input)).isNotNull();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "not-a-date", "2025-13-99"})
    void shouldReturnNullForBlankOrInvalidPublishedDate(String input) {
        assertThat(NugetPackageMetadataResolver.parsePublished(input)).isNull();
    }

    @Test
    void shouldUsePriorPublishedAtForStableVersion() throws Exception {
        stubFor(get(urlPathEqualTo("/v3/index.json"))
                .willReturn(aResponse().withStatus(200).withBody("""
                        {"resources":[{"@id":"{{request.baseUrl}}/reg/","@type":"RegistrationsBaseUrl/3.6.0"}]}
                        """)));
        stubFor(get(urlPathEqualTo("/reg/mypackage/index.json"))
                .willReturn(aResponse().withStatus(200).withBody("""
                        {"items":[{"upper":"1.0.0","items":[
                          {"catalogEntry":{"version":"1.0.0","listed":true,"published":"2020-01-01T00:00:00Z"}}
                        ]}]}
                        """)));

        // Prior carries a different publishedAt to prove the resolver uses it instead of
        // re-reading the value from the registration response.
        final var prior = new PackageArtifactMetadata(
                Instant.parse("2024-01-01T00:00:00Z"),
                Instant.parse("2024-06-15T12:00:00Z"),
                Map.of());

        final PackageMetadata result = resolver.resolve(
                nugetPurl("MyPackage", "1.0.0"),
                new PackageRepository("test", wm.baseUrl(), null, null),
                prior);

        assertThat(result).isNotNull();
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2024-06-15T12:00:00Z"));
    }

    @Test
    void shouldRefetchForPreReleaseVersionEvenWithPrior() throws Exception {
        stubFor(get(urlPathEqualTo("/v3/index.json"))
                .willReturn(aResponse().withStatus(200).withBody("""
                        {"resources":[{"@id":"{{request.baseUrl}}/reg/","@type":"RegistrationsBaseUrl/3.6.0"}]}
                        """)));
        stubFor(get(urlPathEqualTo("/reg/mypackage/index.json"))
                .willReturn(aResponse().withStatus(200).withBody("""
                        {"items":[{"upper":"1.0.0-alpha","items":[
                          {"catalogEntry":{"version":"1.0.0-alpha","listed":true,"published":"2020-01-01T00:00:00Z"}}
                        ]}]}
                        """)));

        final var prior = new PackageArtifactMetadata(
                Instant.parse("2024-01-01T00:00:00Z"),
                Instant.parse("2024-06-15T12:00:00Z"),
                Map.of());

        final PackageMetadata result = resolver.resolve(
                nugetPurl("MyPackage", "1.0.0-alpha"),
                new PackageRepository("test", wm.baseUrl(), null, null),
                prior);

        assertThat(result).isNotNull();
        assertThat(result.artifactMetadata()).isNotNull();
        assertThat(result.artifactMetadata().publishedAt())
                .isEqualTo(Instant.parse("2020-01-01T00:00:00Z"));
    }

    private static PackageURL nugetPurl(String name, String version) throws Exception {
        return PackageURLBuilder.aPackageURL()
                .withType("nuget")
                .withName(name)
                .withVersion(version)
                .build();
    }

    private static PackageRepository artifactoryRepo() {
        return new PackageRepository("test", wm.baseUrl() + "/artifactory/api/nuget/v3/nuget-repo/index.json", null, null);
    }

    private static void stubArtifactoryServiceAndIndex() {
        stubFor(get(urlPathEqualTo("/artifactory/api/nuget/v3/nuget-repo/index.json"))
                .willReturn(aResponse().withStatus(200).withBodyFile(
                        "nuget/https---localhost-nuget-artifactory.v3-index.json")));
        stubFor(get(urlPathEqualTo(ARTIFACTORY_REG_PATH + "/index.json"))
                .willReturn(aResponse().withStatus(200).withBodyFile(
                        "nuget/https---localhost-nuget-artifactory.registration-semver2.mds.index.json")));
    }

    private static void stubArtifactoryPage(String pageRange, String fixtureSuffix) {
        stubFor(get(urlPathEqualTo(ARTIFACTORY_REG_PATH + "/" + pageRange + ".json"))
                .willReturn(aResponse().withStatus(200).withBodyFile(
                        "nuget/https---localhost-nuget-artifactory.registration-semver2.mds." + fixtureSuffix + ".json")));
    }

}
