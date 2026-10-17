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
package org.dependencytrack.pkghealth.client;

import com.github.packageurl.PackageURL;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import org.dependencytrack.common.Mappers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

class GitHubApiClientTest {

    private static final Instant NOW = Instant.parse("2026-09-24T12:00:00Z");

    @RegisterExtension
    static final WireMockExtension wm = WireMockExtension.newInstance()
            .options(wireMockConfig().dynamicPort())
            .configureStaticDsl(true)
            .build();

    private GitHubApiClient client;
    private PackageURL packagePurl;

    @BeforeEach
    void beforeEach() throws Exception {
        client = new GitHubApiClient(
                HttpClient.newHttpClient(),
                Mappers.jsonMapper(),
                "test-token",
                Clock.fixed(NOW, ZoneOffset.UTC),
                wm.baseUrl());

        packagePurl = new PackageURL("pkg:npm/example");
    }

    @Test
    void shouldBuildRepositoryPageUrl() {
        assertThat(GitHubApiClient.repositoryPageUrl("github.com/acme/example"))
                .isEqualTo("https://github.com/acme/example");
        assertThat(GitHubApiClient.repositoryPageUrl("github.com/acme/example.git"))
                .isEqualTo("https://github.com/acme/example");
        assertThat(GitHubApiClient.repositoryPageUrl("gitlab.com/acme/example")).isNull();
    }

    @Test
    void shouldReturnEmptyForUnsupportedProject() throws Exception {
        final var result = client.fetchRepositoryMetadata(packagePurl, "gitlab.com/acme/example");

        assertThat(result).isEmpty();
    }

    @Test
    void shouldReturnEmptyWhenRepositoryDoesNotExist() throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/example"))
                .willReturn(aResponse().withStatus(404)));

        final var result = client.fetchRepositoryMetadata(packagePurl, "github.com/acme/example");

        assertThat(result).isEmpty();
    }

    @Test
    void shouldSendGitHubHeaders() throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/example"))
                .willReturn(aResponse().withStatus(404)));

        client.fetchRepositoryMetadata(packagePurl, "github.com/acme/example");

        verify(getRequestedFor(urlPathEqualTo("/repos/acme/example"))
                .withHeader("Authorization", equalTo("Bearer test-token"))
                .withHeader("Accept", equalTo("application/vnd.github+json"))
                .withHeader("X-GitHub-Api-Version", equalTo("2022-11-28")));
    }

    @Test
    void shouldRejectBlankAccessToken() {
        assertThatIllegalArgumentException().isThrownBy(() -> new GitHubApiClient(" "));
    }

    @Test
    void shouldFetchRepositoryMetadata() throws Exception {
        stubJson("/repos/acme/example", """
            {
              "archived": true,
              "html_url": "https://github.com/acme/example",
              "created_at": "2026-08-27T12:00:00Z",
              "default_branch": "main"
            }
            """);

        stubJson("/repos/acme/example/issues", """
            [
              {
                "created_at": "2026-09-14T12:00:00Z"
              },
              {
                "created_at": "2026-09-04T12:00:00Z"
              },
              {
                "created_at": "2026-09-20T12:00:00Z",
                "pull_request": {
                  "url": "https://api.github.com/repos/acme/example/pulls/1"
                }
              }
            ]
            """);

        stubJson("/repos/acme/example/contributors", """
            [
              {
                "login": "alice",
                "contributions": 6
              },
              {
                "login": "bob",
                "contributions": 2
              }
            ]
            """);

        stubJson("/repos/acme/example/commits", """
            [
              {
                "commit": {
                  "committer": {
                    "date": "2026-09-23T10:00:00Z"
                  }
                }
              }
            ]
            """);

        stubJson("/repos/acme/example/git/trees/main", """
            {
              "truncated": false,
              "tree": [
                {
                  "path": "README.md",
                  "type": "blob"
                },
                {
                  "path": "src",
                  "type": "tree"
                },
                {
                  "path": "src/Main.java",
                  "type": "blob"
                }
              ]
            }
            """);

        stubJson("/repos/acme/example/readme", "{}");
        stubJson("/repos/acme/example/contents/CODE_OF_CONDUCT.md", "{}");
        stubJson("/repos/acme/example/contents/SECURITY.md", "{}");

        final var result = client.fetchRepositoryMetadata(packagePurl, "github.com/acme/example");

        assertThat(result).isPresent();

        final var metadata = result.orElseThrow();

        assertThat(metadata.getPurl()).isEqualTo(packagePurl);
        assertThat(metadata.getGithubUrl()).isEqualTo("https://github.com/acme/example");
        assertThat(metadata.getRepositoryArchived()).isTrue();
        assertThat(metadata.getContributors()).isEqualTo(2L);
        assertThat(metadata.getOpenIssues()).isEqualTo(2L);
        assertThat(metadata.getOpenPullRequests()).isEqualTo(1L);
        assertThat(metadata.getAverageIssueAgeDays()).isEqualTo(15.0f);
        assertThat(metadata.getLastCommit()).isEqualTo(Instant.parse("2026-09-23T10:00:00Z"));
        assertThat(metadata.getFiles()).isEqualTo(2L);
        assertThat(metadata.getHasReadme()).isTrue();
        assertThat(metadata.getHasCodeOfConduct()).isTrue();
        assertThat(metadata.getHasSecurityPolicy()).isTrue();
        assertThat(metadata.getCommitFrequencyWeekly()).isEqualTo(2.0f);
        assertThat(metadata.getBusFactor()).isEqualTo(1);

        final var otherPurl = new PackageURL("pkg:npm/another");
        final var other = client.fetchRepositoryMetadata(otherPurl, "github.com/ACME/EXAMPLE")
                .orElseThrow();

        assertThat(other).isNotSameAs(metadata);
        assertThat(other.getPurl()).isEqualTo(otherPurl);
        assertThat(other.getContributors()).isEqualTo(metadata.getContributors());

        verify(1, getRequestedFor(urlPathEqualTo("/repos/acme/example")));
        verify(1, getRequestedFor(urlPathEqualTo("/repos/acme/example/issues")));
    }

    @Test
    void shouldHandleMissingOptionalRepositoryMetadata() throws Exception {
        stubJson("/repos/acme/example", """
            {
              "archived": false,
              "created_at": "2026-08-27T12:00:00Z",
              "default_branch": "main"
            }
            """);

        stubJson("/repos/acme/example/issues", "[]");
        stubJson("/repos/acme/example/contributors", "[]");
        stubJson("/repos/acme/example/commits", "[]");

        stubJson("/repos/acme/example/git/trees/main", """
            {
              "truncated": true,
              "tree": [
                {
                  "path": "incomplete-file.txt",
                  "type": "blob"
                }
              ]
            }
            """);

        /*
         * README, Code of Conduct and Security Policy are intentionally
         * not stubbed. WireMock responds with 404 for those requests.
         */
        final var result = client.fetchRepositoryMetadata(packagePurl, "github.com/acme/example");

        assertThat(result).isPresent();

        final var metadata = result.orElseThrow();

        assertThat(metadata.getRepositoryArchived()).isFalse();
        assertThat(metadata.getContributors()).isZero();
        assertThat(metadata.getOpenIssues()).isZero();
        assertThat(metadata.getOpenPullRequests()).isZero();
        assertThat(metadata.getAverageIssueAgeDays()).isZero();
        assertThat(metadata.getLastCommit()).isNull();

        // A truncated tree must not be persisted as a complete file count.
        assertThat(metadata.getFiles()).isNull();

        assertThat(metadata.getHasReadme()).isFalse();
        assertThat(metadata.getHasCodeOfConduct()).isFalse();
        assertThat(metadata.getHasSecurityPolicy()).isFalse();

        assertThat(metadata.getCommitFrequencyWeekly()).isZero();
        assertThat(metadata.getBusFactor()).isNull();
    }

    @Test
    void shouldFetchAllContributorPages() throws Exception {
        stubJson("/repos/acme/example", """
            {
              "archived": false,
              "created_at": "2026-08-27T12:00:00Z",
              "default_branch": "main"
            }
            """);

        stubJson("/repos/acme/example/issues", "[]");
        stubJson("/repos/acme/example/commits", "[]");

        stubJson("/repos/acme/example/git/trees/main", """
            {
              "truncated": true,
              "tree": []
            }
            """);

        stubFor(get(urlPathEqualTo("/repos/acme/example/contributors"))
                .withQueryParam("anon", equalTo("1"))
                .withQueryParam("per_page", equalTo("100"))
                .withQueryParam("page", equalTo("1"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(contributorPage(0, 100))));

        stubFor(get(urlPathEqualTo("/repos/acme/example/contributors"))
                .withQueryParam("anon", equalTo("1"))
                .withQueryParam("per_page", equalTo("100"))
                .withQueryParam("page", equalTo("2"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(contributorPage(100, 1))));

        final var result = client.fetchRepositoryMetadata(packagePurl, "github.com/acme/example");

        assertThat(result).isPresent();
        assertThat(result.orElseThrow().getContributors()).isEqualTo(101L);

        verify(getRequestedFor(urlPathEqualTo("/repos/acme/example/contributors"))
                .withQueryParam("page", equalTo("1")));

        verify(getRequestedFor(urlPathEqualTo("/repos/acme/example/contributors"))
                .withQueryParam("page", equalTo("2")));
    }

    private static String contributorPage(final int firstContributor, final int contributorCount) {
        final var json = new StringBuilder("[");

        for (int index = 0; index < contributorCount; index++) {
            if (index > 0) {
                json.append(',');
            }

            final int contributor = firstContributor + index;

            json.append("""
                {
                  "login": "user-%d",
                  "contributions": 1
                }
                """.formatted(contributor));
        }

        return json.append(']').toString();
    }

    @Test
    void shouldUseAuthorDateAndAlternativeFileLocations() throws Exception {
        stubJson("/repos/acme/example", """
            {
              "archived": false,
              "created_at": "2026-08-27T12:00:00Z",
              "default_branch": "main"
            }
            """);

        stubJson("/repos/acme/example/issues", "[]");
        stubJson("/repos/acme/example/contributors", "[]");

        stubJson("/repos/acme/example/commits", """
            [
              {
                "commit": {
                  "committer": {
                    "date": null
                  },
                  "author": {
                    "date": "2026-09-22T08:00:00Z"
                  }
                }
              }
            ]
            """);

        stubJson("/repos/acme/example/git/trees/main", """
            {
              "truncated": false,
              "tree": []
            }
            """);

        /*
         * The root paths are intentionally not stubbed and return 404.
         */
        stubJson("/repos/acme/example/contents/.github/CODE_OF_CONDUCT.md", "{}");
        stubJson("/repos/acme/example/contents/docs/SECURITY.md", "{}");

        final var result = client.fetchRepositoryMetadata(packagePurl, "github.com/acme/example");

        assertThat(result).isPresent();

        final var metadata = result.orElseThrow();

        assertThat(metadata.getLastCommit()).isEqualTo(Instant.parse("2026-09-22T08:00:00Z"));
        assertThat(metadata.getHasReadme()).isFalse();
        assertThat(metadata.getHasCodeOfConduct()).isTrue();
        assertThat(metadata.getHasSecurityPolicy()).isTrue();
        assertThat(metadata.getFiles()).isZero();
    }

    @Test
    void shouldThrowOnServerError() {
        stubFor(get(urlPathEqualTo("/repos/acme/example"))
                .willReturn(aResponse().withStatus(500)));

        assertThatExceptionOfType(IOException.class)
                .isThrownBy(() -> client.fetchRepositoryMetadata(packagePurl, "github.com/acme/example"));
    }

    private static void stubJson(final String path, final String responseBody) {
        stubFor(get(urlPathEqualTo(path))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(responseBody)));
    }

    @Test
    void shouldExposeRateLimitReset() {
        stubFor(get(urlPathEqualTo("/repos/acme/example"))
                .willReturn(aResponse()
                        .withStatus(403)
                        .withHeader("x-ratelimit-remaining", "0")
                        .withHeader("x-ratelimit-reset", "1790333868")));

        assertThatExceptionOfType(ApiRateLimitException.class)
                .isThrownBy(() -> client.fetchRepositoryMetadata(packagePurl, "github.com/acme/example"))
                .satisfies(e -> assertThat(e.resetAt()).isEqualTo(Instant.ofEpochSecond(1790333868)));

        assertThatExceptionOfType(ApiRateLimitException.class)
                .isThrownBy(() -> client.fetchRepositoryMetadata(packagePurl, "github.com/acme/example"));

        verify(2, getRequestedFor(urlPathEqualTo("/repos/acme/example")));
    }

    @Test
    void shouldShareConcurrentRepositoryFetch() throws Exception {
        stubFor(get(urlPathEqualTo("/repos/acme/example"))
                .willReturn(aResponse().withStatus(404).withFixedDelay(300)));

        final var ready = new CountDownLatch(2);
        final var start = new CountDownLatch(1);

        try (var executor = Executors.newFixedThreadPool(2)) {
            final var first = executor.submit(() -> {
                ready.countDown();
                start.await();
                return client.fetchRepositoryMetadata(packagePurl, "github.com/acme/example");
            });
            final var second = executor.submit(() -> {
                ready.countDown();
                start.await();
                return client.fetchRepositoryMetadata(new PackageURL("pkg:npm/another"), "github.com/acme/example");
            });

            try {
                assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
            } finally {
                start.countDown();
            }

            assertThat(first.get()).isEmpty();
            assertThat(second.get()).isEmpty();
        }

        verify(1, getRequestedFor(urlPathEqualTo("/repos/acme/example")));
    }
}
