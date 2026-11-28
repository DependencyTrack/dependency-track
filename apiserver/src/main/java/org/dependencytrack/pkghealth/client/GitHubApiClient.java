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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.packageurl.PackageURL;
import org.dependencytrack.pkghealth.model.AnalyzedPackageHealth;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;

public final class GitHubApiClient extends ApiClient {

    private static final String DEFAULT_API_BASE_URL = "https://api.github.com";
    private static final int PAGE_SIZE = 100;

    private final String apiBaseUrl;
    private final String accessToken;
    private final Clock clock;

    // Multiple packages can share a GitHub repository. Cache its metadata so each
    // repository is fetched once per cache entry, then create a separate result for each PURL.
    private final Cache<String, Optional<RepositoryMetadata>> repositoryCache = Caffeine.newBuilder()
            .maximumSize(1_000)
            .expireAfterWrite(Duration.ofHours(1))
            .build();

    public GitHubApiClient(final @Nullable String accessToken) {
        super();

        if (accessToken == null || accessToken.isBlank()) {
            throw new IllegalArgumentException("accessToken must not be blank");
        }

        this.accessToken = Objects.requireNonNull(accessToken);
        this.clock = Clock.systemUTC();
        this.apiBaseUrl = DEFAULT_API_BASE_URL;
    }

    GitHubApiClient(
            final HttpClient httpClient,
            final ObjectMapper objectMapper,
            final @Nullable String accessToken,
            final Clock clock,
            final String apiBaseUrl) {

        super(httpClient, objectMapper);
        this.accessToken = Objects.requireNonNull(accessToken);
        this.clock = clock;
        this.apiBaseUrl = apiBaseUrl;
    }

    @Override
    protected void configureRequest(final HttpRequest.Builder requestBuilder) {
        requestBuilder.setHeader("Accept", "application/vnd.github+json");
        requestBuilder.setHeader("X-GitHub-Api-Version", "2022-11-28");
        requestBuilder.setHeader("Authorization", "Bearer " + accessToken);
    }

    public Optional<AnalyzedPackageHealth> fetchRepositoryMetadata(final PackageURL packagePurl, final String project)
            throws IOException, InterruptedException {
        final Optional<RepositoryCoordinates> coordinates = parseProject(project);

        if (coordinates.isEmpty()) {
            return Optional.empty();
        }

        return cachedRepositoryData(repositoryUrl(coordinates.get())).map(data -> data.forPackage(packagePurl));
    }

    public static @Nullable String repositoryPageUrl(final @Nullable String project) {
        return parseProject(project)
                .map(coordinates -> "https://github.com/%s/%s"
                        .formatted(urlEncode(coordinates.owner()), urlEncode(coordinates.repository())))
                .orElse(null);
    }

    private Optional<RepositoryMetadata> cachedRepositoryData(final String repositoryUrl)
            throws IOException, InterruptedException {
        try {
            return repositoryCache.get(repositoryUrl.toLowerCase(Locale.ROOT), ignored -> {
                try {
                    return fetchRepositoryData(repositoryUrl);
                } catch (IOException | InterruptedException e) {
                    throw new RepositoryFetchException(e);
                }
            });
        } catch (RepositoryFetchException e) {
            if (e.getCause() instanceof InterruptedException interrupted) {
                throw interrupted;
            }
            if (e.getCause() instanceof IOException io) {
                throw io;
            }
            throw e;
        }
    }

    private static final class RepositoryFetchException extends RuntimeException {
        private RepositoryFetchException(final Exception cause) {
            super(cause);
        }
    }

    private Optional<RepositoryMetadata> fetchRepositoryData(final String repositoryUrl)
            throws IOException, InterruptedException {
        final Optional<JsonNode> response = requestJson(repositoryUrl);
        if (response.isEmpty()) {
            return Optional.empty();
        }

        final JsonNode repository = response.get();
        final IssueStatistics issues = fetchIssueStatistics(repositoryUrl);
        final ContributorStatistics contributors = fetchContributorStatistics(repositoryUrl);
        final String defaultBranch = textOrNull(repository.get("default_branch"));

        return Optional.of(new RepositoryMetadata(
                textOrNull(repository.get("html_url")),
                booleanOrNull(repository.get("archived")),
                issues.openIssues(),
                issues.openPullRequests(),
                issues.averageIssueAgeDays(),
                contributors.count(),
                calculateCommitFrequency(
                        contributors.totalContributions(), instantOrNull(repository.get("created_at"))),
                calculateBusFactor(contributors.contributions()),
                fetchLastCommit(repositoryUrl, defaultBranch),
                fetchFileCount(repositoryUrl, defaultBranch),
                resourceExists(repositoryUrl + "/readme"),
                resourceExistsAtAnyPath(
                        repositoryUrl, "CODE_OF_CONDUCT.md", ".github/CODE_OF_CONDUCT.md", "docs/CODE_OF_CONDUCT.md"),
                resourceExistsAtAnyPath(repositoryUrl, "SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")));
    }

    private IssueStatistics fetchIssueStatistics(final String repositoryUrl) throws IOException, InterruptedException {
        final Instant now = clock.instant();
        final var counter = new IssueCounter();

        forEachItem(repositoryUrl + "/issues?state=open", issue -> counter.add(issue, now));

        return counter.toStatistics();
    }

    private ContributorStatistics fetchContributorStatistics(final String repositoryUrl)
            throws IOException, InterruptedException {
        final var counter = new ContributorCounter();

        forEachItem(repositoryUrl + "/contributors?anon=1", counter::add);

        return counter.toStatistics();
    }

    private @Nullable Instant fetchLastCommit(final String repositoryUrl, final @Nullable String defaultBranch)
            throws IOException, InterruptedException {
        if (defaultBranch == null) {
            return null;
        }

        final Optional<JsonNode> response =
                requestJson(repositoryUrl + "/commits?sha=" + urlEncode(defaultBranch) + "&per_page=1");

        if (response.isEmpty() || !response.get().isArray() || response.get().size() == 0) {
            return null;
        }

        final JsonNode commit = response.get().get(0).path("commit");

        final Instant committerDate = instantOrNull(commit.path("committer").get("date"));

        return committerDate != null
                ? committerDate
                : instantOrNull(commit.path("author").get("date"));
    }

    private @Nullable Long fetchFileCount(final String repositoryUrl, final @Nullable String defaultBranch)
            throws IOException, InterruptedException {
        if (defaultBranch == null) {
            return null;
        }

        final Optional<JsonNode> response =
                requestJson(repositoryUrl + "/git/trees/" + urlEncode(defaultBranch) + "?recursive=1");

        if (response.isEmpty() || response.get().path("truncated").asBoolean(false)) {
            return null;
        }

        final JsonNode tree = response.get().get("tree");
        if (tree == null || !tree.isArray()) {
            return null;
        }

        long files = 0;
        for (final JsonNode entry : tree) {
            if ("blob".equals(entry.path("type").asText())) {
                files++;
            }
        }

        return files;
    }

    private boolean resourceExistsAtAnyPath(final String repositoryUrl, final String... paths)
            throws IOException, InterruptedException {
        for (final String path : paths) {
            if (resourceExists(repositoryUrl + "/contents/" + path)) {
                return true;
            }
        }

        return false;
    }

    private boolean resourceExists(final String url) throws IOException, InterruptedException {
        return requestJson(url).isPresent();
    }

    /**
     * Visits every item of a paginated GitHub list, one page at a time.
     */
    private void forEachItem(final String baseUrl, final Consumer<JsonNode> itemConsumer)
            throws IOException, InterruptedException {
        final String separator = baseUrl.contains("?") ? "&" : "?";
        int page = 1;

        while (true) {
            if (Thread.interrupted()) {
                throw new InterruptedException("Interrupted before all pages of %s were fetched".formatted(baseUrl));
            }

            final Optional<JsonNode> response =
                    requestJson(baseUrl + separator + "per_page=" + PAGE_SIZE + "&page=" + page);

            if (response.isEmpty()) {
                return;
            }

            final JsonNode values = response.get();
            if (!values.isArray()) {
                throw new IOException("Expected GitHub response to be an array");
            }

            values.forEach(itemConsumer);

            if (values.size() < PAGE_SIZE) {
                return;
            }

            page++;
        }
    }

    private @Nullable Float calculateCommitFrequency(
            final long totalContributions, final @Nullable Instant repositoryCreatedAt) {
        if (repositoryCreatedAt == null) {
            return null;
        }

        final long repositoryAgeDays = Math.max(0, ChronoUnit.DAYS.between(repositoryCreatedAt, clock.instant()));
        final long repositoryAgeWeeks = Math.max(1, repositoryAgeDays / 7);

        return (float) totalContributions / repositoryAgeWeeks;
    }

    private static @Nullable Integer calculateBusFactor(final List<Long> contributions) {
        final long totalContributions =
                contributions.stream().mapToLong(Long::longValue).sum();

        if (totalContributions == 0) {
            return null;
        }

        final long threshold = (totalContributions + 1) / 2;
        final List<Long> descending =
                contributions.stream().sorted(Comparator.reverseOrder()).toList();

        long accumulated = 0;
        int busFactor = 0;

        for (final long contributionCount : descending) {
            accumulated += contributionCount;
            busFactor++;

            if (accumulated >= threshold) {
                return busFactor;
            }
        }

        return null;
    }

    private static Optional<RepositoryCoordinates> parseProject(final @Nullable String project) {
        if (project == null || !project.toLowerCase(Locale.ROOT).startsWith("github.com/")) {
            return Optional.empty();
        }

        String path = project.substring("github.com/".length());
        path = path.replaceFirst("/+$", "").replaceFirst("(?i)\\.git$", "");

        final String[] segments = path.split("/");
        if (segments.length != 2 || segments[0].isBlank() || segments[1].isBlank()) {
            return Optional.empty();
        }

        return Optional.of(new RepositoryCoordinates(segments[0], segments[1]));
    }

    private String repositoryUrl(final RepositoryCoordinates coordinates) {
        return "%s/repos/%s/%s"
                .formatted(apiBaseUrl, urlEncode(coordinates.owner()), urlEncode(coordinates.repository()));
    }

    private static @Nullable String textOrNull(final @Nullable JsonNode node) {
        return node != null && node.isTextual() ? node.textValue() : null;
    }

    private static @Nullable Long longOrNull(final @Nullable JsonNode node) {
        return node != null && node.isIntegralNumber() ? node.longValue() : null;
    }

    private static @Nullable Boolean booleanOrNull(final @Nullable JsonNode node) {
        return (node != null && node.isBoolean()) ? node.booleanValue() : null;
    }

    private static @Nullable Instant instantOrNull(final @Nullable JsonNode node) {
        final String value = textOrNull(node);
        if (value == null || value.isBlank()) {
            return null;
        }

        try {
            return Instant.parse(value);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private record RepositoryCoordinates(String owner, String repository) {}

    private static final class IssueCounter {

        private long openIssues;
        private long openPullRequests;
        private double totalIssueAgeDays;

        private void add(final JsonNode issue, final Instant now) {
            if (issue.hasNonNull("pull_request")) {
                openPullRequests++;
                return;
            }

            openIssues++;

            final Instant createdAt = instantOrNull(issue.get("created_at"));
            if (createdAt != null) {
                final long ageSeconds =
                        Math.max(0, Duration.between(createdAt, now).toSeconds());
                totalIssueAgeDays += ageSeconds / 86_400.0;
            }
        }

        private IssueStatistics toStatistics() {
            final float averageIssueAgeDays = openIssues == 0 ? 0 : (float) (totalIssueAgeDays / openIssues);
            return new IssueStatistics(openIssues, openPullRequests, averageIssueAgeDays);
        }
    }

    private static final class ContributorCounter {

        private final List<Long> contributions = new ArrayList<>();
        private long count;

        private void add(final JsonNode contributor) {
            count++;
            final Long value = longOrNull(contributor.get("contributions"));
            if (value != null) {
                contributions.add(value);
            }
        }

        private ContributorStatistics toStatistics() {
            return new ContributorStatistics(count, contributions);
        }
    }

    private record IssueStatistics(long openIssues, long openPullRequests, float averageIssueAgeDays) {}

    private record ContributorStatistics(long count, List<Long> contributions) {

        private long totalContributions() {
            return contributions.stream().mapToLong(Long::longValue).sum();
        }
    }

    private record RepositoryMetadata(
            @Nullable String htmlUrl,
            @Nullable Boolean archived,
            long openIssues,
            long openPullRequests,
            float averageIssueAgeDays,
            long contributors,
            @Nullable Float commitFrequencyWeekly,
            @Nullable Integer busFactor,
            @Nullable Instant lastCommit,
            @Nullable Long files,
            boolean hasReadme,
            boolean hasCodeOfConduct,
            boolean hasSecurityPolicy) {

        private AnalyzedPackageHealth forPackage(final PackageURL packagePurl) {
            final var model = new AnalyzedPackageHealth(packagePurl);
            model.setGithubUrl(htmlUrl);
            model.setRepositoryArchived(archived);
            model.setOpenIssues(openIssues);
            model.setOpenPullRequests(openPullRequests);
            model.setAverageIssueAgeDays(averageIssueAgeDays);
            model.setContributors(contributors);
            model.setCommitFrequencyWeekly(commitFrequencyWeekly);
            model.setBusFactor(busFactor);
            model.setLastCommit(lastCommit);
            model.setFiles(files);
            model.setHasReadme(hasReadme);
            model.setHasCodeOfConduct(hasCodeOfConduct);
            model.setHasSecurityPolicy(hasSecurityPolicy);
            return model;
        }
    }
}
