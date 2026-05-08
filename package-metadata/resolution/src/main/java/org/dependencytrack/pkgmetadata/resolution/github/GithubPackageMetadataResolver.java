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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.PackageURL;
import org.dependencytrack.pkgmetadata.resolution.api.PackageArtifactMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.cache.CachingHttpClient;
import org.dependencytrack.pkgmetadata.resolution.support.UrlUtils;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

final class GithubPackageMetadataResolver implements PackageMetadataResolver {

    private static final Pattern COMMIT_SHA_PATTERN = Pattern.compile("^[0-9a-fA-F]{7,40}$");
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private final ObjectMapper objectMapper;
    private final CachingHttpClient cachingHttpClient;

    GithubPackageMetadataResolver(ObjectMapper objectMapper, CachingHttpClient cachingHttpClient) {
        this.objectMapper = objectMapper;
        this.cachingHttpClient = cachingHttpClient;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final byte[] latestBody = fetchLatestRelease(purl.getNamespace(), purl.getName(), repository);
        if (latestBody == null) {
            return null;
        }

        final JsonNode root = parseJson(latestBody);
        final String tagName = root.path("tag_name").asText(null);
        if (tagName == null) {
            return null;
        }

        final var resolvedAt = Instant.now();

        PackageArtifactMetadata artifactMetadata = null;
        final String version = purl.getVersion();
        if (version != null && version.equals(tagName)) {
            artifactMetadata = extractReleaseArtifactMetadata(root, resolvedAt);
        } else if (version != null) {
            // NB: SHA-shaped versions are usually commits, but *can* also be hex-only release tags
            // (e.g. "deadbeef"). Try the commit endpoint first, and on 404 fall through to the
            // release-by-tag lookup, so legitimate hex tags still resolve.
            if (COMMIT_SHA_PATTERN.matcher(version).matches()) {
                final byte[] commitBody = fetchCommit(
                        purl.getNamespace(), purl.getName(), version, repository);
                if (commitBody != null) {
                    artifactMetadata = extractCommitArtifactMetadata(parseJson(commitBody), resolvedAt);
                }
            }
            if (artifactMetadata == null) {
                final byte[] versionBody = fetchReleaseByTag(
                        purl.getNamespace(), purl.getName(), version, repository);
                if (versionBody != null) {
                    artifactMetadata = extractReleaseArtifactMetadata(parseJson(versionBody), resolvedAt);
                }
            }
        }

        return new PackageMetadata(tagName, resolvedAt, artifactMetadata);
    }

    private byte @Nullable [] fetchLatestRelease(
            String owner,
            String name,
            PackageRepository repository) throws InterruptedException {
        final String url = UrlUtils.join(repository.url(), "repos", owner, name, "releases", "latest");
        return fetch(url, repository);
    }

    private byte @Nullable [] fetchReleaseByTag(
            String owner,
            String name,
            String tag,
            PackageRepository repository) throws InterruptedException {
        final String url = UrlUtils.join(repository.url(), "repos", owner, name, "releases", "tags", tag);
        return fetch(url, repository);
    }

    private byte @Nullable [] fetchCommit(
            String owner,
            String name,
            String sha,
            PackageRepository repository) throws InterruptedException {
        final String url = UrlUtils.join(repository.url(), "repos", owner, name, "commits", sha);
        return fetch(url, repository);
    }

    private byte @Nullable [] fetch(String url, PackageRepository repository) throws InterruptedException {
        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .header("Accept", "application/vnd.github+json")
                .GET();

        if (repository.password() != null) {
            requestBuilder.header("Authorization", "Bearer " + repository.password());
        }

        return cachingHttpClient.get(requestBuilder, repository);
    }

    private static @Nullable PackageArtifactMetadata extractReleaseArtifactMetadata(JsonNode root, Instant resolvedAt) {
        return parseArtifactDate(root.path("published_at").asText(null), resolvedAt);
    }

    private static @Nullable PackageArtifactMetadata extractCommitArtifactMetadata(JsonNode root, Instant resolvedAt) {
        final JsonNode commit = root.path("commit");
        if (commit.isMissingNode() || commit.isNull()) {
            return null;
        }

        // NB: Prefer author date since it records when the code was authored.
        // Committer date can be reset by rebase or cherry-pick, which is misleading.
        String dateStr = commit.path("author").path("date").asText(null);
        if (dateStr == null) {
            dateStr = commit.path("committer").path("date").asText(null);
        }

        return parseArtifactDate(dateStr, resolvedAt);
    }

    private static @Nullable PackageArtifactMetadata parseArtifactDate(@Nullable String dateStr, Instant resolvedAt) {
        if (dateStr == null) {
            return null;
        }

        try {
            return new PackageArtifactMetadata(resolvedAt, Instant.parse(dateStr), Map.of());
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private JsonNode parseJson(byte[] body) {
        try {
            return objectMapper.readTree(body);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
