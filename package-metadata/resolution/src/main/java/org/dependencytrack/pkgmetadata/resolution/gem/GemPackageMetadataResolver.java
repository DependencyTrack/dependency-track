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
package org.dependencytrack.pkgmetadata.resolution.gem;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.Map;

import static java.util.Objects.requireNonNull;

final class GemPackageMetadataResolver implements PackageMetadataResolver {

    private static final Logger LOGGER = LoggerFactory.getLogger(GemPackageMetadataResolver.class);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private final ObjectMapper objectMapper;
    private final CachingHttpClient cachingHttpClient;

    GemPackageMetadataResolver(ObjectMapper objectMapper, CachingHttpClient cachingHttpClient) {
        this.objectMapper = objectMapper;
        this.cachingHttpClient = cachingHttpClient;
    }

    @Override
    public @Nullable PackageMetadata resolve(PackageURL purl, @Nullable PackageRepository repository)
            throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final String url = UrlUtils.join(repository.url(), "api", "v1", "versions", purl.getName() + ".json");

        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .GET();
        maybeApplyAuth(requestBuilder, repository);

        final byte[] body = cachingHttpClient.get(requestBuilder, repository);
        if (body == null) {
            return null;
        }

        final JsonNode root = parseJson(body);
        if (!root.isArray() || root.isEmpty()) {
            return null;
        }

        final String latestVersion = root.get(0).path("number").asText(null);
        if (latestVersion == null) {
            return null;
        }
        Instant latestVersionPublishedAt = getCreatedAt(root.get(0));

        final String requestedVersion = purl.getVersion();
        JsonNode matchingEntry = null;
        for (int i = 0; i < root.size(); i++) {
            if (requestedVersion.equals(root.get(i).path("number").asText(null))) {
                matchingEntry = root.get(i);
                break;
            }
        }

        final var resolvedAt = Instant.now();
        if (matchingEntry == null) {
            return new PackageMetadata(latestVersion, latestVersionPublishedAt, resolvedAt, null);
        }

        Instant publishedAt = latestVersion.equals(requestedVersion)
                ? latestVersionPublishedAt
                : getCreatedAt(matchingEntry);

        return new PackageMetadata(
                latestVersion,
                latestVersionPublishedAt,
                resolvedAt,
                publishedAt != null
                        ? new PackageArtifactMetadata(resolvedAt, publishedAt, Map.of())
                        : null);
    }

    private @Nullable Instant getCreatedAt(JsonNode entry) {
        final String createdAt = entry.path("created_at").asText(null);
        if (createdAt != null) {
            try {
                return Instant.parse(createdAt);
            } catch (DateTimeParseException e) {
                LOGGER.debug("Failed to parse created_at '{}'", createdAt, e);
            }
        }
        return null;
    }

    private static void maybeApplyAuth(HttpRequest.Builder builder, PackageRepository repository) {
        // NB: Private gem mirrors (Gemstash, Gemfury, GitLab, Artifactory) use Basic auth.
        // rubygems.org uses a raw API key header, but its read endpoints don't require auth.
        if (repository.username() == null || repository.password() == null) {
            return;
        }

        final String credentials = repository.username() + ":" + repository.password();
        builder.header(
                "Authorization",
                "Basic " + Base64.getEncoder().encodeToString(
                        credentials.getBytes(StandardCharsets.UTF_8)));
    }

    private JsonNode parseJson(byte[] body) {
        try {
            return objectMapper.readTree(body);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
