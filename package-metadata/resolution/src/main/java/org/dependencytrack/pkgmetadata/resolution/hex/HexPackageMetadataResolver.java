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
package org.dependencytrack.pkgmetadata.resolution.hex;

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

import static java.util.Objects.requireNonNull;

final class HexPackageMetadataResolver implements PackageMetadataResolver {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private final ObjectMapper objectMapper;
    private final CachingHttpClient cachingHttpClient;

    HexPackageMetadataResolver(ObjectMapper objectMapper, CachingHttpClient cachingHttpClient) {
        this.objectMapper = objectMapper;
        this.cachingHttpClient = cachingHttpClient;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final String url = UrlUtils.join(repository.url(), "api", "packages", purl.getName());

        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .GET();

        final byte[] body = cachingHttpClient.get(requestBuilder, repository);
        if (body == null) {
            return null;
        }

        final JsonNode root = parseJson(body);
        final JsonNode releases = root.path("releases");
        if (!releases.isArray() || releases.isEmpty()) {
            return null;
        }

        final String latestVersion = releases.get(0).path("version").asText(null);
        if (latestVersion == null) {
            return null;
        }
        final var latestVersionPublishedAt = extractPublishedAt(releases.get(0));
        final var resolvedAt = Instant.now();

        PackageArtifactMetadata artifactMetadata = null;
        if (purl.getVersion() != null) {
            for (final JsonNode release : releases) {
                if (purl.getVersion().equals(release.path("version").asText(null))) {
                    final var publishedAt = extractPublishedAt(release);
                    artifactMetadata = publishedAt != null
                            ? new PackageArtifactMetadata(resolvedAt, publishedAt, Map.of())
                            : null;
                    break;
                }
            }
        }

        return new PackageMetadata(latestVersion, latestVersionPublishedAt, resolvedAt, artifactMetadata);
    }

    private @Nullable Instant extractPublishedAt(JsonNode release) {
        final String insertedAt = release.path("inserted_at").asText(null);
        if (insertedAt != null) {
            try {
                return Instant.parse(insertedAt);
            } catch (DateTimeParseException ignored) {}
        }
        return null;
    }

    private JsonNode parseJson(byte[] body) {
        try {
            return objectMapper.readTree(body);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
