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
package org.dependencytrack.pkgmetadata.resolution.cpan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.PackageURL;
import org.dependencytrack.pkgmetadata.resolution.api.HashAlgorithm;
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
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.EnumMap;

import static java.util.Objects.requireNonNull;

final class CpanPackageMetadataResolver implements PackageMetadataResolver {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private final ObjectMapper objectMapper;
    private final CachingHttpClient cachingHttpClient;

    CpanPackageMetadataResolver(ObjectMapper objectMapper, CachingHttpClient cachingHttpClient) {
        this.objectMapper = objectMapper;
        this.cachingHttpClient = cachingHttpClient;
    }

    @Override
    public @Nullable PackageMetadata resolve(PackageURL purl, @Nullable PackageRepository repository)
            throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final String url = UrlUtils.join(repository.url(), "v1", "release", purl.getName());

        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .GET();

        final byte[] body = cachingHttpClient.get(requestBuilder, repository);
        if (body == null) {
            return null;
        }

        final JsonNode root = parseJson(body);
        final String latestVersion = root.path("version").asText(null);
        if (latestVersion == null) {
            return null;
        }

        // The /v1/release/{name} endpoint returns the latest release only.
        // Version metadata is only available when the queried version matches the latest.
        final var resolvedAt = Instant.now();
        final var publishedAt = getPublishedAt(root);

        PackageArtifactMetadata artifactMetadata = null;
        if (purl.getVersion() != null && purl.getVersion().equals(latestVersion)) {
            artifactMetadata = extractArtifactMetadata(root, resolvedAt, publishedAt);
        }

        return new PackageMetadata(latestVersion, publishedAt, resolvedAt, artifactMetadata);
    }

    private static @Nullable PackageArtifactMetadata extractArtifactMetadata(JsonNode root, Instant resolvedAt, Instant publishedAt) {
        final var hashes = new EnumMap<HashAlgorithm, String>(HashAlgorithm.class);
        final String sha256 = root.path("checksum_sha256").asText(null);
        if (sha256 != null && HashAlgorithm.SHA256.isValid(sha256)) {
            hashes.put(HashAlgorithm.SHA256, sha256.toLowerCase());
        }

        if (publishedAt == null && hashes.isEmpty()) {
            return null;
        }

        return new PackageArtifactMetadata(resolvedAt, publishedAt, hashes);
    }

    private static @Nullable Instant getPublishedAt(JsonNode root) {
        Instant publishedAt = null;
        final String date = root.path("date").asText(null);
        if (date != null) {
            try {
                // CPAN dates are in ISO local date-time format without timezone (UTC implied).
                publishedAt = LocalDateTime.parse(date).toInstant(ZoneOffset.UTC);
            } catch (DateTimeParseException ignored) {
            }
        }
        return publishedAt;
    }

    private JsonNode parseJson(byte[] body) {
        try {
            return objectMapper.readTree(body);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
