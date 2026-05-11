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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.PackageURL;
import org.dependencytrack.pkgmetadata.resolution.api.HashAlgorithm;
import org.dependencytrack.pkgmetadata.resolution.api.PackageArtifactMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.cache.CachingHttpClient;
import org.dependencytrack.pkgmetadata.resolution.cargo.CargoCrateDocument.Version;
import org.dependencytrack.pkgmetadata.resolution.support.UrlUtils;
import org.jspecify.annotations.Nullable;

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

final class CargoPackageMetadataResolver implements PackageMetadataResolver {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private final ObjectMapper objectMapper;
    private final CachingHttpClient cachingHttpClient;

    CargoPackageMetadataResolver(ObjectMapper objectMapper, CachingHttpClient cachingHttpClient) {
        this.objectMapper = objectMapper;
        this.cachingHttpClient = cachingHttpClient;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final String url = UrlUtils.join(repository.url(), "api", "v1", "crates", purl.getName());

        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .GET();
        maybeApplyAuth(requestBuilder, repository);

        final byte[] body = cachingHttpClient.get(requestBuilder, repository);
        if (body == null) {
            return null;
        }

        final CargoCrateDocument crateDoc = parseDocument(body);
        final String latestVersion = crateDoc.crate() != null
                ? crateDoc.crate().newestVersion()
                : null;
        if (latestVersion == null) {
            return null;
        }

        final var resolvedAt = Instant.now();
        Instant latestVersionPublishedAt = null;

        Version requestedVersion = null;
        if (crateDoc.versions() != null) {
            for (final Version crateVersion : crateDoc.versions()) {
                if (latestVersion.equals(crateVersion.num())) {
                    if (crateVersion.createdAt() != null) {
                        try {
                            latestVersionPublishedAt = Instant.parse(crateVersion.createdAt());
                        } catch (DateTimeParseException ignored) {
                        }
                    }
                }
                if (purl.getVersion().equals(crateVersion.num())) {
                    requestedVersion = crateVersion;
                }
            }
        }

        return new PackageMetadata(
                latestVersion,
                latestVersionPublishedAt,
                resolvedAt,
                buildArtifactMetadata(resolvedAt, requestedVersion));
    }

    private static @Nullable PackageArtifactMetadata buildArtifactMetadata(
            Instant resolvedAt, @Nullable Version crateVersion) {
        if (crateVersion == null) {
            return null;
        }

        Instant publishedAt = null;
        if (crateVersion.createdAt() != null) {
            try {
                publishedAt = Instant.parse(crateVersion.createdAt());
            } catch (DateTimeParseException ignored) {
            }
        }

        Map<HashAlgorithm, String> hashes = Map.of();
        if (crateVersion.checksum() != null
                && HashAlgorithm.SHA256.isValid(crateVersion.checksum())) {
            hashes = Map.of(HashAlgorithm.SHA256, crateVersion.checksum().toLowerCase());
        }

        if (publishedAt == null && hashes.isEmpty()) {
            return null;
        }

        return new PackageArtifactMetadata(resolvedAt, publishedAt, hashes);
    }

    private static void maybeApplyAuth(HttpRequest.Builder builder, PackageRepository repository) {
        if (repository.password() == null) {
            return;
        }

        final String authHeaderValue;
        if (repository.username() != null) {
            final String credentials = repository.username() + ":" + repository.password();
            authHeaderValue = "Basic " + Base64.getEncoder().encodeToString(
                    credentials.getBytes(StandardCharsets.UTF_8));
        } else {
            authHeaderValue = "Bearer " + repository.password();
        }

        builder.header("Authorization", authHeaderValue);
    }

    private CargoCrateDocument parseDocument(byte[] body) {
        try {
            return objectMapper.readValue(body, CargoCrateDocument.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
