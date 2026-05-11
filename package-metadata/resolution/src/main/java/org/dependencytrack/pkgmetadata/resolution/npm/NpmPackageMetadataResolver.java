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
package org.dependencytrack.pkgmetadata.resolution.npm;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.PackageURL;
import org.dependencytrack.pkgmetadata.resolution.api.HashAlgorithm;
import org.dependencytrack.pkgmetadata.resolution.api.PackageArtifactMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.cache.CachingHttpClient;
import org.dependencytrack.pkgmetadata.resolution.npm.NpmPackageDocument.VersionInfo;
import org.dependencytrack.pkgmetadata.resolution.support.UrlUtils;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.EnumMap;
import java.util.HexFormat;

import static java.util.Objects.requireNonNull;

final class NpmPackageMetadataResolver implements PackageMetadataResolver {

    private static final Logger LOGGER = LoggerFactory.getLogger(NpmPackageMetadataResolver.class);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private final CachingHttpClient cachingHttpClient;
    private final JsonFactory jsonFactory;

    NpmPackageMetadataResolver(ObjectMapper objectMapper, CachingHttpClient cachingHttpClient) {
        this.jsonFactory = objectMapper.getFactory();
        this.cachingHttpClient = cachingHttpClient;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final String packageName = formatPackageName(purl);

        final NpmPackageDocument doc = fetchAndParseDocument(packageName, repository);
        if (doc == null) {
            return null;
        }

        final Instant resolvedAt = Instant.now();
        final VersionInfo versionInfo = doc.versions().get(purl.getVersion());
        final var latestVersionPublishedAt = (doc.latestVersion() != null && doc.versions().containsKey(doc.latestVersion()))
                ? doc.versions().get(doc.latestVersion()).publishedAt()
                : null;
        return buildResult(doc.latestVersion(), latestVersionPublishedAt, resolvedAt, versionInfo);
    }

    private static String formatPackageName(PackageURL purl) {
        return purl.getNamespace() != null
                ? purl.getNamespace() + "/" + purl.getName()
                : purl.getName();
    }

    private @Nullable NpmPackageDocument fetchAndParseDocument(
            String packageName,
            PackageRepository repository) throws InterruptedException {
        final String url = UrlUtils.join(repository.url(), packageName);

        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .GET();

        if (repository.password() != null) {
            requestBuilder.header("Authorization", "Bearer " + repository.password());
        }

        final byte[] body = cachingHttpClient.get(requestBuilder, repository);
        if (body == null) {
            return null;
        }

        try (final var parser = jsonFactory.createParser(new ByteArrayInputStream(body))) {
            return NpmPackageDocument.parseFrom(parser);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static @Nullable PackageMetadata buildResult(
            @Nullable String latestVersion,
            @Nullable Instant latestVersionPublishedAt,
            Instant resolvedAt,
            @Nullable VersionInfo versionInfo) {
        Instant publishedAt = null;
        var hashes = new EnumMap<HashAlgorithm, String>(HashAlgorithm.class);

        if (versionInfo != null) {
            publishedAt = versionInfo.publishedAt();
            if (versionInfo.shasum() != null) {
                hashes.put(HashAlgorithm.SHA1, versionInfo.shasum());
            }
            if (versionInfo.integrity() != null) {
                try {
                    final byte[] decoded = Base64.getDecoder().decode(versionInfo.integrity());
                    hashes.put(HashAlgorithm.SHA512, HexFormat.of().formatHex(decoded));
                } catch (IllegalArgumentException e) {
                    LOGGER.debug("Failed to decode SHA-512 from base64", e);
                }
            }
        }

        if (latestVersion == null && publishedAt == null && hashes.isEmpty()) {
            return null;
        }

        final PackageArtifactMetadata artifactMetadata = (versionInfo != null)
                ? new PackageArtifactMetadata(resolvedAt, publishedAt, hashes)
                : null;

        return new PackageMetadata(
                latestVersion,
                latestVersionPublishedAt,
                resolvedAt,
                artifactMetadata);
    }

}
