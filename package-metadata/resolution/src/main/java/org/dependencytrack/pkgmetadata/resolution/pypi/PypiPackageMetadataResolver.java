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
package org.dependencytrack.pkgmetadata.resolution.pypi;

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
import java.time.format.DateTimeParseException;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

final class PypiPackageMetadataResolver implements PackageMetadataResolver {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private final ObjectMapper objectMapper;
    private final CachingHttpClient cachingHttpClient;

    PypiPackageMetadataResolver(ObjectMapper objectMapper, CachingHttpClient cachingHttpClient) {
        this.objectMapper = objectMapper;
        this.cachingHttpClient = cachingHttpClient;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final String fileName = purl.getQualifiers() != null
                ? purl.getQualifiers().get("file_name") : null;

        final PypiPackageDocument doc = fetchDocument(purl, repository);
        if (doc == null) {
            return null;
        }

        final String latestVersion = doc.info() != null ? doc.info().version() : null;
        final Map<String, List<PypiPackageDocument.ReleaseFile>> releases =
                doc.releases() != null ? doc.releases() : Map.of();

        final Instant resolvedAt = Instant.now();
        Instant latestVersionPublishedAt = null;

        ArtifactHashes matched = null;
        List<PypiPackageDocument.ReleaseFile> releaseFiles;
        if (fileName != null) {
            releaseFiles = releases.get(purl.getVersion());
            if (releaseFiles != null) {
                for (final PypiPackageDocument.ReleaseFile file : releaseFiles) {
                    if (fileName.equals(file.filename())) {
                        matched = extractHashes(file);
                        break;
                    }
                }
            }
        }
        if (latestVersion != null) {
            releaseFiles = releases.get(latestVersion);
            if (releaseFiles != null && !releaseFiles.isEmpty()) {
                Instant mostRecentUploadTime = null;
                for (PypiPackageDocument.ReleaseFile file : releaseFiles) {
                    if (file.uploadTime() != null) {
                        try {
                            Instant instant = Instant.parse(file.uploadTime());
                            if (mostRecentUploadTime == null || instant.isAfter(mostRecentUploadTime)) {
                                mostRecentUploadTime = instant;
                            }
                        } catch (DateTimeParseException ignored) {}
                    }
                }
                latestVersionPublishedAt = mostRecentUploadTime;
            }
        }

        return buildResult(latestVersion, latestVersionPublishedAt, resolvedAt, matched);
    }

    private @Nullable PypiPackageDocument fetchDocument(
            PackageURL purl,
            PackageRepository repository) throws InterruptedException {
        final String url = UrlUtils.join(repository.url(), "pypi", purl.getName(), "json");

        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .GET();

        final byte[] body = cachingHttpClient.get(requestBuilder, repository);
        if (body == null) {
            return null;
        }

        try {
            return objectMapper.readValue(body, PypiPackageDocument.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static @Nullable ArtifactHashes extractHashes(PypiPackageDocument.ReleaseFile file) {
        if (file.digests() == null) {
            return null;
        }

        final String md5 = file.digests().md5();
        final String sha256 = file.digests().sha256();

        if (md5 == null && sha256 == null) {
            return null;
        }

        return new ArtifactHashes(md5, sha256);
    }

    private static @Nullable PackageMetadata buildResult(
            @Nullable String latestVersion,
            @Nullable Instant latestVersionPublishedAt,
            Instant resolvedAt,
            @Nullable ArtifactHashes hashes) {
        if (latestVersion == null && hashes == null) {
            return null;
        }

        PackageArtifactMetadata artifactMetadata = null;
        if (hashes != null) {
            final var algoHashes = new EnumMap<HashAlgorithm, String>(HashAlgorithm.class);
            if (hashes.md5() != null) {
                algoHashes.put(HashAlgorithm.MD5, hashes.md5());
            }
            if (hashes.sha256() != null) {
                algoHashes.put(HashAlgorithm.SHA256, hashes.sha256());
            }
            artifactMetadata = new PackageArtifactMetadata(resolvedAt, null, algoHashes);
        }

        return new PackageMetadata(latestVersion, latestVersionPublishedAt, resolvedAt, artifactMetadata);
    }

    private record ArtifactHashes(@Nullable String md5, @Nullable String sha256) {
    }

}
