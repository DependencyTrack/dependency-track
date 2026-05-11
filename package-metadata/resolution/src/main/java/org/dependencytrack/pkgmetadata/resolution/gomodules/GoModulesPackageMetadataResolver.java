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
package org.dependencytrack.pkgmetadata.resolution.gomodules;

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
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.Map;

import static java.util.Objects.requireNonNull;

final class GoModulesPackageMetadataResolver implements PackageMetadataResolver {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private final ObjectMapper objectMapper;
    private final CachingHttpClient cachingHttpClient;

    GoModulesPackageMetadataResolver(ObjectMapper objectMapper, CachingHttpClient cachingHttpClient) {
        this.objectMapper = objectMapper;
        this.cachingHttpClient = cachingHttpClient;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        String modulePath = purl.getName();
        if (purl.getNamespace() != null) {
            // NB: A few modules do not have a namespace, such as
            // the standard library, e.g. pkg:golang/stdlib@1.26.0.
            modulePath = purl.getNamespace() + "/" + modulePath;
        }

        final byte[] body = fetchModule(modulePath, repository);
        if (body == null) {
            return null;
        }

        final JsonNode root = parseJson(body);
        final String latestVersion = root.path("Version").asText(null);
        if (latestVersion == null) {
            return null;
        }

        final var resolvedAt = Instant.now();
        final var latestVersionPublishedAt = extractPublishedAt(root);

        PackageArtifactMetadata artifactMetadata = null;
        if (purl.getVersion().equals(latestVersion)) {
            artifactMetadata = latestVersionPublishedAt != null
                    ? new PackageArtifactMetadata(resolvedAt, latestVersionPublishedAt, Map.of()) : null;
        } else {
            final byte[] versionBody = fetchVersionInfo(modulePath, purl.getVersion(), repository);
            if (versionBody != null) {
                final var publishedAt = extractPublishedAt(parseJson(versionBody));
                artifactMetadata = publishedAt != null
                        ? new PackageArtifactMetadata(resolvedAt, publishedAt, Map.of()) : null;
            }
        }

        return new PackageMetadata(latestVersion, latestVersionPublishedAt, resolvedAt, artifactMetadata);
    }

    private byte @Nullable [] fetchModule(
            String modulePath,
            PackageRepository repository) throws InterruptedException {
        final String[] moduleSegments = modulePath.split("/");
        final String url = UrlUtils.join(UrlUtils.join(repository.url(), moduleSegments), "@latest");
        return fetch(url, repository);
    }

    private byte @Nullable [] fetchVersionInfo(
            String modulePath,
            String version,
            PackageRepository repository) throws InterruptedException {
        final String[] moduleSegments = modulePath.split("/");
        final String url = UrlUtils.join(
                UrlUtils.join(repository.url(), moduleSegments), "@v", version + ".info");
        return fetch(url, repository);
    }

    private byte @Nullable [] fetch(String url, PackageRepository repository) throws InterruptedException {
        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .GET();
        maybeApplyAuth(requestBuilder, repository);

        return cachingHttpClient.get(requestBuilder, repository);
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

    private static @Nullable Instant extractPublishedAt(JsonNode root) {
        final String time = root.path("Time").asText(null);
        if (time == null) {
            return null;
        }

        try {
            return Instant.parse(time);
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
