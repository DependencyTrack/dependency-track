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
package org.dependencytrack.pkgmetadata.resolution.maven;

import com.github.packageurl.PackageURL;
import org.dependencytrack.pkgmetadata.resolution.api.HashAlgorithm;
import org.dependencytrack.pkgmetadata.resolution.api.PackageArtifactMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.pkgmetadata.resolution.cache.CachingHttpClient;
import org.dependencytrack.pkgmetadata.resolution.support.UrlUtils;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.EnumMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.pkgmetadata.resolution.support.UrlUtils.join;

final class MavenPackageMetadataResolver implements PackageMetadataResolver {

    private static final Logger LOGGER = LoggerFactory.getLogger(MavenPackageMetadataResolver.class);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);
    private static final Pattern LATEST_PATTERN = Pattern.compile("<latest>([^<]+)</latest>");
    private static final Pattern VERSION_PATTERN = Pattern.compile("<version>([^<]+)</version>");

    private final CachingHttpClient cachingHttpClient;

    MavenPackageMetadataResolver(CachingHttpClient cachingHttpClient) {
        this.cachingHttpClient = cachingHttpClient;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final String baseUrl = join(repository.url(),
                Stream.concat(
                        Stream.of(purl.getNamespace().split("\\.")),
                        Stream.of(purl.getName())
                ).toArray(String[]::new));

        final Instant resolvedAt = Instant.now();

        final String latestVersion = resolveLatestVersion(baseUrl, repository);
        if (latestVersion == null) {
            return null;
        }
        if (Thread.interrupted()) {
            throw new InterruptedException();
        }

        String artifactUrl = join(baseUrl, latestVersion, formatArtifactFileName(purl, latestVersion));
        final var latestVersionPublishedAt = resolvePublishedAt(artifactUrl, repository);
        if (Thread.interrupted()) {
            throw new InterruptedException();
        }

        if (purl.getVersion() == null) {
            return new PackageMetadata(latestVersion, latestVersionPublishedAt, resolvedAt, null);
        }

        artifactUrl = join(baseUrl, purl.getVersion(), formatArtifactFileName(purl, null));

        final var publishedAt = purl.getVersion().equals(latestVersion)
                ? latestVersionPublishedAt
                : resolvePublishedAt(artifactUrl, repository);
        if (Thread.interrupted()) {
            throw new InterruptedException();
        }

        final String sha1 = fetchSha1Hash(artifactUrl, repository);
        var hashes = new EnumMap<HashAlgorithm, String>(HashAlgorithm.class);
        if (sha1 != null) {
            hashes.put(HashAlgorithm.SHA1, sha1);
        }

        return new PackageMetadata(
                latestVersion,
                latestVersionPublishedAt,
                resolvedAt,
                !hashes.isEmpty() || publishedAt != null
                        ? new PackageArtifactMetadata(resolvedAt, publishedAt, hashes)
                        : null);
    }

    private @Nullable String resolveLatestVersion(
            String baseUrl,
            PackageRepository repository)
            throws InterruptedException {
        final URI uri = URI.create(UrlUtils.join(baseUrl, "maven-metadata.xml"));

        final byte[] xmlBytes = cachingHttpClient.get(
                newRequestBuilder(uri, repository, "GET"), repository);
        if (xmlBytes == null) {
            return null;
        }

        return parseLatestVersion(new String(xmlBytes, StandardCharsets.UTF_8));
    }

    private static @Nullable String parseLatestVersion(String xml) {
        final Matcher latestMatcher = LATEST_PATTERN.matcher(xml);
        if (latestMatcher.find()) {
            return latestMatcher.group(1);
        }

        // Fall back to last <version> in <versions> list.
        // Sometimes the latest version is not explicitly recorded.
        String lastVersion = null;
        final Matcher versionMatcher = VERSION_PATTERN.matcher(xml);
        while (versionMatcher.find()) {
            lastVersion = versionMatcher.group(1);
        }

        return lastVersion;
    }

    private @Nullable Instant resolvePublishedAt(
            String artifactUrl,
            PackageRepository repository) throws InterruptedException {
        // NB: The Last-Modified timestamp is not suuuuuper reliable
        // because artifacts can technically be modified after they've
        // first been published. Also, repository proxies can have different
        // modified timestamps than the repository they're proxying.
        // The Maven protocol doesn't offer a native way to determine
        // publish timestamps, so this is a best-effort resolution.

        final HttpHeaders headers = cachingHttpClient.head(
                newRequestBuilder(URI.create(artifactUrl), repository, "HEAD"),
                repository,
                "last-modified"::equalsIgnoreCase);
        if (headers == null) {
            return null;
        }

        return headers.firstValue("Last-Modified")
                .map(MavenPackageMetadataResolver::parseHttpDate)
                .orElse(null);
    }

    private static @Nullable Instant parseHttpDate(String value) {
        try {
            return ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
        } catch (DateTimeParseException e) {
            LOGGER.debug("Failed to parse Last-Modified header: {}", value, e);
            return null;
        }
    }

    private @Nullable String fetchSha1Hash(
            String artifactUrl,
            PackageRepository repository) throws InterruptedException {
        final byte[] body = cachingHttpClient.get(
                newRequestBuilder(URI.create(artifactUrl + ".sha1"), repository, "GET"),
                repository);
        if (body == null) {
            LOGGER.debug("No SHA-1 hash file found");
            return null;
        }

        String hash = new String(body, StandardCharsets.UTF_8).strip();
        final int spaceIndex = hash.indexOf(' ');
        if (spaceIndex > 0) {
            hash = hash.substring(0, spaceIndex);
        }
        hash = hash.toLowerCase();

        if (!HashAlgorithm.SHA1.isValid(hash)) {
            LOGGER.debug("Ignoring invalid SHA-1 hash: {}", hash);
            return null;
        }

        return hash;
    }

    private static HttpRequest.Builder newRequestBuilder(URI uri, PackageRepository repository, String method) {
        final HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(uri)
                .method(method, HttpRequest.BodyPublishers.noBody())
                .timeout(REQUEST_TIMEOUT);
        maybeApplyAuth(builder, repository);
        return builder;
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

    private static String formatArtifactFileName(PackageURL purl, String versionOverride) {
        final Map<String, String> qualifiers = purl.getQualifiers();

        final String extension = qualifiers != null
                ? qualifiers.getOrDefault("type", "jar")
                : "jar";
        final String classifier = qualifiers != null
                ? qualifiers.get("classifier")
                : null;

        final var sb = new StringBuilder()
                .append(purl.getName())
                .append('-')
                .append(versionOverride == null ? purl.getVersion() :  versionOverride);
        if (classifier != null) {
            sb.append('-').append(classifier);
        }

        return sb.append('.').append(extension).toString();
    }

}
