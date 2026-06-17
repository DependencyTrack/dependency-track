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
import io.github.nscuro.versatile.VersionFactory;
import io.github.nscuro.versatile.spi.InvalidVersionException;
import io.github.nscuro.versatile.spi.Version;
import io.github.nscuro.versatile.version.KnownVersioningSchemes;
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
    private static final Pattern RELEASE_PATTERN = Pattern.compile("<release>([^<]+)</release>");
    private static final Pattern VERSION_PATTERN = Pattern.compile("<version>([^<]+)</version>");

    private final CachingHttpClient cachingHttpClient;

    MavenPackageMetadataResolver(CachingHttpClient cachingHttpClient) {
        this.cachingHttpClient = cachingHttpClient;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository,
            @Nullable PackageArtifactMetadata prior) throws InterruptedException {
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

        // Prior is only trustworthy for stable versions of the same PURL.
        // Snapshot versions are mutable, so artifact metadata can change.
        final boolean canUsePrior = prior != null
                && purl.getVersion() != null
                && !isSnapshotVersion(purl.getVersion());
        final boolean priorMatchesLatest =
                canUsePrior && purl.getVersion().equals(latestVersion);

        final String latestArtifactUrl = join(baseUrl, latestVersion, formatArtifactFileName(purl, latestVersion));
        final Instant latestVersionPublishedAt = (priorMatchesLatest && prior.publishedAt() != null)
                ? prior.publishedAt()
                : resolvePublishedAt(latestArtifactUrl, repository);
        if (Thread.interrupted()) {
            throw new InterruptedException();
        }

        if (purl.getVersion() == null) {
            return new PackageMetadata(latestVersion, latestVersionPublishedAt, resolvedAt, null);
        }

        final String artifactUrl = join(baseUrl, purl.getVersion(), formatArtifactFileName(purl, null));

        final Instant publishedAt;
        if (purl.getVersion().equals(latestVersion)) {
            publishedAt = latestVersionPublishedAt;
        } else if (canUsePrior && prior.publishedAt() != null) {
            publishedAt = prior.publishedAt();
        } else {
            publishedAt = resolvePublishedAt(artifactUrl, repository);
        }
        if (Thread.interrupted()) {
            throw new InterruptedException();
        }

        final String priorSha1 = canUsePrior
                ? prior.hashes().get(HashAlgorithm.SHA1)
                : null;
        final String sha1 = priorSha1 == null
                ? fetchSha1Hash(artifactUrl, repository)
                : priorSha1;
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
        // NB: <latest> and <release> do not reliably point to current stable versions.
        // They may be out-of-date, or point to RC versions. So we walk the entire
        // <versions> array, <latest>, AND <release>, and pick the highest stable
        // among all of them.
        final var candidate = new HighestStableVersionCandidate();

        final Matcher versionMatcher = VERSION_PATTERN.matcher(xml);
        while (versionMatcher.find()) {
            candidate.offer(versionMatcher.group(1));
        }

        final String releaseRaw = firstMatch(xml, RELEASE_PATTERN);
        candidate.offer(releaseRaw);

        final String latestRaw = firstMatch(xml, LATEST_PATTERN);
        candidate.offer(latestRaw);

        if (candidate.highestStableRaw != null) {
            return candidate.highestStableRaw;
        }

        if (releaseRaw != null) {
            return releaseRaw;
        }

        if (latestRaw != null) {
            return latestRaw;
        }

        return candidate.lastSeenRaw;
    }

    private static final class HighestStableVersionCandidate {

        private @Nullable String highestStableRaw;
        private @Nullable Version highestStableVersion;
        private @Nullable String lastSeenRaw;

        private void offer(@Nullable String raw) {
            if (raw == null) {
                return;
            }

            final String normalized = raw.strip();
            if (normalized.isEmpty()) {
                return;
            }

            lastSeenRaw = normalized;

            final Version parsed;
            try {
                parsed = VersionFactory.forScheme(KnownVersioningSchemes.SCHEME_MAVEN, normalized);
            } catch (InvalidVersionException e) {
                LOGGER.debug("Skipping version because parsing it failed: {}", normalized, e);
                return;
            }

            if (parsed.isStable()
                    && (highestStableVersion == null || parsed.compareTo(highestStableVersion) > 0)) {
                highestStableRaw = normalized;
                highestStableVersion = parsed;
            }
        }

    }

    private static @Nullable String firstMatch(String input, Pattern pattern) {
        final Matcher matcher = pattern.matcher(input);
        if (!matcher.find()) {
            return null;
        }

        final String match = matcher.group(1).strip();
        return !match.isEmpty() ? match : null;
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

    private static String formatArtifactFileName(
            PackageURL purl,
            @Nullable String versionOverride) {
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
                .append(versionOverride == null ? purl.getVersion() : versionOverride);
        if (classifier != null) {
            sb.append('-').append(classifier);
        }

        return sb.append('.').append(extension).toString();
    }

    static boolean isSnapshotVersion(String version) {
        return version.toLowerCase().endsWith("-snapshot");
    }

    private static @Nullable Instant parseHttpDate(String value) {
        try {
            return ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
        } catch (DateTimeParseException e) {
            LOGGER.debug("Failed to parse Last-Modified header: {}", value, e);
            return null;
        }
    }

}
