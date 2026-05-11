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
package org.dependencytrack.pkgmetadata.resolution.composer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.packageurl.PackageURL;
import io.github.nscuro.versatile.VersionFactory;
import io.github.nscuro.versatile.spi.InvalidVersionException;
import io.github.nscuro.versatile.spi.Version;
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
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Pattern;

import static io.github.nscuro.versatile.version.KnownVersioningSchemes.SCHEME_COMPOSER;
import static java.util.Objects.requireNonNull;

final class ComposerPackageMetadataResolver implements PackageMetadataResolver {

    private static final Logger LOGGER = LoggerFactory.getLogger(ComposerPackageMetadataResolver.class);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);
    private static final String V1_METADATA_URL_PATTERN = "/p/%package%.json";
    private static final int MAX_INCLUDE_DEPTH = 3;

    private final ObjectMapper objectMapper;
    private final CachingHttpClient cachingHttpClient;

    ComposerPackageMetadataResolver(ObjectMapper objectMapper, CachingHttpClient cachingHttpClient) {
        this.objectMapper = objectMapper;
        this.cachingHttpClient = cachingHttpClient;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final String packageKey = purl.getNamespace() + "/" + purl.getName();
        final JsonNode repoRoot = fetchRepoRoot(repository);

        JsonNode packageVersions = null;

        // NB: provider-includes (V1 provider hashing) is intentionally not supported.
        // Repos with only provider-includes will fall through to the V1 per-package URL fallback.
        final boolean hasUsableRoot = repoRoot != null
                && (repoRoot.has("metadata-url") || repoRoot.has("packages") || repoRoot.has("includes"));

        if (!hasUsableRoot) {
            LOGGER.debug("No usable packages.json, falling back to V1");
            packageVersions = fetchAndExtractPackage(V1_METADATA_URL_PATTERN, packageKey, repository);
        } else if (!isPackageAvailable(repoRoot, packageKey)) {
            LOGGER.debug("Package is not available in this repository");
            return null;
        } else if (repoRoot.has("metadata-url")) {
            packageVersions = fetchAndExtractPackage(
                    repoRoot.path("metadata-url").asText(),
                    packageKey,
                    repository);
        } else {
            // V1 path: check inline packages, then includes, then per-package URL.
            final JsonNode inlinePackages = repoRoot.path("packages");
            if (inlinePackages.isObject() && !inlinePackages.isEmpty() && inlinePackages.has(packageKey)) {
                packageVersions = inlinePackages.path(packageKey);
            } else if (repoRoot.has("includes")) {
                final JsonNode merged = loadIncludes(repoRoot, repository, 0);
                if (merged != null && merged.has(packageKey)) {
                    packageVersions = merged.path(packageKey);
                }
            }

            if (packageVersions == null) {
                LOGGER.debug(
                        "Package {} not found inline/includes for {}, falling back to V1",
                        packageKey, repository.url());
                packageVersions = fetchAndExtractPackage(V1_METADATA_URL_PATTERN, packageKey, repository);
            }
        }

        if (packageVersions == null) {
            return null;
        }

        return buildMetadata(packageVersions, purl);
    }

    private @Nullable JsonNode fetchRepoRoot(PackageRepository repository) throws InterruptedException {
        final String url = UrlUtils.trimTrailingSlash(repository.url()) + "/packages.json";
        final byte[] body = fetchUrl(url, repository);
        return body == null ? null : parseJson(body);
    }

    private static boolean isPackageAvailable(JsonNode repoRoot, String packageKey) {
        final boolean hasAvailablePackages = repoRoot.has("available-packages");
        final boolean hasPatterns = repoRoot.has("available-package-patterns");

        if (!hasAvailablePackages && !hasPatterns) {
            return true;
        }

        if (hasAvailablePackages) {
            for (final JsonNode pkg : repoRoot.path("available-packages")) {
                if (packageKey.equals(pkg.asText())) {
                    return true;
                }
            }
        }

        if (hasPatterns) {
            for (final JsonNode patternNode : repoRoot.path("available-package-patterns")) {
                if (wildcardToPattern(patternNode.asText()).matcher(packageKey).matches()) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Convert a Composer wildcard pattern (e.g. {@code drupal/*}) to a compiled regex.
     * Non-wildcard segments are quoted to prevent ReDoS from untrusted repository data.
     */
    private static Pattern wildcardToPattern(String wildcardPattern) {
        final String[] parts = wildcardPattern.split("\\*", -1);
        final var sb = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) {
                sb.append(".*");
            }
            sb.append(Pattern.quote(parts[i]));
        }

        return Pattern.compile(sb.toString(), Pattern.CASE_INSENSITIVE);
    }

    private @Nullable JsonNode fetchAndExtractPackage(
            String urlPattern,
            String packageKey,
            PackageRepository repository) throws InterruptedException {
        final String url = buildUrl(repository, urlPattern, packageKey);
        if (url == null) {
            return null;
        }

        final byte[] body = fetchUrl(url, repository);
        if (body == null) {
            return null;
        }

        final JsonNode packageNode = parseJson(body).path("packages").path(packageKey);
        return packageNode.isMissingNode() || packageNode.isEmpty() ? null : packageNode;
    }

    private @Nullable JsonNode loadIncludes(
            JsonNode repoRoot,
            PackageRepository repository,
            int depth) throws InterruptedException {
        if (depth >= MAX_INCLUDE_DEPTH) {
            LOGGER.warn("Max include depth ({}) reached, stopping recursive loading", MAX_INCLUDE_DEPTH);
            return null;
        }

        final JsonNode includes = repoRoot.path("includes");
        if (!includes.isObject() || includes.isEmpty()) {
            return null;
        }

        final ObjectNode merged = objectMapper.createObjectNode();

        final Iterator<String> includeNames = includes.fieldNames();
        while (includeNames.hasNext()) {
            final String includeFilename = includeNames.next();
            final String includeUrl = UrlUtils.resolve(repository.url(), includeFilename);
            if (includeUrl == null) {
                LOGGER.warn("Skipping invalid include filename: {}", includeFilename);
                continue;
            }

            final byte[] includeBody = fetchUrl(includeUrl, repository);
            if (includeBody == null) {
                continue;
            }

            final JsonNode includeData = parseJson(includeBody);
            final JsonNode includePackages = includeData.path("packages");
            if (includePackages.isObject()) {
                mergePackages(merged, includePackages);
            }

            if (includeData.has("includes")) {
                final JsonNode nestedMerged = loadIncludes(includeData, repository, depth + 1);
                if (nestedMerged != null) {
                    mergePackages(merged, nestedMerged);
                }
            }
        }

        return merged.isEmpty() ? null : merged;
    }

    private static void mergePackages(ObjectNode target, JsonNode source) {
        for (final Map.Entry<String, JsonNode> field : source.properties()) {
            final String name = field.getKey();
            final JsonNode sourceValue = field.getValue();
            if (target.has(name) && target.get(name).isObject() && sourceValue.isObject()) {
                final ObjectNode targetVersions = (ObjectNode) target.get(name);
                sourceValue.properties().forEach(e -> targetVersions.set(e.getKey(), e.getValue()));
            } else {
                target.set(name, sourceValue);
            }
        }
    }

    private @Nullable PackageMetadata buildMetadata(JsonNode packageVersions, PackageURL purl) {
        final String latestVersion = findLatestVersion(packageVersions);
        if (latestVersion == null) {
            return null;
        }

        final var resolvedAt = Instant.now();
        final VersionMetadata versionMetadata = findVersionMetadata(
                packageVersions,
                latestVersion,
                purl.getVersion(),
                resolvedAt);

        return new PackageMetadata(
                latestVersion,
                versionMetadata.latestVersionPublishedAt(),
                resolvedAt,
                versionMetadata.artifactMetadata());
    }

    private static @Nullable String findLatestVersion(JsonNode packageVersions) {
        Version highestStable = null;
        String highestStableRaw = null;
        Version highestAny = null;
        String highestAnyRaw = null;

        for (final JsonNode entry : versionEntries(packageVersions)) {
            final String versionStr = entry.path("version").asText(null);
            if (versionStr == null) {
                continue;
            }

            // Dev branches (e.g. dev-main, dev-feature/foo) are VCS branches, not releases.
            if (versionStr.startsWith("dev-") || versionStr.endsWith("-dev")) {
                continue;
            }

            final Version version;
            try {
                version = VersionFactory.forScheme(SCHEME_COMPOSER, versionStr);
            } catch (InvalidVersionException e) {
                LOGGER.debug("Skipping unparseable version: {}", versionStr);
                continue;
            }

            if (version.isStable()) {
                if (highestStable == null || version.compareTo(highestStable) > 0) {
                    highestStable = version;
                    highestStableRaw = versionStr;
                }
            }

            if (highestAny == null || version.compareTo(highestAny) > 0) {
                highestAny = version;
                highestAnyRaw = versionStr;
            }
        }

        return highestStableRaw != null ? highestStableRaw : highestAnyRaw;
    }

    private static VersionMetadata findVersionMetadata(
            JsonNode packageVersions,
            @Nullable String latestVersion,
            @Nullable String requestedVersion,
            Instant resolvedAt) {
        Version requested = null;
        Version requestedLatest = null;
        if (requestedVersion != null) {
            try {
                requested = VersionFactory.forScheme(SCHEME_COMPOSER, requestedVersion);
            } catch (InvalidVersionException ignored) {}
        }
        if (latestVersion != null) {
            try {
                requestedLatest = VersionFactory.forScheme(SCHEME_COMPOSER, latestVersion);
            } catch (InvalidVersionException ignored) {}
        }

        Instant latestVersionPublishedAt = null;
        PackageArtifactMetadata artifactMetadata = null;

        for (final JsonNode entry : versionEntries(packageVersions)) {
            final String entryVersion = entry.path("version").asText(null);
            if (entryVersion == null) {
                continue;
            }

            try {
                if (requestedLatest != null && requestedLatest.equals(VersionFactory.forScheme(SCHEME_COMPOSER, entryVersion))) {
                    latestVersionPublishedAt = extractPublishedAt(entry);
                }
            } catch (InvalidVersionException ignored) {
            }

            try {
                if (requested != null && requested.equals(VersionFactory.forScheme(SCHEME_COMPOSER, entryVersion))) {
                    artifactMetadata = extractArtifactMetadata(entry, resolvedAt);
                    if (latestVersionPublishedAt != null) {
                        break;
                    }
                }
            } catch (InvalidVersionException ignored) {
            }
        }

        return new VersionMetadata(latestVersionPublishedAt, artifactMetadata);
    }

    private static Iterable<JsonNode> versionEntries(JsonNode packageVersions) {
        return packageVersions.isArray() ? packageVersions : packageVersions::elements;
    }

    private static @Nullable Instant extractPublishedAt(JsonNode entry) {
        final String time = entry.path("time").asText(null);
        if (time == null) {
            return null;
        }

        try {
            return OffsetDateTime.parse(time).toInstant();
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static @Nullable PackageArtifactMetadata extractArtifactMetadata(JsonNode entry, Instant resolvedAt) {
        final Instant publishedAt = extractPublishedAt(entry);
        if (publishedAt == null) {
            return null;
        }

        return new PackageArtifactMetadata(resolvedAt, publishedAt, Map.of());
    }

    private record VersionMetadata(
            @Nullable Instant latestVersionPublishedAt,
            @Nullable PackageArtifactMetadata artifactMetadata) {
    }

    private static @Nullable String buildUrl(PackageRepository repository, String urlPattern, String packageKey) {
        final String resolved = urlPattern.replace("%package%", packageKey);
        if (resolved.startsWith("http://") || resolved.startsWith("https://")) {
            if (!UrlUtils.hasSameOrigin(resolved, repository.url())) {
                LOGGER.warn("Skipping absolute URL '{}': origin does not match repository '{}'", resolved, repository.url());
                return null;
            }

            return resolved;
        }

        final String base = UrlUtils.trimTrailingSlash(repository.url());
        return resolved.startsWith("/") ? base + resolved : base + "/" + resolved;
    }

    private byte @Nullable [] fetchUrl(String url, PackageRepository repository) throws InterruptedException {
        final URI requestUri;
        try {
            requestUri = URI.create(url);
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Skipping malformed URL '{}' for repository '{}'", url, repository.url(), e);
            return null;
        }

        final HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(requestUri)
                .timeout(REQUEST_TIMEOUT)
                .GET();

        if (repository.password() != null && UrlUtils.hasSameOrigin(url, repository.url())) {
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

        return cachingHttpClient.get(builder, repository);
    }

    private JsonNode parseJson(byte[] body) {
        try {
            return objectMapper.readTree(body);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
