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
package org.dependencytrack.pkgmetadata.resolution.nuget;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.StreamSupport;

import static io.github.nscuro.versatile.version.KnownVersioningSchemes.SCHEME_NUGET;
import static java.util.Objects.requireNonNull;

final class NugetPackageMetadataResolver implements PackageMetadataResolver {

    private static final Logger LOGGER = LoggerFactory.getLogger(NugetPackageMetadataResolver.class);

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);
    private static final String SERVICE_INDEX_SUFFIX = "index.json";

    // Resource @types in the v3 service index, ordered by preference:
    //  * 3.6.0: gzip-compressed, includes SemVer 2.0.0 packages
    //  * 3.4.0: gzip-compressed, SemVer 1 only
    //  * (unversioned): uncompressed, SemVer 1 only
    // See https://learn.microsoft.com/en-us/nuget/api/registration-base-url-resource
    private static final List<String> REGISTRATIONS_RESOURCE_TYPES = List.of(
            "registrationsbaseurl/3.6.0",
            "registrationsbaseurl/3.4.0",
            "registrationsbaseurl");

    private final ObjectMapper objectMapper;
    private final CachingHttpClient cachingHttpClient;

    NugetPackageMetadataResolver(ObjectMapper objectMapper, CachingHttpClient cachingHttpClient) {
        this.objectMapper = objectMapper;
        this.cachingHttpClient = cachingHttpClient;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl,
            @Nullable PackageRepository repository) throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final String registrationsBaseUrl = discoverRegistrationsBaseUrl(repository);
        if (registrationsBaseUrl == null) {
            return null;
        }

        final String packageId = purl.getName().toLowerCase(Locale.ROOT);
        final String registrationIndexUrl = UrlUtils.join(registrationsBaseUrl, packageId, "index.json");

        final byte[] indexBody = fetch(registrationIndexUrl, repository);
        if (indexBody == null) {
            return null;
        }

        final JsonNode rootNode = parseJson(indexBody);
        final JsonNode pagesNode = rootNode.path("items");
        if (!pagesNode.isArray() || pagesNode.isEmpty()) {
            return null;
        }

        final List<Page> pages = sortPagesByUpperDesc(pagesNode);

        // Search stable releases first, and fall back to pre-release only if no stable exists.
        CatalogEntry latest = findLatest(pages, repository, false);
        if (latest == null) {
            latest = findLatest(pages, repository, true);
        }
        if (latest == null) {
            return null;
        }

        final Instant resolvedAt = Instant.now();
        PackageArtifactMetadata artifactMetadata = null;
        if (purl.getVersion() != null) {
            final Instant publishedAt = findPublishedAt(pages, repository, purl.getVersion());
            if (publishedAt != null) {
                artifactMetadata = new PackageArtifactMetadata(resolvedAt, publishedAt, Map.of());
            }
        }

        return new PackageMetadata(latest.version(), latest.publishedAt, resolvedAt, artifactMetadata);
    }

    private @Nullable String discoverRegistrationsBaseUrl(PackageRepository repository) throws InterruptedException {
        final String serviceIndexUrl = serviceIndexUrl(repository.url());

        final byte[] body = fetch(serviceIndexUrl, repository);
        if (body == null) {
            return null;
        }

        final JsonNode resources = parseJson(body).path("resources");
        if (!resources.isArray()) {
            LOGGER.debug("Service index at {} has no resources array", serviceIndexUrl);
            return null;
        }

        for (final String preferredType : REGISTRATIONS_RESOURCE_TYPES) {
            for (final JsonNode resource : resources) {
                final String type = resource.path("@type").asText("").toLowerCase(Locale.ROOT);
                if (type.startsWith(preferredType)) {
                    final String id = resource.path("@id").asText(null);
                    if (id != null && !id.isBlank()) {
                        return UrlUtils.trimTrailingSlash(id);
                    }
                }
            }
        }

        LOGGER.debug("Service index at {} does not advertise a RegistrationsBaseUrl resource", serviceIndexUrl);
        return null;
    }

    private static String serviceIndexUrl(String repositoryUrl) {
        // Treat URLs ending in index.json as fully qualified service index URLs to support
        // private repositories (Artifactory, Nexus, ...) that expose the v3 index at a
        // non-standard path.
        if (repositoryUrl.toLowerCase(Locale.ROOT).endsWith(SERVICE_INDEX_SUFFIX)) {
            return repositoryUrl;
        }

        return UrlUtils.trimTrailingSlash(repositoryUrl) + "/v3/index.json";
    }

    private List<Page> sortPagesByUpperDesc(JsonNode pagesNode) {
        // Pages with parseable upper bounds first (semantically descending),
        // unparseable bounds last (lexicographic descending fallback).
        return StreamSupport.stream(pagesNode.spliterator(), false)
                .map(NugetPackageMetadataResolver::toPage)
                .sorted(Comparator
                        .comparing((Page page) -> page.upperVersion() != null, Comparator.reverseOrder())
                        .thenComparing((a, b) -> {
                            if (a.upperVersion() != null && b.upperVersion() != null) {
                                return b.upperVersion().compareTo(a.upperVersion());
                            }

                            return b.upperRaw().compareToIgnoreCase(a.upperRaw());
                        }))
                .toList();
    }

    private static Page toPage(JsonNode pageNode) {
        final String upperRaw = pageNode.path("upper").asText("");
        if (upperRaw.isEmpty()) {
            return new Page(pageNode, upperRaw, null);
        }

        try {
            return new Page(pageNode, upperRaw, VersionFactory.forScheme(SCHEME_NUGET, upperRaw));
        } catch (InvalidVersionException e) {
            LOGGER.debug("Failed to parse NuGet page upper bound: {}", upperRaw, e);
            return new Page(pageNode, upperRaw, null);
        }
    }

    private @Nullable CatalogEntry findLatest(
            List<Page> pages,
            PackageRepository repository,
            boolean includePreRelease) throws InterruptedException {
        for (final Page page : pages) {
            final JsonNode leaves = resolveLeaves(page.node(), repository);
            if (leaves == null) {
                // A page request failure means we can't trust ordering.
                // Abort the pass to avoid surfacing a stale "latest" from an older page.
                return null;
            }

            CatalogEntry best = null;
            Version bestVersion = null;
            for (final JsonNode leaf : leaves) {
                final CatalogEntry entry = parseCatalogEntry(leaf.path("catalogEntry"));
                if (entry == null) {
                    continue;
                }

                final Version version;
                try {
                    version = VersionFactory.forScheme(SCHEME_NUGET, entry.version());
                } catch (InvalidVersionException e) {
                    LOGGER.debug("Skipping NuGet catalog entry with unparseable version {}", entry.version(), e);
                    continue;
                }

                if (!version.isStable() && !includePreRelease) {
                    continue;
                }

                if (bestVersion == null || version.compareTo(bestVersion) > 0) {
                    best = entry;
                    bestVersion = version;
                }
            }

            if (best != null) {
                return best;
            }
        }

        return null;
    }

    private @Nullable Instant findPublishedAt(
            List<Page> pages,
            PackageRepository repository,
            String requestedVersion) throws InterruptedException {
        // NuGet canonicalises versions in registration responses (e.g. "1.0" -> "1.0.0",
        // "1.0.0.0" -> "1.0.0"), so a raw string match would silently miss equivalent
        // versions. Compare semantically when possible, falling back to string equality
        // for unparseable versions on either side.
        final Version requested;
        try {
            requested = VersionFactory.forScheme(SCHEME_NUGET, requestedVersion);
        } catch (InvalidVersionException e) {
            LOGGER.debug("Requested NuGet version is unparseable, using raw string match: {}",
                    requestedVersion, e);
            return findPublishedAtByRawVersion(pages, repository, requestedVersion);
        }

        for (final Page page : pages) {
            final JsonNode leaves = resolveLeaves(page.node(), repository);
            if (leaves == null) {
                continue;
            }

            for (final JsonNode leaf : leaves) {
                final JsonNode catalogEntry = leaf.path("catalogEntry");
                final String entryVersion = catalogEntry.path("version").asText(null);
                if (entryVersion == null) {
                    continue;
                }

                final Version parsed;
                try {
                    parsed = VersionFactory.forScheme(SCHEME_NUGET, entryVersion);
                } catch (InvalidVersionException e) {
                    // Entry version is malformed. Still match it raw against the requested
                    // version so a non-canonical entry isn't silently skipped.
                    if (requestedVersion.equals(entryVersion)) {
                        return parsePublished(catalogEntry.path("published").asText(null));
                    }
                    continue;
                }

                if (requested.compareTo(parsed) == 0) {
                    return parsePublished(catalogEntry.path("published").asText(null));
                }
            }
        }
        return null;
    }

    private @Nullable Instant findPublishedAtByRawVersion(
            List<Page> pages,
            PackageRepository repository,
            String requestedVersion) throws InterruptedException {
        for (final Page page : pages) {
            final JsonNode leaves = resolveLeaves(page.node(), repository);
            if (leaves == null) {
                continue;
            }

            for (final JsonNode leaf : leaves) {
                final JsonNode catalogEntry = leaf.path("catalogEntry");
                if (requestedVersion.equals(catalogEntry.path("version").asText(null))) {
                    return parsePublished(catalogEntry.path("published").asText(null));
                }
            }
        }

        return null;
    }

    private @Nullable JsonNode resolveLeaves(JsonNode pageNode, PackageRepository repository) throws InterruptedException {
        final JsonNode inline = pageNode.path("items");
        if (inline.isArray() && !inline.isEmpty()) {
            return inline;
        }

        final String pageUrl = pageNode.path("@id").asText(null);
        if (pageUrl == null || pageUrl.isBlank()) {
            return null;
        }

        final byte[] body = fetch(pageUrl, repository);
        if (body == null) {
            return null;
        }

        final JsonNode leaves = parseJson(body).path("items");
        return leaves.isArray() ? leaves : null;
    }

    private static @Nullable CatalogEntry parseCatalogEntry(JsonNode catalogEntry) {
        // listed defaults to true when absent. Unlisted versions are deliberately hidden by
        // the publisher (e.g. due to critical bugs) and must not be surfaced as latest.
        if (catalogEntry.has("listed") && !catalogEntry.path("listed").asBoolean(true)) {
            return null;
        }

        final String version = catalogEntry.path("version").asText(null);
        if (version == null || version.isBlank()) {
            return null;
        }

        return new CatalogEntry(version, parsePublished(catalogEntry.path("published").asText(null)));
    }

    private byte @Nullable [] fetch(String url, PackageRepository repository) throws InterruptedException {
        final URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Skipping malformed NuGet URL '{}'", url, e);
            return null;
        }

        // Service index and registration responses contain @id values that the resolver
        // follows. Reject anything that is not http(s), so a hostile registry cannot point
        // us at file://, jar://, or other local schemes.
        final String scheme = uri.getScheme();
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
            LOGGER.warn("Skipping NuGet URL with unsupported scheme: {}", url);
            return null;
        }

        final HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(uri)
                .timeout(REQUEST_TIMEOUT)
                .GET();
        applyAuth(builder, repository, uri);
        return cachingHttpClient.get(builder, repository);
    }

    private static void applyAuth(HttpRequest.Builder builder, PackageRepository repository, URI requestUri) {
        if (repository.password() == null) {
            return;
        }

        // Only attach credentials to requests that target the same origin as the configured
        // repository URL. Registration responses can include absolute @id links pointing at
        // arbitrary hosts. Sending the credential there would leak it.
        if (!UrlUtils.hasSameOrigin(requestUri.toString(), repository.url())) {
            return;
        }

        if (repository.username() != null) {
            final String credentials = repository.username() + ":" + repository.password();
            builder.header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                    credentials.getBytes(StandardCharsets.UTF_8)));
        } else {
            builder.header("Authorization", "Bearer " + repository.password());
        }
    }

    private JsonNode parseJson(byte[] body) {
        try {
            return objectMapper.readTree(body);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static @Nullable Instant parsePublished(@Nullable String published) {
        if (published == null || published.isBlank()) {
            return null;
        }

        try {
            return OffsetDateTime.parse(published).toInstant();
        } catch (DateTimeParseException ignored) {
            // try next format
        }

        try {
            return LocalDateTime.parse(published).toInstant(ZoneOffset.UTC);
        } catch (DateTimeParseException ignored) {
            return null;
        }
    }

    private record Page(JsonNode node, String upperRaw, @Nullable Version upperVersion) {
    }

    private record CatalogEntry(String version, @Nullable Instant publishedAt) {
    }

}
