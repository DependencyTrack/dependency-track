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

import com.fasterxml.jackson.databind.MappingIterator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.PackageURL;
import io.github.nscuro.versatile.VersionFactory;
import io.github.nscuro.versatile.spi.InvalidVersionException;
import io.github.nscuro.versatile.spi.Version;
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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;

import static io.github.nscuro.versatile.version.KnownVersioningSchemes.SCHEME_CARGO;
import static java.util.Comparator.comparing;
import static java.util.Objects.requireNonNull;

final class CargoPackageMetadataResolver implements PackageMetadataResolver {

    private static final Logger LOGGER = LoggerFactory.getLogger(CargoPackageMetadataResolver.class);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private record Candidate(CargoIndexEntry entry, Version version) {}

    private final ObjectMapper objectMapper;
    private final CachingHttpClient cachingHttpClient;

    CargoPackageMetadataResolver(ObjectMapper objectMapper, CachingHttpClient cachingHttpClient) {
        this.objectMapper = objectMapper;
        this.cachingHttpClient = cachingHttpClient;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl, @Nullable PackageRepository repository, @Nullable PackageArtifactMetadata prior)
            throws InterruptedException {
        requireNonNull(repository, "repository must not be null");

        final String url = UrlUtils.join(repository.url(), indexPathSegments(purl.getName()));

        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .GET();
        maybeApplyAuth(requestBuilder, repository);

        final byte[] body = cachingHttpClient.get(requestBuilder, repository);
        if (body == null) {
            return null;
        }

        final var candidates = new ArrayList<Candidate>();
        CargoIndexEntry requested = null;

        try (final MappingIterator<CargoIndexEntry> indexEntryIterator =
                objectMapper.readerFor(CargoIndexEntry.class).readValues(body)) {
            while (indexEntryIterator.hasNext()) {
                final CargoIndexEntry indexEntry = indexEntryIterator.next();
                if (indexEntry.vers() == null) {
                    continue;
                }
                if (purl.getVersion().equals(indexEntry.vers())) {
                    requested = indexEntry;
                }
                if (indexEntry.yanked()) {
                    continue;
                }

                final Version version;
                try {
                    version = VersionFactory.forScheme(SCHEME_CARGO, indexEntry.vers());
                } catch (InvalidVersionException e) {
                    LOGGER.debug("Skipping index entry with unparseable version {}", indexEntry.vers(), e);
                    continue;
                }

                candidates.add(new Candidate(indexEntry, version));
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        final Candidate latest = candidates.stream()
                .filter(candidate -> candidate.version().isStable())
                .max(comparing(Candidate::version))
                .or(() -> candidates.stream().max(comparing(Candidate::version)))
                .orElse(null);
        if (latest == null) {
            return null;
        }

        final var resolvedAt = Instant.now();
        return new PackageMetadata(
                latest.entry().vers(),
                tryParseInstant(latest.entry().pubtime()),
                resolvedAt,
                buildArtifactMetadata(resolvedAt, requested));
    }

    /// @see <a href="https://doc.rust-lang.org/cargo/reference/registry-index.html#index-files">Cargo index files</a>
    private static String[] indexPathSegments(String crateName) {
        final String name = crateName.toLowerCase(Locale.ROOT);
        return switch (name.length()) {
            case 1 -> new String[] {"1", name};
            case 2 -> new String[] {"2", name};
            case 3 -> new String[] {"3", name.substring(0, 1), name};
            default -> new String[] {name.substring(0, 2), name.substring(2, 4), name};
        };
    }

    private static @Nullable PackageArtifactMetadata buildArtifactMetadata(
            Instant resolvedAt, @Nullable CargoIndexEntry entry) {
        if (entry == null) {
            return null;
        }

        final Instant publishedAt = tryParseInstant(entry.pubtime());

        Map<HashAlgorithm, String> hashes = Map.of();
        if (entry.cksum() != null && HashAlgorithm.SHA256.isValid(entry.cksum())) {
            hashes = Map.of(HashAlgorithm.SHA256, entry.cksum().toLowerCase());
        }

        if (publishedAt == null && hashes.isEmpty()) {
            return null;
        }

        return new PackageArtifactMetadata(resolvedAt, publishedAt, hashes);
    }

    private static @Nullable Instant tryParseInstant(@Nullable String value) {
        if (value == null) {
            return null;
        }

        try {
            return Instant.parse(value);
        } catch (DateTimeParseException _) {
            return null;
        }
    }

    private static void maybeApplyAuth(HttpRequest.Builder builder, PackageRepository repository) {
        if (repository.password() == null) {
            return;
        }

        final String authHeaderValue;
        if (repository.username() != null) {
            final String credentials = repository.username() + ":" + repository.password();
            authHeaderValue =
                    "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        } else {
            authHeaderValue = repository.password();
        }

        builder.header("Authorization", authHeaderValue);
    }
}
