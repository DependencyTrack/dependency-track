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
package org.dependencytrack.kevdatasource.vulncheck;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MappingIterator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.dependencytrack.kevdatasource.api.KevAssertion;
import org.dependencytrack.kevdatasource.api.KevDataSource;
import org.dependencytrack.kevdatasource.vulncheck.VulnCheckBackupResponse.Backup;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Spliterator;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static java.util.Objects.requireNonNull;
import static java.util.Spliterators.spliteratorUnknownSize;
import static java.util.function.Predicate.not;

/// @see [VulnCheck KEV](https://docs.vulncheck.com/community/vulncheck-kev/introduction)
/// @since 5.1.0
final class VulnCheckKevDataSource implements KevDataSource {

    private static final Logger LOGGER = LoggerFactory.getLogger(VulnCheckKevDataSource.class);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final URI apiUrl;
    private final String apiToken;

    private @Nullable Path archivePath;
    private @Nullable ZipFile archive;
    private @Nullable Iterator<KevAssertion> delegate;

    VulnCheckKevDataSource(
            HttpClient httpClient,
            ObjectMapper objectMapper,
            URI apiUrl,
            String apiToken) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.apiUrl = apiUrl;
        this.apiToken = apiToken;
    }

    @Override
    public boolean hasNext() {
        return iterator().hasNext();
    }

    @Override
    public KevAssertion next() {
        return iterator().next();
    }

    @Override
    public void close() {
        try {
            if (archive != null) {
                archive.close();
            }
        } catch (IOException e) {
            LOGGER.warn("Failed to close KEV archive", e);
        } finally {
            if (archivePath != null) {
                try {
                    Files.deleteIfExists(archivePath);
                } catch (IOException e) {
                    LOGGER.warn("Failed to delete KEV archive {}", archivePath, e);
                }
            }
        }
    }

    private Iterator<KevAssertion> iterator() {
        if (delegate == null) {
            final Path downloadedPath = downloadVerifiedArchive(resolveBackup());

            final ZipFile openedArchive;
            try {
                openedArchive = new ZipFile(downloadedPath.toFile());
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to open KEV archive", e);
            }

            archive = openedArchive;

            delegate = openedArchive.stream()
                    .filter(not(ZipEntry::isDirectory))
                    .filter(entry -> entry.getName().endsWith(".json"))
                    .flatMap(this::assertionsIn)
                    .iterator();
        }

        return delegate;
    }

    private Backup resolveBackup() {
        final URI requestUri = URI.create(
                apiUrl.toString().replaceAll("/+$", "") + "/v3/backup/vulncheck-kev");
        LOGGER.debug("Resolving KEV backup via {}", requestUri);

        final HttpResponse<InputStream> response;
        try {
            response = httpClient.send(
                    HttpRequest.newBuilder(requestUri)
                            .header("Authorization", "Bearer " + apiToken)
                            .header("Accept", "application/json")
                            .timeout(Duration.ofSeconds(10))
                            .GET()
                            .build(),
                    BodyHandlers.ofInputStream());
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to request KEV backup", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while requesting KEV backup", e);
        }

        final VulnCheckBackupResponse backupResponse;
        try (final InputStream body = response.body()) {
            if (response.statusCode() != 200) {
                body.transferTo(OutputStream.nullOutputStream());
                throw new IllegalStateException(
                        "Requesting KEV backup failed with unexpected response code: "
                                + response.statusCode());
            }

            backupResponse = objectMapper.readValue(body, VulnCheckBackupResponse.class);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to parse KEV backup response", e);
        }

        final List<Backup> backups = backupResponse.data();
        if (backups == null || backups.isEmpty()) {
            throw new IllegalStateException("VulnCheck reported no backup for index vulncheck-kev");
        }

        return backups.getFirst();
    }

    private Path downloadVerifiedArchive(Backup backup) {
        final URI downloadUrl = backup.url();
        if (downloadUrl == null) {
            throw new IllegalStateException("VulnCheck backup does not have a download URL");
        }
        if (!isAcceptableDownloadUrl(downloadUrl)) {
            throw new IllegalStateException(
                    "Refusing to download KEV backup from an insecure URL");
        }

        final String sha256 = backup.sha256();
        if (sha256 == null || sha256.isBlank()) {
            throw new IllegalStateException("VulnCheck backup does not have a checksum");
        }

        final Path downloadedPath;
        try {
            downloadedPath = Files.createTempFile(null, ".zip");
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to create temporary file", e);
        }

        archivePath = downloadedPath;

        final String actualSha256 = download(downloadUrl, downloadedPath);
        if (!actualSha256.equalsIgnoreCase(sha256)) {
            throw new IllegalStateException(
                    "KEV archive checksum mismatch: expected %s but got %s".formatted(
                            sha256, actualSha256));
        }

        return downloadedPath;
    }

    private boolean isAcceptableDownloadUrl(URI downloadUrl) {
        final String scheme = downloadUrl.getScheme();
        if ("https".equalsIgnoreCase(scheme)) {
            return true;
        }

        return "http".equalsIgnoreCase(scheme)
                && !"https".equalsIgnoreCase(apiUrl.getScheme());
    }

    private String download(URI downloadUrl, Path targetPath) {
        LOGGER.debug("Downloading KEV archive");

        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }

        // NB: The download URL is pre-signed.
        final HttpResponse<InputStream> response;
        try {
            response = httpClient.send(
                    HttpRequest.newBuilder(downloadUrl)
                            .timeout(Duration.ofMinutes(5))
                            .GET()
                            .build(),
                    BodyHandlers.ofInputStream());
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to download KEV archive", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while downloading KEV archive", e);
        }

        try (final InputStream body = new DigestInputStream(response.body(), digest)) {
            if (response.statusCode() != 200) {
                body.transferTo(OutputStream.nullOutputStream());
                throw new IllegalStateException(
                        "Downloading KEV archive failed with unexpected response code: "
                                + response.statusCode());
            }

            Files.copy(body, targetPath, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to download KEV archive", e);
        }

        return HexFormat.of().formatHex(digest.digest());
    }

    private Stream<KevAssertion> assertionsIn(ZipEntry entry) {
        final MappingIterator<ObjectNode> entryNodesIter;
        try {
            entryNodesIter = objectMapper
                    .readerFor(ObjectNode.class)
                    .readValues(requireNonNull(archive, "archive must not be null").getInputStream(entry));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read archive member " + entry.getName(), e);
        }

        return StreamSupport.stream(
                        spliteratorUnknownSize(entryNodesIter, Spliterator.ORDERED | Spliterator.NONNULL),
                        /* parallel */ false)
                .flatMap(this::toKevAssertions)
                .onClose(() -> {
                    try {
                        entryNodesIter.close();
                    } catch (IOException e) {
                        throw new UncheckedIOException(
                                "Failed to close archive member " + entry.getName(), e);
                    }
                });
    }

    private Stream<KevAssertion> toKevAssertions(JsonNode entryNode) {
        final VulnCheckKevEntry entry;
        try {
            entry = objectMapper.treeToValue(entryNode, VulnCheckKevEntry.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to parse KEV entry", e);
        }

        final List<String> cveIds = entry.cve();
        if (cveIds == null || cveIds.isEmpty()) {
            // TODO: VulnCheck reports non-CVE identifiers in dedicated fields.
            //  Entries without CVE are skipped until those are supported.
            return Stream.empty();
        }

        final Boolean knownRansomware =
                "known".equalsIgnoreCase(entry.knownRansomwareCampaignUse())
                        ? true
                        : null;

        return cveIds.stream()
                .filter(not(String::isBlank))
                .map(cveId -> new KevAssertion(
                        "NVD",
                        cveId,
                        entry.dateAdded(),
                        entry.requiredAction(),
                        knownRansomware,
                        entry.shortDescription(),
                        entryNode));
    }

}
