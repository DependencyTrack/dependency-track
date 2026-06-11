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
package org.dependencytrack.vulndatasource.osv;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.util.Timestamps;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Property;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.osv.OsvAdvisorySource.IncrementalOsvAdvisorySource;
import org.dependencytrack.vulndatasource.osv.OsvAdvisorySource.ZipOsvAdvisorySource;
import org.dependencytrack.vulndatasource.osv.schema.Osv;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.vulndatasource.osv.CycloneDxPropertyNames.OSV_ECOSYSTEM;
import static org.dependencytrack.vulndatasource.osv.OsvEcosystems.encodeEcosystem;

/**
 * @since 5.0.0
 */
final class OsvVulnDataSource implements VulnDataSource {

    private static final Logger LOGGER = LoggerFactory.getLogger(OsvVulnDataSource.class);
    private static final int MAX_INCREMENTAL_ADVISORY_DOWNLOADS = 250;

    private final WatermarkManager watermarkManager;
    private final ObjectMapper objectMapper;
    private final String dataUrl;
    private final List<String> ecosystems;
    private final Set<String> successfullyCompletedEcosystems;
    private final HttpClient httpClient;
    private final ModelConverter modelConverter;
    private String currentEcosystem;
    private int currentEcosystemIndex;
    private int currentEcosystemAdvisoriesProcessed;
    private @Nullable OsvAdvisorySource currentAdvisorySource;
    private boolean hasNextCalled;
    private Bom nextItem;
    private final boolean isAliasSyncEnabled;

    OsvVulnDataSource(
            final WatermarkManager watermarkManager,
            final ObjectMapper objectMapper,
            final String dataUrl,
            final Collection<String> ecosystems,
            final HttpClient httpClient,
            final boolean isAliasSyncEnabled) {
        this.watermarkManager = watermarkManager;
        this.objectMapper = objectMapper;
        this.dataUrl = dataUrl;
        this.ecosystems = List.copyOf(ecosystems);
        this.isAliasSyncEnabled = isAliasSyncEnabled;
        this.successfullyCompletedEcosystems = new HashSet<>();
        this.httpClient = httpClient;
        this.modelConverter = new ModelConverter(objectMapper);
    }

    @Override
    public boolean hasNext() {
        if (hasNextCalled && nextItem != null) {
            return true;
        }

        hasNextCalled = true;

        if (currentEcosystem != null) {
            final Bom item = readNextItem();
            if (item != null) {
                nextItem = item;
                return true;
            }

            successfullyCompletedEcosystems.add(currentEcosystem);
            if (watermarkManager != null) {
                watermarkManager.maybeCommit(List.of(currentEcosystem));
            }
            logCurrentEcosystemSummary();
            closeCurrentEcosystem();
            currentEcosystemIndex++;
        }

        if (currentEcosystemIndex < ecosystems.size()) {
            final boolean nextEcosystemOpened = openNextEcosystem();
            if (nextEcosystemOpened) {
                final Bom item = readNextItem();
                if (item != null) {
                    nextItem = item;
                    return true;
                }
                successfullyCompletedEcosystems.add(currentEcosystem);
                if (watermarkManager != null) {
                    watermarkManager.maybeCommit(List.of(currentEcosystem));
                }
                logCurrentEcosystemSummary();
                closeCurrentEcosystem();
            }
            currentEcosystemIndex++;
        }

        nextItem = null;
        return false;
    }

    @Override
    public Bom next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }

        final Bom item = nextItem;
        nextItem = null;
        hasNextCalled = false;
        return item;
    }

    @Override
    public void markProcessed(Bom bov) {
        requireNonNull(bov, "bov must not be null");

        if (bov.getVulnerabilitiesCount() != 1) {
            throw new IllegalArgumentException(
                    "BOV must have exactly one vulnerability, but has "
                            + bov.getVulnerabilitiesCount());
        }

        final Vulnerability vuln = bov.getVulnerabilities(0);

        final String ecosystem = extractEcosystem(vuln);
        if (ecosystem == null) {
            throw new IllegalArgumentException();
        }

        final Instant updatedAt = vuln.hasUpdated()
                ? Instant.ofEpochMilli(Timestamps.toMillis(vuln.getUpdated()))
                : null;
        if (updatedAt == null) {
            LOGGER.warn("Vulnerability {} has no updated timestamp; Cannot advance watermark", vuln.getId());
            return;
        }

        if (watermarkManager != null) {
            watermarkManager.maybeAdvance(ecosystem, updatedAt);
        }
    }

    @Override
    public void close() {
        if (watermarkManager != null) {
            watermarkManager.maybeCommit(successfullyCompletedEcosystems);
        }
        closeCurrentEcosystem();
    }

    private Bom readNextItem() {
        if (currentAdvisorySource == null || !currentAdvisorySource.hasNext()) {
            return null;
        }

        final Osv osv = currentAdvisorySource.next();
        currentEcosystemAdvisoriesProcessed++;
        return modelConverter.convert(osv, isAliasSyncEnabled, currentEcosystem);
    }

    private void logCurrentEcosystemSummary() {
        if (currentEcosystem == null) {
            return;
        }

        LOGGER.info(
                "Finished ecosystem {}: processed {} advisories",
                currentEcosystem,
                currentEcosystemAdvisoriesProcessed);
    }

    private boolean openNextEcosystem() {
        if (currentEcosystemIndex >= ecosystems.size()) {
            return false;
        }

        currentEcosystem = ecosystems.get(currentEcosystemIndex);
        currentEcosystemAdvisoriesProcessed = 0;
        currentAdvisorySource = openAdvisorySource(currentEcosystem);

        LOGGER.info("Processing ecosystem {}", currentEcosystem);
        return true;
    }

    private @Nullable OsvAdvisorySource openAdvisorySource(String ecosystem) {
        if (watermarkManager == null) {
            LOGGER.debug("Incremental mirroring disabled; downloading all advisories");
            return downloadFullArchive(ecosystem);
        }

        final Instant watermark = watermarkManager.getWatermark(ecosystem);
        if (watermark == null) {
            LOGGER.debug("No watermark found; Downloading all advisories");
            return downloadFullArchive(ecosystem);
        }

        LOGGER.debug("Downloading advisories changed since {}", watermark);
        final Set<String> modifiedIds = getModifiedIds(ecosystem, watermark);
        if (modifiedIds.isEmpty()) {
            LOGGER.info("No new or updated advisories since {}", watermark);
            return null;
        }

        if (modifiedIds.size() > MAX_INCREMENTAL_ADVISORY_DOWNLOADS) {
            LOGGER.info("""
                            Number of new or updated advisories for ecosystem {} exceeds the incremental \
                            download threshold of {}; downloading the full advisory archive instead""",
                    ecosystem, MAX_INCREMENTAL_ADVISORY_DOWNLOADS);
            return downloadFullArchive(ecosystem);
        }

        LOGGER.info("Incrementally mirroring {} new or updated advisories for ecosystem {}",
                modifiedIds.size(), ecosystem);
        return new IncrementalOsvAdvisorySource(httpClient, objectMapper, dataUrl, ecosystem, modifiedIds);
    }

    private ZipOsvAdvisorySource downloadFullArchive(String ecosystem) {
        LOGGER.info("Downloading all advisories for ecosystem {} from upstream", ecosystem);

        final Path tempZipPath;
        try {
            tempZipPath = Files.createTempFile(null, ".zip");
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to create temp file", e);
        }

        final var request = HttpRequest.newBuilder()
                .uri(URI.create("%s/%s/all.zip".formatted(dataUrl, encodeEcosystem(ecosystem))))
                .GET()
                .build();

        try {
            final HttpResponse<Path> response;
            try {
                response = httpClient.send(request, BodyHandlers.ofFile(tempZipPath));
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to download advisory archive", e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while downloading advisory archive", e);
            }
            if (response.statusCode() != 200) {
                throw new IllegalStateException("Unexpected response code: " + response.statusCode());
            }

            try {
                return new ZipOsvAdvisorySource(tempZipPath, objectMapper);
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to open advisory archive " + tempZipPath, e);
            }
        } catch (RuntimeException e) {
            try {
                Files.deleteIfExists(tempZipPath);
            } catch (IOException suppressed) {
                e.addSuppressed(suppressed);
            }
            throw e;
        }
    }

    private void closeCurrentEcosystem() {
        if (currentAdvisorySource != null) {
            try {
                currentAdvisorySource.close();
            } catch (IOException e) {
                LOGGER.warn("Failed to close advisory source for ecosystem {}", currentEcosystem, e);
            }
            currentAdvisorySource = null;
        }

        currentEcosystem = null;
    }

    private Set<String> getModifiedIds(String ecosystem, Instant watermark) {
        final var request = HttpRequest.newBuilder()
                .uri(URI.create("%s/%s/modified_id.csv".formatted(dataUrl, encodeEcosystem(ecosystem))))
                .GET()
                .build();

        final HttpResponse<InputStream> response;
        try {
            response = httpClient.send(request, BodyHandlers.buffering(
                    BodyHandlers.ofInputStream(), 1024));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to download modified IDs", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while downloading modified IDs", e);
        }
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Unexpected response code: " + response.statusCode());
        }

        final var modifiedIds = new HashSet<String>();
        try (final InputStream inputStream = response.body();
             final var inputStreamReader = new InputStreamReader(inputStream);
             final var bufferedReader = new BufferedReader(inputStreamReader)) {
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                final String[] parts = line.split(",", 2);
                if (parts.length != 2) {
                    throw new IllegalStateException();
                }

                final Instant timestamp = Instant.parse(parts[0]);
                if (timestamp.isAfter(watermark)) {
                    modifiedIds.add(parts[1]);
                    if (modifiedIds.size() > MAX_INCREMENTAL_ADVISORY_DOWNLOADS) {
                        // NB: We already know there are too many modified IDs,
                        // no point in scanning further.
                        break;
                    }
                } else {
                    break;
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        return modifiedIds;
    }

    private static String extractEcosystem(Vulnerability vuln) {
        for (final Property property : vuln.getPropertiesList()) {
            if (OSV_ECOSYSTEM.equals(property.getName())) {
                return property.getValue();
            }
        }

        return null;
    }

    WatermarkManager getWatermarkManager() {
        return watermarkManager;
    }

}