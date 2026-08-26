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
package org.dependencytrack.vulndatasource.jvn;

import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.NoSuchElementException;

import static java.util.Objects.requireNonNull;

/**
 * A {@link VulnDataSource} for JVN (Japan Vulnerability Notes).
 * <p>
 * Mirrors the complete JVN history by downloading the yearly detail feeds
 * ({@code jvndb_detail_YYYY.rdf}) for {@code startYear..endYear} to a temporary file and streaming
 * one {@code <Vulinfo>} at a time via {@link JvnAdvisorySource}, converting each to a CycloneDX
 * BOV. Years whose feed digest ({@code sha256} from {@code checksum.txt}) is unchanged since the
 * previous run are skipped.
 *
 * @since 5.1.0
 */
final class JvnVulnDataSource implements VulnDataSource {

    private static final Logger LOGGER = LoggerFactory.getLogger(JvnVulnDataSource.class);

    private final JvnClient client;
    private final WatermarkManager watermarkManager;
    private final Deque<Integer> pendingYears = new ArrayDeque<>();

    private @Nullable Map<String, String> feedDigestByFilename;
    private boolean completedSuccessfully;
    private @Nullable Bom nextBom;

    private @Nullable JvnAdvisorySource currentSource;
    private @Nullable String currentFeedFilename;
    private @Nullable String currentFeedDigest;
    private int currentFeedAdvisoryCount;

    JvnVulnDataSource(
            final JvnClient client, final WatermarkManager watermarkManager, final int startYear, final int endYear) {
        this.client = client;
        this.watermarkManager = watermarkManager;
        for (int year = startYear; year <= endYear; year++) {
            pendingYears.add(year);
        }
    }

    @Override
    public boolean hasNext() {
        if (nextBom != null) {
            return true;
        }

        while (true) {
            final JvnAdvisorySource source = currentSource;
            if (source != null) {
                final JvnAdvisory advisory = readAdvisory(source);
                if (advisory != null) {
                    nextBom = ModelConverter.convert(advisory);
                    return true;
                }
                continue;
            }
            if (pendingYears.isEmpty()) {
                completedSuccessfully = true;
                return false;
            }
            openYear(pendingYears.poll());
        }
    }

    @Override
    public Bom next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        final Bom bom = requireNonNull(nextBom);
        nextBom = null;
        return bom;
    }

    @Override
    public void markProcessed(final Bom bov) {
        if (bov.getVulnerabilitiesCount() == 0) {
            return;
        }
        final Vulnerability vuln = bov.getVulnerabilities(0);
        if (vuln.hasPublished()) {
            watermarkManager.maybeAdvance(Instant.ofEpochSecond(
                    vuln.getPublished().getSeconds(), vuln.getPublished().getNanos()));
        }
    }

    @Override
    public void close() {
        // Persist the watermark and the digests of the years processed this run, but only on a full
        // pass — an interrupted run must re-fetch the years it did not finish.
        if (completedSuccessfully) {
            watermarkManager.maybeCommit();
        }
        closeCurrentFeed();
    }

    /**
     * Returns the next advisory of the current feed, or {@code null} after closing it — either
     * because it was fully drained (only then is its digest recorded, so a partially parsed year
     * is retried next run) or because parsing failed.
     */
    private @Nullable JvnAdvisory readAdvisory(final JvnAdvisorySource source) {
        try {
            if (source.hasNext()) {
                currentFeedAdvisoryCount++;
                return source.next();
            }
            if (currentFeedFilename != null && currentFeedDigest != null) {
                watermarkManager.recordFeedDigest(currentFeedFilename, currentFeedDigest);
            }
            LOGGER.info("Fetched {} JVN advisories from {}", currentFeedAdvisoryCount, currentFeedFilename);
        } catch (RuntimeException e) {
            LOGGER.warn("Failed to parse JVN feed {}; skipping", currentFeedFilename, e);
        }
        closeCurrentFeed();
        return null;
    }

    /** Downloads a single year's detail feed and opens it for streaming, unless its checksum is unchanged. */
    private void openYear(final int year) {
        final String filename = JvnClient.detailFeedFilename(year);
        final @Nullable String digest = feedDigest(filename);
        if (digest != null && digest.equals(watermarkManager.getCommittedFeedDigest(filename))) {
            LOGGER.debug("JVN feed {} unchanged since last run; skipping", filename);
            return;
        }
        try {
            final Path feedFile = client.downloadDetailFeed(year);
            currentSource = JvnAdvisorySource.open(feedFile);
            currentFeedFilename = filename;
            currentFeedDigest = digest;
            currentFeedAdvisoryCount = 0;
        } catch (IOException e) {
            LOGGER.warn("Failed to fetch JVN feed {}; skipping", filename, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Closes the current feed's source, which also deletes its temporary file. */
    private void closeCurrentFeed() {
        final JvnAdvisorySource source = currentSource;
        currentSource = null;
        currentFeedFilename = null;
        currentFeedDigest = null;
        currentFeedAdvisoryCount = 0;
        if (source != null) {
            try {
                source.close();
            } catch (IOException e) {
                LOGGER.warn("Failed to close JVN feed source", e);
            }
        }
    }

    /** The {@code checksum.txt} digest for {@code filename}, fetching the manifest lazily once per run. */
    private @Nullable String feedDigest(final String filename) {
        if (feedDigestByFilename == null) {
            try {
                feedDigestByFilename = client.fetchChecksums();
            } catch (IOException e) {
                LOGGER.warn("Failed to fetch JVN checksum.txt; feeds will not be skipped this run", e);
                feedDigestByFilename = Map.of();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                feedDigestByFilename = Map.of();
            }
        }
        return feedDigestByFilename.get(filename);
    }
}
