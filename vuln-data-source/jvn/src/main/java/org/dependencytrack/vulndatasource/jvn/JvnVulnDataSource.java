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
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * A {@link VulnDataSource} for JVN (Japan Vulnerability Notes).
 * <p>
 * Mirrors the complete JVN history by downloading the yearly detail feeds
 * ({@code jvndb_detail_YYYY.rdf}) for {@code startYear..endYear}, parsing every {@code <Vulinfo>}
 * via {@link JvnDetailParser} and converting it to a CycloneDX BOV. Years whose feed digest
 * ({@code sha256} from {@code checksum.txt}) is unchanged since the previous run are skipped.
 *
 * @since 5.1.0
 */
final class JvnVulnDataSource implements VulnDataSource {

    private static final Logger LOGGER = LoggerFactory.getLogger(JvnVulnDataSource.class);

    private final JvnClient client;
    private final WatermarkManager watermarkManager;
    private final Deque<Integer> pendingYears = new ArrayDeque<>();
    private final Deque<JvnAdvisory> advisoryBuffer = new ArrayDeque<>();

    private @Nullable Map<String, String> feedDigestByFilename;
    private boolean completedSuccessfully;
    private @Nullable Bom nextBom;

    JvnVulnDataSource(
            final JvnClient client,
            final WatermarkManager watermarkManager,
            final int startYear,
            final int endYear) {
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
            if (!advisoryBuffer.isEmpty()) {
                nextBom = ModelConverter.convert(advisoryBuffer.poll());
                return true;
            }
            if (pendingYears.isEmpty()) {
                completedSuccessfully = true;
                return false;
            }
            loadYear(pendingYears.poll());
        }
    }

    @Override
    public Bom next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        final Bom bom = nextBom;
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
    }

    /** Fetches, parses and buffers a single year's detail feed, unless its checksum is unchanged. */
    private void loadYear(final int year) {
        final String filename = JvnClient.detailFeedFilename(year);
        final @Nullable String digest = feedDigest(filename);
        if (digest != null && digest.equals(watermarkManager.getCommittedFeedDigest(filename))) {
            LOGGER.debug("JVN feed {} unchanged since last run; skipping", filename);
            return;
        }
        try {
            final List<JvnAdvisory> advisories = JvnDetailParser.parse(client.fetchDetailFeed(year));
            advisoryBuffer.addAll(advisories);
            // Record the digest only after a successful fetch+parse, so a failed year is retried.
            if (digest != null) {
                watermarkManager.recordFeedDigest(filename, digest);
            }
            LOGGER.info("Fetched {} JVN advisories from {}", advisories.size(), filename);
        } catch (IOException e) {
            LOGGER.warn("Failed to fetch JVN feed {}; skipping", filename, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (RuntimeException e) {
            LOGGER.warn("Failed to parse JVN feed {}; skipping", filename, e);
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
