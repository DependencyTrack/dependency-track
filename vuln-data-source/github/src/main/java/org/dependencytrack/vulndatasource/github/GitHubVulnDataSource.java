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
package org.dependencytrack.vulndatasource.github;

import com.google.protobuf.util.Timestamps;
import io.github.jeremylong.openvulnerability.client.ghsa.GitHubSecurityAdvisoryClient;
import io.github.jeremylong.openvulnerability.client.ghsa.SecurityAdvisory;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Vulnerability;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Collection;
import java.util.LinkedList;
import java.util.NoSuchElementException;
import java.util.Queue;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
final class GitHubVulnDataSource implements VulnDataSource {

    private static final Logger LOGGER = LoggerFactory.getLogger(GitHubVulnDataSource.class);

    private final WatermarkManager watermarkManager;
    private final GitHubSecurityAdvisoryClient client;
    private final boolean isAliasSyncEnabled;
    private final Queue<SecurityAdvisory> advisoryQueue;
    private boolean hasNextCalled = false;
    private boolean startLogged = false;
    private int pagesFetched = 0;
    private int advisoriesFetched = 0;

    GitHubVulnDataSource(
            final WatermarkManager watermarkManager,
            final GitHubSecurityAdvisoryClient client,
            final boolean isAliasSyncEnabled) {
        this.watermarkManager = requireNonNull(watermarkManager, "watermarkManager must not be null");
        this.client = requireNonNull(client, "client must not be null");
        this.isAliasSyncEnabled = isAliasSyncEnabled;
        this.advisoryQueue = new LinkedList<>();
    }

    @Override
    public boolean hasNext() {
        if (hasNextCalled && !advisoryQueue.isEmpty()) {
            return true;
        }

        hasNextCalled = true;

        if (!advisoryQueue.isEmpty()) {
            return true;
        }
        if (!startLogged) {
            LOGGER.info(
                    "Downloading and processing GitHub advisories updated since {} (interleaved by page)",
                    watermarkManager.getWatermark());
            startLogged = true;
        }
        if (!client.hasNext()) {
            return false;
        }

        final Collection<SecurityAdvisory> advisories = client.next();
        pagesFetched++;
        advisoriesFetched += advisories.size();
        LOGGER.debug("Fetched page {} ({} advisories)", pagesFetched, advisories.size());

        advisoryQueue.addAll(advisories);
        return !advisoryQueue.isEmpty();
    }

    @Override
    public Bom next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }

        final SecurityAdvisory advisory = advisoryQueue.poll();
        if (advisory == null) {
            throw new IllegalStateException("No advisories queued");
        }

        hasNextCalled = false;
        return ModelConverter.convert(advisory, isAliasSyncEnabled);
    }

    @Override
    public void markProcessed(final Bom bov) {
        requireNonNull(bov, "bov must not be null");
        if (bov.getVulnerabilitiesCount() != 1) {
            throw new IllegalArgumentException(
                    "BOV must have exactly one vulnerability, but has "
                            + bov.getVulnerabilitiesCount());
        }

        final Vulnerability vuln = bov.getVulnerabilities(0);

        final Instant updatedAt = vuln.hasUpdated()
                ? Instant.ofEpochMilli(Timestamps.toMillis(vuln.getUpdated()))
                : null;
        watermarkManager.maybeAdvance(updatedAt);

        // Advisories are retrieved in ascending modification date order,
        // so it's safe to commit watermarks more frequently.
        watermarkManager.maybeCommit(/* ignoreMinCommitInterval */ false);
    }

    @Override
    public void close() {
        watermarkManager.maybeCommit(/* ignoreMinCommitInterval */ true);

        LOGGER.info("Fetched {} advisories across {} page(s)", advisoriesFetched, pagesFetched);

        try {
            client.close();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to close client", e);
        }
    }

}
