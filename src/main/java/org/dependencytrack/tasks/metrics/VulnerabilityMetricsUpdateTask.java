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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks.metrics;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.dependencytrack.event.VulnerabilityMetricsUpdateEvent;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityMetrics;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * A {@link Subscriber} task that updates vulnerability metrics.
 *
 * @since 4.6.0
 */
public class VulnerabilityMetricsUpdateTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(VulnerabilityMetricsUpdateTask.class);

    @Override
    public void inform(final Event e) {
        if (e instanceof VulnerabilityMetricsUpdateEvent) {
            try {
                updateMetrics();
            } catch (Exception ex) {
                LOGGER.error("An unexpected error occurred while updating vulnerability metrics", ex);
            }
        }
    }

    private void updateMetrics() throws Exception {
        LOGGER.info("Executing metrics update on vulnerability database");

        final var measuredAt = new Date();
        final var yearMonthCounters = new VulnerabilityDateCounters(measuredAt, true);
        final var yearCounters = new VulnerabilityDateCounters(measuredAt, false);

        try (final var qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();

            LOGGER.debug("Fetching first vulnerabilities page");
            List<Vulnerability> vulnerabilities = fetchNextVulnerabilitiesPage(pm, null);

            while (!vulnerabilities.isEmpty()) {
                for (final Vulnerability vulnerability : vulnerabilities) {
                    if (vulnerability.getCreated() != null) {
                        yearMonthCounters.updateMetrics(vulnerability.getCreated());
                        yearCounters.updateMetrics(vulnerability.getCreated());
                    } else if (vulnerability.getPublished() != null) {
                        yearMonthCounters.updateMetrics(vulnerability.getPublished());
                        yearCounters.updateMetrics(vulnerability.getPublished());
                    }
                }

                LOGGER.debug("Fetching next vulnerabilities page");
                final long lastId = vulnerabilities.get(vulnerabilities.size() - 1).getId();
                vulnerabilities = fetchNextVulnerabilitiesPage(pm, lastId);
            }

            for (final VulnerabilityMetrics metric : yearMonthCounters.getMetrics()) {
                qm.synchronizeVulnerabilityMetrics(metric);
            }
            for (final VulnerabilityMetrics metric : yearCounters.getMetrics()) {
                qm.synchronizeVulnerabilityMetrics(metric);
            }
        }

        LOGGER.info("Completed metrics update on vulnerability database in " +
                DurationFormatUtils.formatDuration(new Date().getTime() - measuredAt.getTime(), "mm:ss:SS"));
    }

    /**
     * Fetch {@link Vulnerability}s in pages of {@code 500}.
     *
     * @param pm     The {@link  PersistenceManager} to use
     * @param lastId Highest ID of the previously fetched page
     * @return Up to {@code 500} {@link Vulnerability} objects
     * @throws Exception If the query could not be closed
     */
    private List<Vulnerability> fetchNextVulnerabilitiesPage(final PersistenceManager pm, final Long lastId) throws Exception {
        try (final Query<Vulnerability> query = pm.newQuery(Vulnerability.class)) {
            if (lastId != null) {
                query.setFilter("id < :lastId");
                query.setParameters(lastId);
            }
            query.setOrdering("id DESC");
            query.range(0, 500);
            query.getFetchPlan().setGroup(Vulnerability.FetchGroup.METRICS_UPDATE.name());
            return List.copyOf(query.executeList());
        }
    }

    private static final class VulnerabilityDateCounters {
        private final Date measuredAt;
        private final boolean trackMonth;
        private final List<VulnerabilityMetrics> metrics = new ArrayList<>();

        private VulnerabilityDateCounters(final Date measuredAt, final boolean trackMonth) {
            this.measuredAt = measuredAt;
            this.trackMonth = trackMonth;
        }

        private void updateMetrics(final Date timestamp) {
            final LocalDateTime date = LocalDateTime.ofInstant(timestamp.toInstant(), ZoneId.systemDefault());
            final int year = date.getYear();
            final int month = date.getMonthValue();

            boolean found = false;
            for (final VulnerabilityMetrics metric : metrics) {
                if (trackMonth && metric.getYear() == year && metric.getMonth() == month) {
                    metric.setCount(metric.getCount() + 1);
                    found = true;
                } else if (!trackMonth && metric.getYear() == year) {
                    metric.setCount(metric.getCount() + 1);
                    found = true;
                }
            }
            if (!found) {
                final VulnerabilityMetrics metric = new VulnerabilityMetrics();
                metric.setYear(year);
                if (trackMonth) {
                    metric.setMonth(month);
                }
                metric.setCount(1);
                metric.setMeasuredAt(measuredAt);
                metrics.add(metric);
            }
        }

        private List<VulnerabilityMetrics> getMetrics() {
            return metrics;
        }
    }

}
