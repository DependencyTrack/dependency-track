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
package org.dependencytrack.tasks;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import alpine.resources.OrderDirection;
import alpine.resources.Pagination;
import org.dependencytrack.event.MetricsUpdateEvent;
import org.dependencytrack.metrics.Metrics;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentMetrics;
import org.dependencytrack.model.Dependency;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityMetrics;
import org.dependencytrack.persistence.QueryManager;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static java.lang.Math.toIntExact;

/**
 * Subscriber task that performs calculations of various Metrics.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class MetricsUpdateTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(MetricsUpdateTask.class);

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof MetricsUpdateEvent) {
            final MetricsUpdateEvent event = (MetricsUpdateEvent) e;

            LOGGER.debug("Starting metrics update task");
            try (QueryManager qm = new QueryManager()) {
                if (MetricsUpdateEvent.Type.PORTFOLIO == event.getType()) {
                    updatePortfolioMetrics(qm);
                } else if (event.getTarget() instanceof Project) {
                    updateProjectMetrics(qm, ((Project) event.getTarget()).getId());
                } else if (event.getTarget() instanceof Component) {
                    updateComponentMetrics(qm, ((Component) event.getTarget()).getId());
                } else if (event.getTarget() instanceof Dependency) {
                    updateDependencyMetrics(qm, ((Dependency) event.getTarget()).getId());
                } else if (MetricsUpdateEvent.Type.VULNERABILITY == event.getType()) {
                    updateVulnerabilitiesMetrics(qm);
                }
            } catch (Exception ex) {
                LOGGER.error(ex.getMessage());
            }
            LOGGER.debug("Metrics update complete");
        }
    }

   


    /**
     * Performs metric updates on the entire vulnerability database.
     * @param qm a QueryManager instance
     */
    private void updateVulnerabilitiesMetrics(final QueryManager qm) {
        LOGGER.info("Executing metrics update on vulnerability database");
        final Date measuredAt = new Date();
        final VulnerabilityMetricCounters yearMonthCounters = new VulnerabilityMetricCounters(measuredAt, true);
        final VulnerabilityMetricCounters yearCounters = new VulnerabilityMetricCounters(measuredAt, false);
        LOGGER.debug("Retrieving all vulnerabilities and paginating through results");
        final PaginatedResult vulnsResult = qm.getVulnerabilities();
        for (final Vulnerability vulnerability: vulnsResult.getList(Vulnerability.class)) {
            LOGGER.debug("Processing vulnerability: " + vulnerability.getUuid());
            if (vulnerability.getCreated() != null) {
                LOGGER.debug("The 'created' field contained a date. Updating year and year/month counters for vulnerability: " + vulnerability.getUuid());
                yearMonthCounters.updateMetics(vulnerability.getCreated());
                yearCounters.updateMetics(vulnerability.getCreated());
            } else if (vulnerability.getPublished() != null) {
                LOGGER.debug("The 'published' field contained a date. Updating year and year/month counters for vulnerability: " + vulnerability.getUuid());
                yearMonthCounters.updateMetics(vulnerability.getPublished());
                yearCounters.updateMetics(vulnerability.getPublished());
            } else {
                LOGGER.debug("A created or published date did not exist for vulnerability: " + vulnerability.getUuid());
            }
        }
        for (final VulnerabilityMetrics metric: yearMonthCounters.getMetrics()) {
            LOGGER.debug("Synchronizing vulnerability (by year/month) metrics");
            qm.synchronizeVulnerabilityMetrics(metric);
        }
        for (final VulnerabilityMetrics metric: yearCounters.getMetrics()) {
            LOGGER.debug("Synchronizing vulnerability (by year) metrics");
            qm.synchronizeVulnerabilityMetrics(metric);
        }
        LOGGER.info("Completed metrics update on vulnerability database");
    }

    /**
     * A value object that holds various counters returned by the updating of metrics.
     */
    private class VulnerabilityMetricCounters {

        private final Date measuredAt;
        private final boolean trackMonth;
        private final List<VulnerabilityMetrics> metrics = new ArrayList<>();

        private VulnerabilityMetricCounters(final Date measuredAt, final boolean trackMonth) {
            this.measuredAt = measuredAt;
            this.trackMonth = trackMonth;
        }

        private void updateMetics(final Date timestamp) {
            final LocalDateTime date = LocalDateTime.ofInstant(timestamp.toInstant(), ZoneId.systemDefault());
            final int year = date.getYear();
            final int month = date.getMonthValue();

            boolean found = false;
            for (final VulnerabilityMetrics metric: metrics) {
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

    /**
     * A value object that holds various counters returned by the updating of metrics.
     */
    private class MetricCounters {

        private int critical, high, medium, low, unassigned;
        private int projects, vulnerableProjects, components, vulnerableComponents, dependencies,
                vulnerableDependencies, vulnerabilities, suppressions, findingsTotal, findingsAudited,
                findingsUnaudited;

        /**
         * Increments critical, high, medium, low counters based on the specified severity.
         * @param severity the severity to update counters on
         */
        private void updateSeverity(final Severity severity) {
            if (Severity.CRITICAL == severity) {
                critical++;
            } else if (Severity.HIGH == severity) {
                high++;
            } else if (Severity.MEDIUM == severity) {
                medium++;
            } else if (Severity.LOW == severity) {
                low++;
            } else if (Severity.INFO == severity) {
                low++;
            } else if (Severity.UNASSIGNED == severity) {
                unassigned++;
            }
        }

        /**
         * Returns the sum of the total number of critical, high, medium, low, and unassigned severity vulnerabilities.
         * @return the sum of the counters for critical, high, medium, low, and unassigned.
         */
        private int severitySum() {
            return critical + high + medium + low  + unassigned;
        }

        /**
         * Returns the calculated Inherited Risk Score.
         * See: {@link Metrics#inheritedRiskScore(int, int, int, int, int)}
         * @return the calculated score
         */
        private double getInheritedRiskScore() {
            return Metrics.inheritedRiskScore(critical, high, medium, low, unassigned);
        }
    }

}
