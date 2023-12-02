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
package org.dependencytrack.tasks.metrics;

import alpine.common.logging.Logger;
import alpine.common.util.SystemUtil;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.dependencytrack.event.CallbackEvent;
import org.dependencytrack.event.PortfolioMetricsUpdateEvent;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.metrics.Metrics;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * A {@link Subscriber} task that updates portfolio metrics.
 *
 * @since 4.6.0
 */
public class PortfolioMetricsUpdateTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(PortfolioMetricsUpdateTask.class);
    private static final long BATCH_SIZE = SystemUtil.getCpuCores();

    @Override
    public void inform(final Event e) {
        if (e instanceof PortfolioMetricsUpdateEvent) {
            try {
                updateMetrics();
            } catch (Exception ex) {
                LOGGER.error("An unexpected error occurred while updating portfolio metrics", ex);
            }
        }
    }

    private void updateMetrics() throws Exception {
        LOGGER.info("Executing portfolio metrics update");
        final var counters = new Counters();

        try (final var qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();

            LOGGER.debug("Fetching first " + BATCH_SIZE + " projects");
            List<Project> activeProjects = fetchNextActiveProjectsPage(pm, null);

            while (!activeProjects.isEmpty()) {
                final long firstId = activeProjects.get(0).getId();
                final long lastId = activeProjects.get(activeProjects.size() - 1).getId();
                final int batchCount = activeProjects.size();

                final var countDownLatch = new CountDownLatch(batchCount);

                for (final Project project : activeProjects) {
                    LOGGER.debug("Dispatching metrics update event for project " + project.getUuid());
                    final var callbackEvent = new CallbackEvent(countDownLatch::countDown);
                    Event.dispatch(new ProjectMetricsUpdateEvent(project.getUuid())
                            .onSuccess(callbackEvent)
                            .onFailure(callbackEvent));
                }

                LOGGER.debug("Waiting for metrics updates for projects " + firstId + "-" + lastId + " to complete");
                if (!countDownLatch.await(15, TimeUnit.MINUTES)) {
                    // Depending on the system load, it may take a while for the queued events
                    // to be processed. And depending on how large the projects are, it may take a
                    // while for the processing of the respective event to complete.
                    // It is unlikely though that either of these situations causes a block for
                    // over 15 minutes. If that happens, the system is under-resourced.
                    LOGGER.warn("Updating metrics for projects " + firstId + "-" + lastId +
                            " took longer than expected (15m); Proceeding with potentially stale data");
                }
                LOGGER.debug("Completed metrics updates for projects " + firstId + "-" + lastId);

                for (final Project project : activeProjects) {
                    LOGGER.debug("Processing latest metrics for project " + project.getUuid());
                    final ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
                    if (metrics == null) {
                        // The project metrics calculation task failed, or the project has been
                        // deleted after the event being dispatched. Either way, nothing we can
                        // do anything about.
                        LOGGER.debug("No metrics found for project " + project.getUuid() + " - skipping");
                        continue;
                    }

                    counters.critical += metrics.getCritical();
                    counters.high += metrics.getHigh();
                    counters.medium += metrics.getMedium();
                    counters.low += metrics.getLow();
                    counters.unassigned += metrics.getUnassigned();
                    counters.vulnerabilities += metrics.getVulnerabilities();

                    counters.findingsTotal += metrics.getFindingsTotal();
                    counters.findingsAudited += metrics.getFindingsAudited();
                    counters.findingsUnaudited += metrics.getFindingsUnaudited();
                    counters.suppressions += metrics.getSuppressed();
                    counters.inheritedRiskScore = Metrics.inheritedRiskScore(counters.critical, counters.high, counters.medium, counters.low, counters.unassigned);

                    counters.projects++;
                    if (metrics.getVulnerabilities() > 0) {
                        counters.vulnerableProjects++;
                    }
                    counters.components += metrics.getComponents();
                    counters.vulnerableComponents += metrics.getVulnerableComponents();

                    counters.policyViolationsFail += metrics.getPolicyViolationsFail();
                    counters.policyViolationsWarn += metrics.getPolicyViolationsWarn();
                    counters.policyViolationsInfo += metrics.getPolicyViolationsInfo();
                    counters.policyViolationsTotal += metrics.getPolicyViolationsTotal();
                    counters.policyViolationsAudited += metrics.getPolicyViolationsAudited();
                    counters.policyViolationsUnaudited += metrics.getPolicyViolationsUnaudited();
                    counters.policyViolationsSecurityTotal += metrics.getPolicyViolationsSecurityTotal();
                    counters.policyViolationsSecurityAudited += metrics.getPolicyViolationsSecurityAudited();
                    counters.policyViolationsSecurityUnaudited += metrics.getPolicyViolationsSecurityUnaudited();
                    counters.policyViolationsLicenseTotal += metrics.getPolicyViolationsLicenseTotal();
                    counters.policyViolationsLicenseAudited += metrics.getPolicyViolationsLicenseAudited();
                    counters.policyViolationsLicenseUnaudited += metrics.getPolicyViolationsLicenseUnaudited();
                    counters.policyViolationsOperationalTotal += metrics.getPolicyViolationsOperationalTotal();
                    counters.policyViolationsOperationalAudited += metrics.getPolicyViolationsOperationalAudited();
                    counters.policyViolationsOperationalUnaudited += metrics.getPolicyViolationsOperationalUnaudited();
                }

                LOGGER.debug("Fetching next " + BATCH_SIZE + " projects");
                activeProjects = fetchNextActiveProjectsPage(pm, lastId);
            }

            qm.runInTransaction(() -> {
                final PortfolioMetrics latestMetrics = qm.getMostRecentPortfolioMetrics();
                if (!counters.hasChanged(latestMetrics)) {
                    LOGGER.debug("Portfolio metrics did not change");
                    latestMetrics.setLastOccurrence(counters.measuredAt);
                } else {
                    LOGGER.debug("Portfolio metrics changed");
                    final PortfolioMetrics metrics = counters.createPortfolioMetrics();
                    pm.makePersistent(metrics);
                }
            });
        }

        LOGGER.info("Completed portfolio metrics update in " +
                DurationFormatUtils.formatDuration(new Date().getTime() - counters.measuredAt.getTime(), "mm:ss:SS"));
    }

    private List<Project> fetchNextActiveProjectsPage(final PersistenceManager pm, final Long lastId) throws Exception {
        try (final Query<Project> query = pm.newQuery(Project.class)) {
            // exclude collection projects since their numbers are included in other projects and would wrongly influence portfolio metrics.
            if (lastId == null) {
                query.setFilter("(active == null || active == true) && (collectionLogic == null || collectionLogic == 'NONE')");
            } else {
                query.setFilter("(active == null || active == true) && (collectionLogic == null || collectionLogic == 'NONE') " +
                        "&& id < :lastId");
                query.setParameters(lastId);
            }
            query.setOrdering("id DESC");
            query.range(0, BATCH_SIZE);
            query.getFetchPlan().setGroup(Project.FetchGroup.METRICS_UPDATE.name());
            return List.copyOf(query.executeList());
        }
    }

}
