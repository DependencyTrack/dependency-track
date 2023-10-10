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
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.metrics.Metrics;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.Date;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

/**
 * A {@link Subscriber} task that updates {@link Project} metrics.
 *
 * @since 4.6.0
 */
public class ProjectMetricsUpdateTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(ProjectMetricsUpdateTask.class);

    @Override
    public void inform(final Event e) {
        if (e instanceof final ProjectMetricsUpdateEvent event) {
            try {
                final UUID uuid = event.getUuid();
                LOGGER.info("Executing metrics update for project " + uuid);
                updateMetrics(uuid);
            } catch (Exception ex) {
                LOGGER.error("An unexpected error occurred while updating metrics for project " + event.getUuid(), ex);
            }
        }
    }

    private void updateMetrics(final UUID uuid) throws Exception {
        final var counters = new Counters();

        try (final QueryManager qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();

            final Project project = qm.getObjectByUuid(Project.class, uuid, List.of(Project.FetchGroup.METRICS_UPDATE.name()));
            if (project == null) {
                throw new NoSuchElementException("Project " + uuid + " does not exist");
            }

            LOGGER.debug("Fetching first components page for project " + uuid);
            List<Component> components = fetchNextComponentsPage(pm, project, null);

            while (!components.isEmpty()) {
                for (final Component component : components) {
                    final Counters componentCounters;
                    try {
                        componentCounters = ComponentMetricsUpdateTask.updateMetrics(component.getUuid());
                    } catch (NoSuchElementException ex) {
                        // This will happen when a component or its associated project have been deleted after the
                        // task started. Instead of splurging the log with to-be-expected errors, we just log it
                        // with DEBUG, and ignore it otherwise.
                        LOGGER.debug("Couldn't update metrics of component " + component.getUuid() + " because the component was not found", ex);
                        continue;
                    } catch (Exception ex) {
                        LOGGER.error("An unexpected error occurred while updating metrics of component " + component.getUuid(), ex);
                        continue;
                    }

                    counters.critical += componentCounters.critical;
                    counters.high += componentCounters.high;
                    counters.medium += componentCounters.medium;
                    counters.low += componentCounters.low;
                    counters.unassigned += componentCounters.unassigned;
                    counters.vulnerabilities += componentCounters.vulnerabilities;

                    counters.findingsTotal += componentCounters.findingsTotal;
                    counters.findingsAudited += componentCounters.findingsAudited;
                    counters.findingsUnaudited += componentCounters.findingsUnaudited;
                    counters.suppressions += componentCounters.suppressions;
                    counters.inheritedRiskScore = Metrics.inheritedRiskScore(counters.critical, counters.high, counters.medium, counters.low, counters.unassigned);

                    counters.components++;
                    if (componentCounters.vulnerabilities > 0) {
                        counters.vulnerableComponents += 1;
                    }

                    counters.policyViolationsFail += componentCounters.policyViolationsFail;
                    counters.policyViolationsWarn += componentCounters.policyViolationsWarn;
                    counters.policyViolationsInfo += componentCounters.policyViolationsInfo;
                    counters.policyViolationsTotal += componentCounters.policyViolationsTotal;
                    counters.policyViolationsAudited += componentCounters.policyViolationsAudited;
                    counters.policyViolationsUnaudited += componentCounters.policyViolationsUnaudited;
                    counters.policyViolationsSecurityTotal += componentCounters.policyViolationsSecurityTotal;
                    counters.policyViolationsSecurityAudited += componentCounters.policyViolationsSecurityAudited;
                    counters.policyViolationsSecurityUnaudited += componentCounters.policyViolationsSecurityUnaudited;
                    counters.policyViolationsLicenseTotal += componentCounters.policyViolationsLicenseTotal;
                    counters.policyViolationsLicenseAudited += componentCounters.policyViolationsLicenseAudited;
                    counters.policyViolationsLicenseUnaudited += componentCounters.policyViolationsLicenseUnaudited;
                    counters.policyViolationsOperationalTotal += componentCounters.policyViolationsOperationalTotal;
                    counters.policyViolationsOperationalAudited += componentCounters.policyViolationsOperationalAudited;
                    counters.policyViolationsOperationalUnaudited += componentCounters.policyViolationsOperationalUnaudited;
                }

                LOGGER.debug("Fetching next components page for project " + uuid);
                final long lastId = components.get(components.size() - 1).getId();
                components = fetchNextComponentsPage(pm, project, lastId);
            }

            qm.runInTransaction(() -> {
                final ProjectMetrics latestMetrics = qm.getMostRecentProjectMetrics(project);
                if (!counters.hasChanged(latestMetrics)) {
                    LOGGER.debug("Metrics of project " + uuid + " did not change");
                    latestMetrics.setLastOccurrence(counters.measuredAt);
                } else {
                    LOGGER.debug("Metrics of project " + uuid + " changed");
                    final ProjectMetrics metrics = counters.createProjectMetrics(project);
                    pm.makePersistent(metrics);
                }
            });

            if (project.getLastInheritedRiskScore() == null ||
                    project.getLastInheritedRiskScore() != counters.inheritedRiskScore) {
                LOGGER.debug("Updating inherited risk score of project " + uuid);
                qm.runInTransaction(() -> project.setLastInheritedRiskScore(counters.inheritedRiskScore));
            }
        }

        LOGGER.debug("Completed metrics update for project " + uuid + " in " +
                DurationFormatUtils.formatDuration(new Date().getTime() - counters.measuredAt.getTime(), "mm:ss:SS"));
    }

    private List<Component> fetchNextComponentsPage(final PersistenceManager pm, final Project project, final Long lastId) throws Exception {
        try (final Query<Component> query = pm.newQuery(Component.class)) {
            if (lastId == null) {
                query.setFilter("project == :project");
                query.setParameters(project);
            } else {
                query.setFilter("project == :project && id < :lastId");
                query.setParameters(project, lastId);
            }
            query.setOrdering("id DESC");
            query.setRange(0, 500);
            query.getFetchPlan().setGroup(Component.FetchGroup.METRICS_UPDATE.name());
            return List.copyOf(query.executeList());
        }
    }

}
