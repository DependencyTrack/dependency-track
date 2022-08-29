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
import org.dependencytrack.util.PersistenceUtil;

import javax.jdo.FetchGroup;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.Transaction;
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
                updateMetrics(event.getProject());
            } catch (Exception ex) {
                LOGGER.error("An unexpected error occurred while updating project metrics", ex);
            }
        }
    }

    private void updateMetrics(Project project) throws Exception {
        PersistenceUtil.requireDetached(project);

        // Take the UUID from the detached project at the very beginning
        // to avoid DataNucleus from reaching out to the datastore every
        // time the .getUuid() getter is called on the attached project.
        final UUID projectUuid = project.getUuid();

        LOGGER.info("Executing metrics update for project " + projectUuid);
        final var counters = new Counters();

        try (final QueryManager qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();

            project = getProject(pm, project);
            if (project == null) {
                throw new NoSuchElementException("Project " + projectUuid + " does not exist");
            }

            LOGGER.trace("Fetching first components page for project " + projectUuid);
            List<Component> components = seekComponents(pm, project, 0);

            while (!components.isEmpty()) {
                for (final Component component : components) {
                    final Counters componentCounters;
                    try {
                        componentCounters = ComponentMetricsUpdateTask.updateMetrics(detachComponent(pm, component));
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

                LOGGER.trace("Fetching next components page for project " + projectUuid);
                final long lastId = components.get(components.size() - 1).getId();
                components = seekComponents(pm, project, lastId);
            }

            Transaction trx = pm.currentTransaction();
            try {
                trx.begin();
                final ProjectMetrics latestMetrics = qm.getMostRecentProjectMetrics(project);
                if (!counters.hasChanged(latestMetrics)) {
                    LOGGER.debug("Metrics of project " + projectUuid + " did not change");
                    latestMetrics.setLastOccurrence(counters.measuredAt);
                } else {
                    LOGGER.debug("Metrics of project " + projectUuid + " changed");
                    final ProjectMetrics metrics = counters.createProjectMetrics(project);
                    pm.makePersistent(metrics);
                }
                trx.commit();
            } finally {
                if (trx.isActive()) {
                    trx.rollback();
                }
            }

            if (project.getLastInheritedRiskScore() == null ||
                    project.getLastInheritedRiskScore() != counters.inheritedRiskScore) {
                LOGGER.debug("Updating inherited risk score of project " + projectUuid);
                trx = qm.getPersistenceManager().currentTransaction();
                try {
                    trx.begin();
                    project.setLastInheritedRiskScore(counters.inheritedRiskScore);
                    trx.commit();
                } finally {
                    if (trx.isActive()) {
                        trx.rollback();
                    }
                }
            }
        }

        LOGGER.info("Completed metrics update for project " + projectUuid + " in " +
                DurationFormatUtils.formatDuration(new Date().getTime() - counters.measuredAt.getTime(), "mm:ss:SS"));
    }

    private Project getProject(final PersistenceManager pm, final Project project) {
        try {
            pm.getFetchPlan().setGroup(Project.FetchGroup.METRICS.name());
            return pm.getObjectById(Project.class, project.getId());
        } finally {
            pm.getFetchPlan().setGroup(FetchGroup.DEFAULT);
        }
    }

    private List<Component> seekComponents(final PersistenceManager pm, final Project project, final long lastId) throws Exception {
        try (final Query<Component> query = pm.newQuery(Component.class)) {
            query.setFilter("project == :project && id > :lastId");
            query.setParameters(project, lastId);
            query.setOrdering("id asc");
            query.setRange(0, 500);
            query.getFetchPlan().setGroup(Component.FetchGroup.METRICS.name());
            return List.copyOf(query.executeList());
        }
    }

    private Component detachComponent(final PersistenceManager pm, final Component component) {
        try {
            pm.getFetchPlan().setGroup(Component.FetchGroup.METRICS.name());
            return pm.detachCopy(component);
        } finally {
            pm.getFetchPlan().setGroup(FetchGroup.DEFAULT);
        }
    }

}
