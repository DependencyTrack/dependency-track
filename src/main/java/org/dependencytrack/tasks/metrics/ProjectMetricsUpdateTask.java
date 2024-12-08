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
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.persistence.ScopedCustomization;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.metrics.Metrics;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectCollectionLogic;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

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

    private void updateMetrics(final UUID uuid) {
        final var counters = new Counters();

        try (final QueryManager qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();

            final Project project = fetchProject(pm, uuid);
            if (project == null) {
                throw new NoSuchElementException("Project " + uuid + " does not exist");
            }

            counters.projectCollectionLogic = project.getCollectionLogic();
            // if the project is a collection, different logic has to be applied depending on project configuration
            switch (project.getCollectionLogic()) {
                case NONE -> this.updateRegularProjectMetrics(project, pm, counters);
                case AGGREGATE_DIRECT_CHILDREN -> this.updateAggregateDirectChildrenCollectionMetrics(project, pm, counters);
                case AGGREGATE_DIRECT_CHILDREN_WITH_TAG -> this.updateAggregateDirectChildrenWithTagCollectionMetrics(project, pm, counters);
                case AGGREGATE_LATEST_VERSION_CHILDREN -> this.updateLatestVersionChildrenCollectionMetrics(project, pm, counters);
            }

            AtomicBoolean metricsChanged = new AtomicBoolean(false);
            qm.runInTransaction(() -> {
                final ProjectMetrics latestMetrics = qm.getMostRecentProjectMetrics(project);
                metricsChanged.set(counters.hasChanged(latestMetrics));
                if (!counters.hasChanged(latestMetrics)) {
                    LOGGER.debug("Metrics of project " + uuid + " did not change");
                    latestMetrics.setLastOccurrence(counters.measuredAt);
                } else {
                    LOGGER.debug("Metrics of project " + uuid + " changed");
                    final boolean collectionLogicChanged = latestMetrics != null &&
                            latestMetrics.getCollectionLogic() != project.getCollectionLogic();
                    final ProjectMetrics metrics = counters.createProjectMetrics(project, collectionLogicChanged);
                    pm.makePersistent(metrics);
                }
            });

            if (project.getLastInheritedRiskScore() == null ||
                    project.getLastInheritedRiskScore() != counters.inheritedRiskScore) {
                LOGGER.debug("Updating inherited risk score of project " + uuid);
                qm.runInTransaction(() -> project.setLastInheritedRiskScore(counters.inheritedRiskScore));
            }

            LOGGER.debug("Completed metrics update for project " + uuid + " in " +
                    DurationFormatUtils.formatDuration(new Date().getTime() - counters.measuredAt.getTime(), "mm:ss:SS"));

            Project parent = project.getParent();
            if(parent != null && parent.getCollectionLogic() != ProjectCollectionLogic.NONE && metricsChanged.get()) {
                LOGGER.debug("Scheduling metrics update of project's parent collection " + parent.getUuid());
                Event.dispatch(new ProjectMetricsUpdateEvent(parent.getUuid()));
            }
        }
    }

    private void updateRegularProjectMetrics(final Project project, final PersistenceManager pm, final Counters counters) {
        final UUID uuid = project.getUuid();

        LOGGER.debug("Fetching first components page for project " + uuid);
        List<Component> components = fetchNextComponentsPage(pm, project, null);

        while (!components.isEmpty()) {
            final long lastId = components.getLast().getId();

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

                // Remove components from the L1 cache to prevent it from growing too large.
                // Note that because ComponentMetricsUpdateTask uses its own QueryManager,
                // component metrics objects are not in this L1 cache.
                pm.evictAll(false, Component.class);

            LOGGER.debug("Fetching next components page for project " + uuid);
            components = fetchNextComponentsPage(pm, project, lastId);
        }
    }

    private void updateAggregateDirectChildrenCollectionMetrics(final Project project, final PersistenceManager pm, final Counters counters) {
        LOGGER.debug("Fetching metrics of children of collection project " + project.getUuid() +
                " using collection logic " + project.getCollectionLogic());

        Query<ProjectMetrics> subQuery = pm.newQuery(ProjectMetrics.class);
        subQuery.setFilter("project == :project");
        subQuery.setResult("max(lastOccurrence)");

        final Query<ProjectMetrics> query = pm.newQuery(ProjectMetrics.class);
        query.setFilter("project.parent == :parentProject && " +
                "(project.active == true || project.active == null) " +
                "&& lastOccurrence == maxLastOccurrence");
        query.declareVariables("java.util.Date maxLastOccurrence");
        query.addSubquery(subQuery, "java.util.Date maxLastOccurrence", null, "this.project");

        query.setParameters(project);
        final List<ProjectMetrics> childrenMetrics = query.executeList();
        for (ProjectMetrics metrics : childrenMetrics) {
            this.addToCounters(counters, metrics);
        }
    }

    private void updateAggregateDirectChildrenWithTagCollectionMetrics(final Project project, final PersistenceManager pm, final Counters counters) {
        if(project.getCollectionTag() == null) {
            LOGGER.debug("Couldn't update metrics of collection project " +
                    project.getUuid() + " using logic " + project.getCollectionLogic() +
                    " because the collection has no collection tags defined.");
            return;
        }

        LOGGER.debug("Fetching metrics of children with tag " + project.getCollectionTag().getName() +
                " of project " + project.getUuid() + " using collection logic " +
                project.getCollectionLogic());

        Query<ProjectMetrics> subQuery = pm.newQuery(ProjectMetrics.class);
        subQuery.setFilter("project == :project");
        subQuery.setResult("max(lastOccurrence)");

        final Query<ProjectMetrics> query = pm.newQuery(ProjectMetrics.class);
        query.setFilter("project.parent == :parentProject && " +
                "(project.active == true || project.active == null) && " +
                "lastOccurrence == maxLastOccurrence && " +
                "(project.tags.contains(:tag))");
        query.declareVariables("java.util.Date maxLastOccurrence");
        query.addSubquery(subQuery, "java.util.Date maxLastOccurrence", null, "this.project");

        query.setNamedParameters(
                Map.of("parentProject", project, "tag", project.getCollectionTag())
        );
        final List<ProjectMetrics> childrenMetrics = query.executeList();
        for (ProjectMetrics metrics : childrenMetrics) {
            this.addToCounters(counters, metrics);
        }
    }

    private void updateLatestVersionChildrenCollectionMetrics(final Project project, final PersistenceManager pm, final Counters counters) {
        LOGGER.debug("Fetching metrics of children of collection project " + project.getUuid() +
                " using collection logic " + project.getCollectionLogic());

        Query<ProjectMetrics> subQuery = pm.newQuery(ProjectMetrics.class);
        subQuery.setFilter("project == :project");
        subQuery.setResult("max(lastOccurrence)");

        final Query<ProjectMetrics> query = pm.newQuery(ProjectMetrics.class);
        query.setFilter("project.parent == :parentProject && " +
                "(project.active == true || project.active == null) " +
                "&& project.isLatest == true" +
                "&& lastOccurrence == maxLastOccurrence");
        query.declareVariables("java.util.Date maxLastOccurrence");
        query.addSubquery(subQuery, "java.util.Date maxLastOccurrence", null, "this.project");

        query.setParameters(project);
        final List<ProjectMetrics> childrenMetrics = query.executeList();
        // Hint: There could be multiple children with isLatest==true from different project parts, so we aggregate those.
        for (ProjectMetrics metrics : childrenMetrics) {
            this.addToCounters(counters, metrics);
        }
    }

    private Project fetchProject(final PersistenceManager pm, final UUID uuid) {
        final Query<Project> query = pm.newQuery(Project.class);
        query.setFilter("uuid == :uuid");
        query.setParameters(uuid);

        // NB: Set fetch group on PM level to avoid fields of the default fetch group from being loaded.
        try (var ignoredPersistenceCustomization = new ScopedCustomization(pm)
                .withFetchGroup(Project.FetchGroup.METRICS_UPDATE.name())) {
            return query.executeUnique();
        } finally {
            query.closeAll();
        }
    }

    private List<Component> fetchNextComponentsPage(final PersistenceManager pm, final Project project, final Long lastId) {
        final Query<Component> query = pm.newQuery(Component.class);
        if (lastId == null) {
            query.setFilter("project == :project");
            query.setParameters(project);
        } else {
            query.setFilter("project == :project && id < :lastId");
            query.setParameters(project, lastId);
        }
        query.setOrdering("id DESC");
        query.setRange(0, 1000);

        // NB: Set fetch group on PM level to avoid fields of the default fetch group from being loaded.
        try (var ignoredPersistenceCustomization = new ScopedCustomization(pm)
                .withFetchGroup(Component.FetchGroup.METRICS_UPDATE.name())) {
            return List.copyOf(query.executeList());
        } finally {
            query.closeAll();
        }
    }

    private void addToCounters(Counters counters, ProjectMetrics projectMetrics) {
        counters.critical += projectMetrics.getCritical();
        counters.high += projectMetrics.getHigh();
        counters.medium += projectMetrics.getMedium();
        counters.low += projectMetrics.getLow();
        counters.unassigned += projectMetrics.getUnassigned();
        counters.vulnerabilities += Math.toIntExact(projectMetrics.getVulnerabilities());

        counters.findingsTotal += projectMetrics.getFindingsTotal();
        counters.findingsAudited += projectMetrics.getFindingsAudited();
        counters.findingsUnaudited += projectMetrics.getFindingsUnaudited();
        counters.suppressions += projectMetrics.getSuppressed();
        counters.inheritedRiskScore = Metrics.inheritedRiskScore(counters.critical, counters.high, counters.medium, counters.low, counters.unassigned);

        counters.components += projectMetrics.getComponents();
        counters.vulnerableComponents += projectMetrics.getVulnerableComponents();

        counters.policyViolationsFail += projectMetrics.getPolicyViolationsFail();
        counters.policyViolationsWarn += projectMetrics.getPolicyViolationsWarn();
        counters.policyViolationsInfo += projectMetrics.getPolicyViolationsInfo();
        counters.policyViolationsTotal += projectMetrics.getPolicyViolationsTotal();
        counters.policyViolationsAudited += projectMetrics.getPolicyViolationsAudited();
        counters.policyViolationsUnaudited += projectMetrics.getPolicyViolationsUnaudited();
        counters.policyViolationsSecurityTotal += projectMetrics.getPolicyViolationsSecurityTotal();
        counters.policyViolationsSecurityAudited += projectMetrics.getPolicyViolationsSecurityAudited();
        counters.policyViolationsSecurityUnaudited += projectMetrics.getPolicyViolationsSecurityUnaudited();
        counters.policyViolationsLicenseTotal += projectMetrics.getPolicyViolationsLicenseTotal();
        counters.policyViolationsLicenseAudited += projectMetrics.getPolicyViolationsLicenseAudited();
        counters.policyViolationsLicenseUnaudited += projectMetrics.getPolicyViolationsLicenseUnaudited();
        counters.policyViolationsOperationalTotal += projectMetrics.getPolicyViolationsOperationalTotal();
        counters.policyViolationsOperationalAudited += projectMetrics.getPolicyViolationsOperationalAudited();
        counters.policyViolationsOperationalUnaudited += projectMetrics.getPolicyViolationsOperationalUnaudited();
    }

}
