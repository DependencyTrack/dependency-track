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
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.datanucleus.api.jdo.JDOQuery;
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
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.Comparator;
import java.util.Map;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;
import java.util.stream.IntStream;

/**
 * A {@link Subscriber} task that updates {@link Project} metrics.
 *
 * @since 4.6.0
 */
public class ProjectMetricsUpdateTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(ProjectMetricsUpdateTask.class);

    /**
     * captures simplified Semver Versions with optional epoch, ignoring build number or other addons
     * format like: [1:]1[.2[.3]][-alpha123+34234] --> consideres only 1:1.2.3
     */
    protected static final Pattern VERSION_PATTERN = Pattern.compile(
            "^(?:(.*):)?v?(\\d+[a-z]*)?(?:\\.(\\d+[a-z]*))?(?:\\.(\\d+[a-z]*))?.*$",
            Pattern.CASE_INSENSITIVE
    );

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

            // if the project is a collection, different logic has to be applied depending on project configuration
            switch (project.getCollectionLogic()) {
                case NONE -> this.updateRegularProjectMetrics(project, pm, counters);
                case AGGREGATE_DIRECT_CHILDREN -> this.updateAggregateDirectChildrenCollectionMetrics(project, pm, counters);
                case AGGREGATE_DIRECT_CHILDREN_WITH_TAG -> this.updateAggregateDirectChildrenWithTagCollectionMetrics(project, pm, counters);
                case HIGHEST_SEMVER_CHILD -> this.updateHighestSemVerChildCollectionMetrics(project, pm, counters);
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
                    final ProjectMetrics metrics = counters.createProjectMetrics(project);
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

    private void updateRegularProjectMetrics(final Project project, final PersistenceManager pm, final Counters counters) throws Exception {
        final UUID uuid = project.getUuid();

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
    }

    private void updateAggregateDirectChildrenCollectionMetrics(final Project project, final PersistenceManager pm, final Counters counters) {
        LOGGER.debug("Fetching metrics of children of collection project " + project.getUuid() +
                " using collection logic " + project.getCollectionLogic());

        Query subQuery = pm.newQuery(ProjectMetrics.class);
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

        Query subQuery = pm.newQuery(ProjectMetrics.class);
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

    private void updateHighestSemVerChildCollectionMetrics(final Project project, final PersistenceManager pm, final Counters counters) {
        // Optimized query to quickly get project IDs and versions only, we don't need other project data
        final String jdoql = "SELECT id, version FROM org.dependencytrack.model.Project WHERE parent.id == :parentId && " +
                "(active == true || active == null) && version != null && version.length() != 0";
        final Query<Object[]> query = pm.newQuery(JDOQuery.JDOQL_QUERY_LANGUAGE, jdoql);
        query.setResult("id, version");

        final List<Object[]> projectVersions = (List<Object[]>)query.execute(project.getId());
        if(projectVersions.isEmpty()) {
            return;
        }
        // Find the highest version. this supports a simplified SemVer versioning with optional epoch,
        // ignoring any extra buildnumber or similar.
        // Any other version text is sorted lowest and only shows up if no numeric or SemVer version is available.
        // Examples: "123123", "1.1.2", "1.0.0", "1:0.0.1", "4.4.2-alpha.2", "1.244.43+asd2"
        Comparator<Object[]> versionComparator = Comparator.comparing(
                p -> VERSION_PATTERN.matcher((String)p[1]).results()
                        .flatMap(
                                mr -> IntStream.rangeClosed(1, mr.groupCount())
                                        .mapToObj(mr::group)
                        )
                        .mapToInt(val -> val == null ? 0 : Integer.parseInt(val))
                        .toArray(),
                Arrays::compare);
        Object[] highestProject = Collections.max(projectVersions, versionComparator);

        // get metrics of highest version
        LOGGER.debug("Fetching metrics of highest version child " + highestProject[1] +
                " of project " + project.getUuid() + " using collection logic " +
                project.getCollectionLogic());
        final Query<ProjectMetrics> metricsQuery = pm.newQuery(ProjectMetrics.class);
        metricsQuery.setFilter("project.id == :projectId");
        metricsQuery.setParameters(highestProject[0]);
        metricsQuery.setOrdering("lastOccurrence desc");
        metricsQuery.setRange(0, 1);
        final ProjectMetrics metrics = metricsQuery.executeUnique();
        this.addToCounters(counters, metrics);
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

    private void addToCounters(Counters counters, ProjectMetrics projectMetrics) {
        counters.critical += projectMetrics.getCritical();
        counters.high += projectMetrics.getHigh();
        counters.medium += projectMetrics.getMedium();
        counters.low += projectMetrics.getLow();
        counters.unassigned += projectMetrics.getUnassigned();
        counters.vulnerabilities += projectMetrics.getVulnerabilities();

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
