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

import alpine.common.logging.Logger;
import alpine.common.util.ThreadUtil;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.server.persistence.PersistenceManagerFactory;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.dependencytrack.event.CallbackEvent;
import org.dependencytrack.event.MetricsUpdateEvent;
import org.dependencytrack.metrics.Metrics;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.VulnerabilityMetrics;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.VulnerabilityUtil;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.Transaction;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static java.lang.Math.toIntExact;

/**
 * Subscriber task that performs calculations of various metrics.
 * <p>
 * For read-only database operations, raw SQL queries are preferred,
 * due to the high overhead of DataNucleus' object lifecycles and caches.
 *
 * @since 3.0.0
 */
public class MetricsUpdateTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(MetricsUpdateTask.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public void inform(final Event e) {
        if (!(e instanceof MetricsUpdateEvent)) {
            return;
        }

        LOGGER.debug("Starting metrics update task");
        final var event = (MetricsUpdateEvent) e;
        try {
            if (MetricsUpdateEvent.Type.PORTFOLIO == event.getType()) {
                updatePortfolioMetrics();
            } else if (MetricsUpdateEvent.Type.PROJECT == event.getType()) {
                updateProjectMetrics(((Project) event.getTarget()).getId());
            } else if (MetricsUpdateEvent.Type.COMPONENT == event.getType()) {
                updateComponentMetrics(((Component) event.getTarget()).getId());
            } else if (MetricsUpdateEvent.Type.VULNERABILITY == event.getType()) {
                updateVulnerabilityMetrics();
            }
        } catch (Exception ex) {
            LOGGER.error("An unknown error occurred while updating metrics", ex);
        }
        LOGGER.debug("Metrics update complete");
    }

    /**
     * Performs high-level metric updates on the portfolio.
     * <p>
     * Portfolio metrics are the aggregate of all project metrics.
     * <p>
     * A forced refresh of all project metrics is performed by dispatching a {@link MetricsUpdateEvent}
     * for each project in the portfolio. This is done in batches of size equal to a third of the worker pool
     * thread count, as a means of applying back-pressure and not overloading the event bus.
     */
    private void updatePortfolioMetrics() throws Exception {
        LOGGER.info("Executing portfolio metrics update");
        final var counters = new Counters();

        final long batchSize = ThreadUtil.determineNumberOfWorkerThreads() / 3;

        try (final var qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();

            LOGGER.debug("Fetching first " + batchSize + " projects");
            List<Long> projectIds = getActiveProjects(pm, batchSize, 0);

            while (!projectIds.isEmpty()) {
                final long firstId = projectIds.get(0);
                final long lastId = projectIds.get(projectIds.size() - 1);
                final int batchCount = projectIds.size();

                final var latch = new CountDownLatch(batchCount);

                for (final long projectId : projectIds) {
                    final var project = new Project();
                    project.setId(projectId);

                    final var callbackEvent = new CallbackEvent(latch::countDown);
                    Event.dispatch(new MetricsUpdateEvent(project)
                            .onSuccess(callbackEvent)
                            .onFailure(callbackEvent));
                }

                LOGGER.debug("Waiting for metrics updates for projects " + firstId + "-" + lastId + " to complete");
                if (!latch.await(1, TimeUnit.HOURS)) {
                    LOGGER.warn("Updating metrics for projects " + firstId + "-" + lastId +
                            "took longer than expected - Proceeding with potentially stale data");
                }
                LOGGER.debug("Completed metrics updates for projects " + firstId + "-" + lastId);

                for (final long projectId : projectIds) {
                    LOGGER.debug("Processing latest metrics for project " + projectId);
                    try (final Query<ProjectMetrics> query = pm.newQuery(ProjectMetrics.class)) {
                        query.setFilter("project.id == :projectId");
                        query.setOrdering("lastOccurrence desc");
                        query.setParameters(projectId);

                        final ProjectMetrics metrics = query.executeUnique();
                        if (metrics == null) {
                            LOGGER.debug("No metrics found for project " + projectId + " - skipping");
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
                }

                LOGGER.debug("Fetching next " + batchSize + " projects");
                projectIds = getActiveProjects(pm, batchSize, projectIds.get(projectIds.size() - 1));
            }
        }

        try (final var qm = new QueryManager()) {
            Transaction trx = qm.getPersistenceManager().currentTransaction();
            try {
                trx.begin();
                final PortfolioMetrics latestMetrics = qm.getMostRecentPortfolioMetrics();
                if (latestMetrics != null
                        && latestMetrics.getCritical() == counters.critical
                        && latestMetrics.getHigh() == counters.high
                        && latestMetrics.getMedium() == counters.medium
                        && latestMetrics.getLow() == counters.low
                        && latestMetrics.getUnassigned() == counters.unassigned
                        && latestMetrics.getVulnerabilities() == counters.vulnerabilities
                        && latestMetrics.getInheritedRiskScore() == counters.inheritedRiskScore
                        && latestMetrics.getPolicyViolationsFail() == counters.policyViolationsFail
                        && latestMetrics.getPolicyViolationsWarn() == counters.policyViolationsWarn
                        && latestMetrics.getPolicyViolationsInfo() == counters.policyViolationsInfo
                        && latestMetrics.getPolicyViolationsTotal() == counters.policyViolationsTotal
                        && latestMetrics.getPolicyViolationsAudited() == counters.policyViolationsAudited
                        && latestMetrics.getPolicyViolationsUnaudited() == counters.policyViolationsUnaudited
                        && latestMetrics.getPolicyViolationsSecurityTotal() == counters.policyViolationsSecurityTotal
                        && latestMetrics.getPolicyViolationsSecurityAudited() == counters.policyViolationsSecurityAudited
                        && latestMetrics.getPolicyViolationsSecurityUnaudited() == counters.policyViolationsSecurityUnaudited
                        && latestMetrics.getPolicyViolationsLicenseTotal() == counters.policyViolationsLicenseTotal
                        && latestMetrics.getPolicyViolationsLicenseAudited() == counters.policyViolationsLicenseAudited
                        && latestMetrics.getPolicyViolationsLicenseUnaudited() == counters.policyViolationsLicenseUnaudited
                        && latestMetrics.getPolicyViolationsOperationalTotal() == counters.policyViolationsOperationalTotal
                        && latestMetrics.getPolicyViolationsOperationalAudited() == counters.policyViolationsOperationalAudited
                        && latestMetrics.getPolicyViolationsOperationalUnaudited() == counters.policyViolationsOperationalUnaudited
                        && latestMetrics.getComponents() == counters.components
                        && latestMetrics.getVulnerableComponents() == counters.vulnerableComponents
                        && latestMetrics.getSuppressed() == counters.suppressions
                        && latestMetrics.getFindingsTotal() == counters.findingsTotal
                        && latestMetrics.getFindingsAudited() == counters.findingsAudited
                        && latestMetrics.getFindingsUnaudited() == counters.findingsUnaudited
                        && latestMetrics.getProjects() == counters.projects
                        && latestMetrics.getVulnerableProjects() == counters.vulnerableProjects) {
                    LOGGER.debug("Portfolio metrics did not change");
                    latestMetrics.setLastOccurrence(counters.measuredAt);
                } else {
                    LOGGER.debug("Portfolio metrics changed");
                    final var metrics = new PortfolioMetrics();
                    metrics.setCritical(counters.critical);
                    metrics.setHigh(counters.high);
                    metrics.setMedium(counters.medium);
                    metrics.setLow(counters.low);
                    metrics.setUnassigned(counters.unassigned);
                    metrics.setVulnerabilities(counters.vulnerabilities);
                    metrics.setComponents(counters.components);
                    metrics.setVulnerableComponents(counters.vulnerableComponents);
                    metrics.setSuppressed(counters.suppressions);
                    metrics.setFindingsTotal(counters.findingsTotal);
                    metrics.setFindingsAudited(counters.findingsAudited);
                    metrics.setFindingsUnaudited(counters.findingsUnaudited);
                    metrics.setProjects(counters.projects);
                    metrics.setVulnerableProjects(counters.vulnerableProjects);
                    metrics.setInheritedRiskScore(counters.inheritedRiskScore);
                    metrics.setPolicyViolationsFail(counters.policyViolationsFail);
                    metrics.setPolicyViolationsWarn(counters.policyViolationsWarn);
                    metrics.setPolicyViolationsInfo(counters.policyViolationsInfo);
                    metrics.setPolicyViolationsTotal(counters.policyViolationsTotal);
                    metrics.setPolicyViolationsAudited(counters.policyViolationsAudited);
                    metrics.setPolicyViolationsUnaudited(counters.policyViolationsUnaudited);
                    metrics.setPolicyViolationsSecurityTotal(counters.policyViolationsSecurityTotal);
                    metrics.setPolicyViolationsSecurityAudited(counters.policyViolationsSecurityAudited);
                    metrics.setPolicyViolationsSecurityUnaudited(counters.policyViolationsSecurityUnaudited);
                    metrics.setPolicyViolationsLicenseTotal(counters.policyViolationsLicenseTotal);
                    metrics.setPolicyViolationsLicenseAudited(counters.policyViolationsLicenseAudited);
                    metrics.setPolicyViolationsLicenseUnaudited(counters.policyViolationsLicenseUnaudited);
                    metrics.setPolicyViolationsOperationalTotal(counters.policyViolationsOperationalTotal);
                    metrics.setPolicyViolationsOperationalAudited(counters.policyViolationsOperationalAudited);
                    metrics.setPolicyViolationsOperationalUnaudited(counters.policyViolationsOperationalUnaudited);
                    metrics.setFirstOccurrence(counters.measuredAt);
                    metrics.setLastOccurrence(counters.measuredAt);
                    qm.getPersistenceManager().makePersistent(metrics);
                }
                trx.commit();
            } finally {
                if (trx.isActive()) {
                    trx.rollback();
                }
            }
        }

        LOGGER.info("Completed portfolio metrics update in " +
                DurationFormatUtils.formatDuration(new Date().getTime() - counters.measuredAt.getTime(), "mm:ss:SS"));
    }

    /**
     * Perform metric updates on a specific project.
     * <p>
     * Project metrics are the aggregate of all components within a project.
     *
     * @param projectId ID of the project to update metrics for
     * @return A {@link Counters} instance resembling the calculated metrics
     */
    private Counters updateProjectMetrics(final long projectId) throws Exception {
        final var counters = new Counters();

        final UUID projectUuid;
        final List<Long> componentIds;
        try (final PersistenceManager pm = PersistenceManagerFactory.createPersistenceManager()) {
            LOGGER.debug("Fetching UUID for project with ID " + projectId);
            projectUuid = getProjectUuid(pm, projectId)
                    .orElseThrow(() -> new NoSuchElementException("Project with ID " + projectId + " does not exist"));
            LOGGER.info("Executing metrics update for project " + projectUuid);

            LOGGER.debug("Fetching components for project " + projectUuid);
            componentIds = getComponents(pm, projectId);
            LOGGER.debug("Metrics update for project " + projectUuid + " will include " + componentIds.size() + " components");
        }

        for (final long componentId : componentIds) {
            final Counters componentCounters;
            try {
                componentCounters = updateComponentMetrics(componentId);
            } catch (NoSuchElementException e) {
                LOGGER.warn("Couldn't update component metrics because the component was not found." +
                        "This typically happens when the component or the project is was associated with " +
                        "was deleted after the metrics update task started.", e);
                continue;
            } catch (Exception e) {
                LOGGER.error("An unexpected error occurred while updating component metrics", e);
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

        try (final var qm = new QueryManager()) {
            final Project project = qm.getObjectById(Project.class, projectId);

            Transaction trx = qm.getPersistenceManager().currentTransaction();
            try {
                trx.begin();
                final ProjectMetrics latestMetrics = qm.getMostRecentProjectMetrics(project);
                if (latestMetrics != null
                        && latestMetrics.getCritical() == counters.critical
                        && latestMetrics.getHigh() == counters.high
                        && latestMetrics.getMedium() == counters.medium
                        && latestMetrics.getLow() == counters.low
                        && latestMetrics.getUnassigned() == counters.unassigned
                        && latestMetrics.getVulnerabilities() == counters.vulnerabilities
                        && latestMetrics.getSuppressed() == counters.suppressions
                        && latestMetrics.getFindingsTotal() == counters.findingsTotal
                        && latestMetrics.getFindingsAudited() == counters.findingsAudited
                        && latestMetrics.getFindingsUnaudited() == counters.findingsUnaudited
                        && latestMetrics.getInheritedRiskScore() == counters.inheritedRiskScore
                        && latestMetrics.getPolicyViolationsFail() == counters.policyViolationsFail
                        && latestMetrics.getPolicyViolationsWarn() == counters.policyViolationsWarn
                        && latestMetrics.getPolicyViolationsInfo() == counters.policyViolationsInfo
                        && latestMetrics.getPolicyViolationsTotal() == counters.policyViolationsTotal
                        && latestMetrics.getPolicyViolationsAudited() == counters.policyViolationsAudited
                        && latestMetrics.getPolicyViolationsUnaudited() == counters.policyViolationsUnaudited
                        && latestMetrics.getPolicyViolationsSecurityTotal() == counters.policyViolationsSecurityTotal
                        && latestMetrics.getPolicyViolationsSecurityAudited() == counters.policyViolationsSecurityAudited
                        && latestMetrics.getPolicyViolationsSecurityUnaudited() == counters.policyViolationsSecurityUnaudited
                        && latestMetrics.getPolicyViolationsLicenseTotal() == counters.policyViolationsLicenseTotal
                        && latestMetrics.getPolicyViolationsLicenseAudited() == counters.policyViolationsLicenseAudited
                        && latestMetrics.getPolicyViolationsLicenseUnaudited() == counters.policyViolationsLicenseUnaudited
                        && latestMetrics.getPolicyViolationsOperationalTotal() == counters.policyViolationsOperationalTotal
                        && latestMetrics.getPolicyViolationsOperationalAudited() == counters.policyViolationsOperationalAudited
                        && latestMetrics.getPolicyViolationsOperationalUnaudited() == counters.policyViolationsOperationalUnaudited
                        && latestMetrics.getComponents() == counters.components
                        && latestMetrics.getVulnerableComponents() == counters.vulnerableComponents) {
                    LOGGER.debug("Metrics of project " + projectUuid + " did not change");
                    latestMetrics.setLastOccurrence(counters.measuredAt);
                } else {
                    LOGGER.debug("Metrics of project " + projectUuid + " changed");
                    final var metrics = new ProjectMetrics();
                    metrics.setProject(project);
                    metrics.setCritical(counters.critical);
                    metrics.setHigh(counters.high);
                    metrics.setMedium(counters.medium);
                    metrics.setLow(counters.low);
                    metrics.setUnassigned(counters.unassigned);
                    metrics.setVulnerabilities(counters.vulnerabilities);
                    metrics.setComponents(counters.components);
                    metrics.setVulnerableComponents(counters.vulnerableComponents);
                    metrics.setSuppressed(counters.suppressions);
                    metrics.setFindingsTotal(counters.findingsTotal);
                    metrics.setFindingsAudited(counters.findingsAudited);
                    metrics.setFindingsUnaudited(counters.findingsUnaudited);
                    metrics.setInheritedRiskScore(counters.inheritedRiskScore);
                    metrics.setPolicyViolationsFail(counters.policyViolationsFail);
                    metrics.setPolicyViolationsWarn(counters.policyViolationsWarn);
                    metrics.setPolicyViolationsInfo(counters.policyViolationsInfo);
                    metrics.setPolicyViolationsTotal(counters.policyViolationsTotal);
                    metrics.setPolicyViolationsAudited(counters.policyViolationsAudited);
                    metrics.setPolicyViolationsUnaudited(counters.policyViolationsUnaudited);
                    metrics.setPolicyViolationsSecurityTotal(counters.policyViolationsSecurityTotal);
                    metrics.setPolicyViolationsSecurityAudited(counters.policyViolationsSecurityAudited);
                    metrics.setPolicyViolationsSecurityUnaudited(counters.policyViolationsSecurityUnaudited);
                    metrics.setPolicyViolationsLicenseTotal(counters.policyViolationsLicenseTotal);
                    metrics.setPolicyViolationsLicenseAudited(counters.policyViolationsLicenseAudited);
                    metrics.setPolicyViolationsLicenseUnaudited(counters.policyViolationsLicenseUnaudited);
                    metrics.setPolicyViolationsOperationalTotal(counters.policyViolationsOperationalTotal);
                    metrics.setPolicyViolationsOperationalAudited(counters.policyViolationsOperationalAudited);
                    metrics.setPolicyViolationsOperationalUnaudited(counters.policyViolationsOperationalUnaudited);
                    metrics.setFirstOccurrence(counters.measuredAt);
                    metrics.setLastOccurrence(counters.measuredAt);
                    qm.getPersistenceManager().makePersistent(metrics);
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
        return counters;
    }

    /**
     * Perform metric updates on a specific component.
     *
     * @param componentId ID of the component to update metrics for
     * @return A {@link Counters} instance resembling the calculated metrics
     */
    private Counters updateComponentMetrics(final long componentId) throws Exception {
        final var counters = new Counters();
        final UUID componentUuid;

        try (final PersistenceManager pm = PersistenceManagerFactory.createPersistenceManager()) {
            componentUuid = getComponentUuid(pm, componentId)
                    .orElseThrow(() -> new NoSuchElementException("Component with ID " + componentId + " does not exist"));
            LOGGER.debug("Executing metrics update for component " + componentUuid);

            for (final VulnerabilityProjection vulnerability : getVulnerabilities(pm, componentId)) {
                counters.vulnerabilities++;

                // Replicate the behavior of Vulnerability#getSeverity
                final Severity severity;
                if (vulnerability.severity != null) {
                    severity = vulnerability.severity;
                } else {
                    severity = VulnerabilityUtil.getSeverity(vulnerability.cvssV2BaseScore, vulnerability.cvssV3BaseScore);
                }

                if (Severity.CRITICAL == severity) {
                    counters.critical++;
                } else if (Severity.HIGH == severity) {
                    counters.high++;
                } else if (Severity.MEDIUM == severity) {
                    counters.medium++;
                } else if (Severity.LOW == severity) {
                    counters.low++;
                } else if (Severity.INFO == severity) {
                    counters.low++;
                } else if (Severity.UNASSIGNED == severity) {
                    counters.unassigned++;
                }
            }
            counters.findingsTotal = toIntExact(counters.vulnerabilities);
            counters.findingsAudited = toIntExact(getTotalAuditedFindings(pm, componentId));
            counters.findingsUnaudited = counters.findingsTotal - counters.findingsAudited;
            counters.suppressions = toIntExact(getTotalSuppressedFindings(pm, componentId));
            counters.inheritedRiskScore = Metrics.inheritedRiskScore(counters.critical, counters.high, counters.medium, counters.low, counters.unassigned);

            for (final PolicyViolationProjection violation : getPolicyViolations(pm, componentId)) {
                counters.policyViolationsTotal++;

                if (PolicyViolation.Type.LICENSE == violation.type) {
                    counters.policyViolationsLicenseTotal++;
                } else if (PolicyViolation.Type.OPERATIONAL == violation.type) {
                    counters.policyViolationsOperationalTotal++;
                } else if (PolicyViolation.Type.SECURITY == violation.type) {
                    counters.policyViolationsSecurityTotal++;
                }

                if (Policy.ViolationState.FAIL == violation.violationState) {
                    counters.policyViolationsFail++;
                } else if (Policy.ViolationState.WARN == violation.violationState) {
                    counters.policyViolationsWarn++;
                } else if (Policy.ViolationState.INFO == violation.violationState) {
                    counters.policyViolationsInfo++;
                }
            }
            if (counters.policyViolationsLicenseTotal > 0) {
                counters.policyViolationsLicenseAudited = toIntExact(getTotalAuditedPolicyViolations(pm, componentId, PolicyViolation.Type.LICENSE));
                counters.policyViolationsLicenseUnaudited = counters.policyViolationsLicenseTotal - counters.policyViolationsLicenseAudited;
            }
            if (counters.policyViolationsOperationalTotal > 0) {
                counters.policyViolationsOperationalAudited = toIntExact(getTotalAuditedPolicyViolations(pm, componentId, PolicyViolation.Type.OPERATIONAL));
                counters.policyViolationsOperationalUnaudited = counters.policyViolationsOperationalTotal - counters.policyViolationsOperationalAudited;
            }
            if (counters.policyViolationsSecurityTotal > 0) {
                counters.policyViolationsSecurityAudited = toIntExact(getTotalAuditedPolicyViolations(pm, componentId, PolicyViolation.Type.SECURITY));
                counters.policyViolationsSecurityUnaudited = counters.policyViolationsSecurityTotal - counters.policyViolationsSecurityAudited;
            }
            counters.policyViolationsAudited = counters.policyViolationsLicenseAudited +
                    counters.policyViolationsOperationalAudited +
                    counters.policyViolationsSecurityAudited;
            counters.policyViolationsUnaudited = counters.policyViolationsTotal - counters.policyViolationsAudited;
        }

        try (final var qm = new QueryManager()) {
            final Component component = qm.getObjectById(Component.class, componentId);

            Transaction trx = qm.getPersistenceManager().currentTransaction();
            try {
                trx.begin();
                final DependencyMetrics latestMetrics = qm.getMostRecentDependencyMetrics(component);
                if (latestMetrics != null
                        && latestMetrics.getCritical() == counters.critical
                        && latestMetrics.getHigh() == counters.high
                        && latestMetrics.getMedium() == counters.medium
                        && latestMetrics.getLow() == counters.low
                        && latestMetrics.getUnassigned() == counters.unassigned
                        && latestMetrics.getVulnerabilities() == counters.vulnerabilities
                        && latestMetrics.getSuppressed() == counters.suppressions
                        && latestMetrics.getFindingsTotal() == counters.findingsTotal
                        && latestMetrics.getFindingsAudited() == counters.findingsAudited
                        && latestMetrics.getFindingsUnaudited() == counters.findingsUnaudited
                        && latestMetrics.getInheritedRiskScore() == counters.inheritedRiskScore
                        && latestMetrics.getPolicyViolationsFail() == counters.policyViolationsFail
                        && latestMetrics.getPolicyViolationsWarn() == counters.policyViolationsWarn
                        && latestMetrics.getPolicyViolationsInfo() == counters.policyViolationsInfo
                        && latestMetrics.getPolicyViolationsTotal() == counters.policyViolationsTotal
                        && latestMetrics.getPolicyViolationsAudited() == counters.policyViolationsAudited
                        && latestMetrics.getPolicyViolationsUnaudited() == counters.policyViolationsUnaudited
                        && latestMetrics.getPolicyViolationsSecurityTotal() == counters.policyViolationsSecurityTotal
                        && latestMetrics.getPolicyViolationsSecurityAudited() == counters.policyViolationsSecurityAudited
                        && latestMetrics.getPolicyViolationsSecurityUnaudited() == counters.policyViolationsSecurityUnaudited
                        && latestMetrics.getPolicyViolationsLicenseTotal() == counters.policyViolationsLicenseTotal
                        && latestMetrics.getPolicyViolationsLicenseAudited() == counters.policyViolationsLicenseAudited
                        && latestMetrics.getPolicyViolationsLicenseUnaudited() == counters.policyViolationsLicenseUnaudited
                        && latestMetrics.getPolicyViolationsOperationalTotal() == counters.policyViolationsOperationalTotal
                        && latestMetrics.getPolicyViolationsOperationalAudited() == counters.policyViolationsOperationalAudited
                        && latestMetrics.getPolicyViolationsOperationalUnaudited() == counters.policyViolationsOperationalUnaudited) {
                    LOGGER.debug("Metrics of component " + componentUuid + " did not change");
                    latestMetrics.setLastOccurrence(counters.measuredAt);
                } else {
                    LOGGER.debug("Metrics of component " + componentUuid + " changed");
                    final var metrics = new DependencyMetrics();
                    metrics.setComponent(component);
                    metrics.setProject(component.getProject());
                    metrics.setCritical(counters.critical);
                    metrics.setHigh(counters.high);
                    metrics.setMedium(counters.medium);
                    metrics.setLow(counters.low);
                    metrics.setUnassigned(counters.unassigned);
                    metrics.setVulnerabilities(counters.vulnerabilities);
                    metrics.setSuppressed(counters.suppressions);
                    metrics.setFindingsTotal(counters.findingsTotal);
                    metrics.setFindingsAudited(counters.findingsAudited);
                    metrics.setFindingsUnaudited(counters.findingsUnaudited);
                    metrics.setInheritedRiskScore(counters.inheritedRiskScore);
                    metrics.setPolicyViolationsFail(counters.policyViolationsFail);
                    metrics.setPolicyViolationsWarn(counters.policyViolationsWarn);
                    metrics.setPolicyViolationsInfo(counters.policyViolationsInfo);
                    metrics.setPolicyViolationsTotal(counters.policyViolationsTotal);
                    metrics.setPolicyViolationsAudited(counters.policyViolationsAudited);
                    metrics.setPolicyViolationsUnaudited(counters.policyViolationsUnaudited);
                    metrics.setPolicyViolationsSecurityTotal(counters.policyViolationsSecurityTotal);
                    metrics.setPolicyViolationsSecurityAudited(counters.policyViolationsSecurityAudited);
                    metrics.setPolicyViolationsSecurityUnaudited(counters.policyViolationsSecurityUnaudited);
                    metrics.setPolicyViolationsLicenseTotal(counters.policyViolationsLicenseTotal);
                    metrics.setPolicyViolationsLicenseAudited(counters.policyViolationsLicenseAudited);
                    metrics.setPolicyViolationsLicenseUnaudited(counters.policyViolationsLicenseUnaudited);
                    metrics.setPolicyViolationsOperationalTotal(counters.policyViolationsOperationalTotal);
                    metrics.setPolicyViolationsOperationalAudited(counters.policyViolationsOperationalAudited);
                    metrics.setPolicyViolationsOperationalUnaudited(counters.policyViolationsOperationalUnaudited);
                    metrics.setFirstOccurrence(counters.measuredAt);
                    metrics.setLastOccurrence(counters.measuredAt);
                    qm.getPersistenceManager().makePersistent(metrics);
                }
                trx.commit();
            } finally {
                if (trx.isActive()) {
                    trx.rollback();
                }
            }

            if (component.getLastInheritedRiskScore() == null ||
                    component.getLastInheritedRiskScore() != counters.inheritedRiskScore) {
                LOGGER.debug("Updating inherited risk score of component " + componentUuid);
                trx = qm.getPersistenceManager().currentTransaction();
                try {
                    trx.begin();
                    component.setLastInheritedRiskScore(counters.inheritedRiskScore);
                    trx.commit();
                } finally {
                    if (trx.isActive()) {
                        trx.rollback();
                    }
                }
            }
        }

        LOGGER.debug("Completed metrics update for component " + componentUuid + " in " +
                DurationFormatUtils.formatDuration(new Date().getTime() - counters.measuredAt.getTime(), "mm:ss:SS"));
        return counters;
    }

    private void updateVulnerabilityMetrics() throws Exception {
        LOGGER.info("Executing metrics update on vulnerability database");

        final var measuredAt = new Date();
        final var yearMonthCounters = new VulnerabilityDateCounters(measuredAt, true);
        final var yearCounters = new VulnerabilityDateCounters(measuredAt, false);

        try (final PersistenceManager pm = PersistenceManagerFactory.createPersistenceManager()) {
            List<VulnerabilityDateProjection> vulnerabilities = getVulnerabilityDates(pm, 0);
            while (!vulnerabilities.isEmpty()) {
                for (final VulnerabilityDateProjection vulnerability : vulnerabilities) {
                    if (vulnerability.created != null) {
                        yearMonthCounters.updateMetrics(vulnerability.created);
                        yearCounters.updateMetrics(vulnerability.created);
                    } else if (vulnerability.published != null) {
                        yearMonthCounters.updateMetrics(vulnerability.published);
                        yearCounters.updateMetrics(vulnerability.published);
                    }
                }

                final long lastId = vulnerabilities.get(vulnerabilities.size() - 1).id;
                vulnerabilities = getVulnerabilityDates(pm, lastId);
            }
        }

        try (final var qm = new QueryManager()) {
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
     * Fetch IDs of active projects in pages of {@code limit}.
     * <p>
     * In order to not load multiple thousands of objects at once, paging is used.
     * The first call should provide a {@code lastId} of {@code 0}, subsequent calls
     * are expected to provide the highest ID of the previously fetched page.
     *
     * @param pm     The {@link  PersistenceManager} to use
     * @param limit  Maximum number of IDs to fetch
     * @param lastId Highest ID of the previously fetched page
     * @return Up to {@code limit} project IDs
     * @throws Exception If the query could not be closed
     */
    private List<Long> getActiveProjects(final PersistenceManager pm, final long limit, final long lastId) throws Exception {
        try (final Query<?> query = pm.newQuery(Project.class)) {
            query.setFilter("id > :lastId");
            query.setOrdering("id asc");
            query.setParameters(lastId);
            query.setResult("id");
            query.range(0, limit);
            return List.copyOf(query.executeResultList(Long.class));
        }
    }

    private Optional<UUID> getProjectUuid(final PersistenceManager pm, final long projectId) throws Exception {
        try (final Query<?> query = pm.newQuery(Query.SQL, "SELECT \"UUID\" FROM \"PROJECT\" WHERE \"ID\" = ?")) {
            query.setParameters(projectId);
            return Optional.ofNullable(query.executeResultUnique(String.class)).map(UUID::fromString);
        }
    }

    private List<Long> getComponents(final PersistenceManager pm, final long projectId) throws Exception {
        try (final Query<?> query = pm.newQuery(Query.SQL, "SELECT \"ID\" FROM \"COMPONENT\" WHERE \"PROJECT_ID\" = ?")) {
            query.setParameters(projectId);
            return List.copyOf(query.executeResultList(Long.class));
        }
    }

    private Optional<UUID> getComponentUuid(final PersistenceManager pm, final long componentId) throws Exception {
        try (final Query<?> query = pm.newQuery(Query.SQL, "SELECT \"UUID\" FROM \"COMPONENT\" WHERE \"ID\" = ?")) {
            query.setParameters(componentId);
            return Optional.ofNullable(query.executeResultUnique(String.class)).map(UUID::fromString);
        }
    }

    private List<VulnerabilityProjection> getVulnerabilities(final PersistenceManager pm, final long componentId) throws Exception {
        try (final Query<?> query = pm.newQuery(Query.SQL, "" +
                "SELECT " +
                "  \"VULNERABILITY\".\"SEVERITY\", " +
                "  \"VULNERABILITY\".\"CVSSV2BASESCORE\", " +
                "  \"VULNERABILITY\".\"CVSSV3BASESCORE\" " +
                "FROM \"COMPONENTS_VULNERABILITIES\" " +
                "  INNER JOIN \"COMPONENT\" ON \"COMPONENT\".\"ID\" = \"COMPONENTS_VULNERABILITIES\".\"COMPONENT_ID\" " +
                "  INNER JOIN \"VULNERABILITY\" ON \"VULNERABILITY\".\"ID\" = \"COMPONENTS_VULNERABILITIES\".\"VULNERABILITY_ID\" " +
                "  LEFT JOIN \"ANALYSIS\" " +
                "    ON \"ANALYSIS\".\"COMPONENT_ID\" = \"COMPONENTS_VULNERABILITIES\".\"COMPONENT_ID\" " +
                "    AND \"ANALYSIS\".\"VULNERABILITY_ID\" = \"COMPONENTS_VULNERABILITIES\".\"VULNERABILITY_ID\" " +
                "WHERE \"COMPONENTS_VULNERABILITIES\".\"COMPONENT_ID\" = ? " +
                "  AND (\"ANALYSIS\".\"SUPPRESSED\" IS NULL OR \"ANALYSIS\".\"SUPPRESSED\" = ?) " +
                "ORDER BY \"VULNERABILITY\".\"ID\"")) {
            query.setParameters(componentId, false);
            return List.copyOf(query.executeResultList(VulnerabilityProjection.class));
        }
    }

    private long getTotalAuditedFindings(final PersistenceManager pm, final long componentId) throws Exception {
        try (final Query<?> query = pm.newQuery(Query.SQL, "" +
                "SELECT COUNT(*) FROM \"ANALYSIS\" " +
                "WHERE \"COMPONENT_ID\" = ? " +
                "  AND \"SUPPRESSED\" = ? " +
                "  AND \"STATE\" IS NOT NULL " +
                "  AND \"STATE\" != ? " +
                "  AND \"STATE\" != ?")) {
            query.setParameters(componentId, false,
                    AnalysisState.NOT_SET.name(),
                    AnalysisState.IN_TRIAGE.name());
            return query.executeResultUnique(Long.class);
        }
    }

    private long getTotalSuppressedFindings(final PersistenceManager pm, final long componentId) throws Exception {
        try (final Query<?> query = pm.newQuery(Query.SQL, "" +
                "SELECT COUNT(*) FROM \"ANALYSIS\" " +
                "WHERE \"COMPONENT_ID\" = ? " +
                "  AND \"SUPPRESSED\" = ?")) {
            query.setParameters(componentId, true);
            return query.executeResultUnique(Long.class);
        }
    }

    private List<PolicyViolationProjection> getPolicyViolations(final PersistenceManager pm, final long componentId) throws Exception {
        try (final Query<?> query = pm.newQuery(Query.SQL, "" +
                "SELECT \"POLICYVIOLATION\".\"TYPE\", \"POLICY\".\"VIOLATIONSTATE\" " +
                "FROM \"POLICYVIOLATION\" " +
                "  INNER JOIN \"POLICYCONDITION\" ON \"POLICYCONDITION\".\"ID\" = \"POLICYVIOLATION\".\"POLICYCONDITION_ID\" " +
                "  INNER JOIN \"POLICY\" ON \"POLICY\".\"ID\" = \"POLICYCONDITION\".\"POLICY_ID\" " +
                "  LEFT JOIN \"VIOLATIONANALYSIS\" " +
                "    ON \"VIOLATIONANALYSIS\".\"COMPONENT_ID\" = \"POLICYVIOLATION\".\"COMPONENT_ID\" " +
                "    AND \"VIOLATIONANALYSIS\".\"POLICYVIOLATION_ID\" = \"POLICYVIOLATION\".\"ID\" " +
                "WHERE \"POLICYVIOLATION\".\"COMPONENT_ID\" = ? " +
                "  AND (\"VIOLATIONANALYSIS\".\"SUPPRESSED\" IS NULL OR \"VIOLATIONANALYSIS\".\"SUPPRESSED\" = ?)")) {
            query.setParameters(componentId, false);
            return List.copyOf(query.executeResultList(PolicyViolationProjection.class));
        }
    }

    private long getTotalAuditedPolicyViolations(final PersistenceManager pm, final long componentId, final PolicyViolation.Type violationType) throws Exception {
        try (final Query<?> query = pm.newQuery(Query.SQL, "" +
                "SELECT COUNT(*) FROM \"VIOLATIONANALYSIS\" " +
                "  INNER JOIN \"POLICYVIOLATION\" ON \"POLICYVIOLATION\".\"ID\" = \"VIOLATIONANALYSIS\".\"POLICYVIOLATION_ID\" " +
                "WHERE \"VIOLATIONANALYSIS\".\"COMPONENT_ID\" = ? " +
                "  AND \"POLICYVIOLATION\".\"TYPE\" = ? " +
                "  AND \"VIOLATIONANALYSIS\".\"SUPPRESSED\" = ? " +
                "  AND \"VIOLATIONANALYSIS\".\"STATE\" IS NOT NULL " +
                "  AND \"VIOLATIONANALYSIS\".\"STATE\" != ?")) {
            query.setParameters(componentId, violationType.name(),
                    false, ViolationAnalysisState.NOT_SET.name());
            return query.executeResultUnique(Long.class);
        }
    }

    /**
     * Fetch {@link VulnerabilityDateProjection}s in pages of {@code 500}.
     * <p>
     * In order to not load multiple thousands of objects at once, paging is used.
     * The first call should provide a {@code lastId} of {@code 0}, subsequent calls
     * are expected to provide the highest ID of the previously fetched page.
     *
     * @param pm     The {@link  PersistenceManager} to use
     * @param lastId Highest ID of the previously fetched page
     * @return Up to {@code 500} {@link VulnerabilityDateProjection} objects
     * @throws Exception If the query could not be closed
     */
    private List<VulnerabilityDateProjection> getVulnerabilityDates(final PersistenceManager pm, final long lastId) throws Exception {
        try (final Query<?> query = pm.newQuery(org.dependencytrack.model.Vulnerability.class)) {
            query.setFilter("id > :lastId");
            query.setOrdering("id ASC");
            query.setParameters(lastId);
            query.setResult("id, created, published");
            query.range(0, 500);
            return List.copyOf(query.executeResultList(VulnerabilityDateProjection.class));
        }
    }

    /**
     * Projection of a policy violation that holds the information
     * needed to calculate component metrics.
     * <p>
     * Class and setters must be public in order for DataNucleus to be
     * able to set the fields.
     *
     * @since 4.6.0
     */
    public static final class PolicyViolationProjection {
        private PolicyViolation.Type type;
        private Policy.ViolationState violationState;

        @SuppressWarnings("unused") // Called by DataNucleus
        public void setType(final String type) {
            this.type = PolicyViolation.Type.valueOf(type);
        }

        @SuppressWarnings("unused") // Called by DataNucleus
        public void setViolationState(final String violationState) {
            if (violationState != null) {
                this.violationState = Policy.ViolationState.valueOf(violationState);
            }
        }
    }

    /**
     * Projection of a vulnerability that contains the information
     * needed to calculate component metrics.
     * <p>
     * Class and setters must be public in order for DataNucleus to be
     * able to set the fields.
     *
     * @since 4.6.0
     */
    public static final class VulnerabilityProjection {
        private Severity severity;
        private BigDecimal cvssV2BaseScore;
        private BigDecimal cvssV3BaseScore;

        @SuppressWarnings("unused") // Called by DataNucleus
        public void setSeverity(final String severity) {
            if (severity != null) {
                this.severity = Severity.valueOf(severity);
            }
        }

        @SuppressWarnings("unused") // Called by DataNucleus
        public void setCvssV2BaseScore(final BigDecimal cvssV2BaseScore) {
            this.cvssV2BaseScore = cvssV2BaseScore;
        }

        @SuppressWarnings("unused") // Called by DataNucleus
        public void setCvssV3BaseScore(final BigDecimal cvssV3BaseScore) {
            this.cvssV3BaseScore = cvssV3BaseScore;
        }
    }

    /**
     * Projection of a vulnerability that holds the information
     * needed to calculate vulnerabilities metrics.
     * <p>
     * Class and setters must be public in order for DataNucleus to be
     * able to set the fields.
     *
     * @since 4.6.0
     */
    public static final class VulnerabilityDateProjection {
        private long id;
        private Date created;
        private Date published;

        @SuppressWarnings("unused") // Called by DataNucleus
        public void setId(final long id) {
            this.id = id;
        }

        @SuppressWarnings("unused") // Called by DataNucleus
        public void setCreated(final Date created) {
            this.created = created;
        }

        @SuppressWarnings("unused") // Called by DataNucleus
        public void setPublished(final Date published) {
            this.published = published;
        }
    }

    private static final class Counters {
        private int critical, high, medium, low, unassigned;
        private double inheritedRiskScore;
        private int components, vulnerableComponents, projects, vulnerableProjects;
        private int vulnerabilities, suppressions, findingsTotal, findingsAudited, findingsUnaudited;
        private int policyViolationsFail, policyViolationsWarn, policyViolationsInfo,
                policyViolationsTotal, policyViolationsAudited, policyViolationsUnaudited,
                policyViolationsSecurityTotal, policyViolationsSecurityAudited, policyViolationsSecurityUnaudited,
                policyViolationsLicenseTotal, policyViolationsLicenseAudited, policyViolationsLicenseUnaudited,
                policyViolationsOperationalTotal, policyViolationsOperationalAudited, policyViolationsOperationalUnaudited;
        private final Date measuredAt;

        private Counters() {
            this.measuredAt = new Date();
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
