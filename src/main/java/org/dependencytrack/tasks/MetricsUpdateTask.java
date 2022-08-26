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
import alpine.common.util.SystemUtil;
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
import org.dependencytrack.model.Vulnerability;
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
        if (e instanceof final MetricsUpdateEvent event) {
            LOGGER.debug("Starting metrics update task");
            try {
                if (MetricsUpdateEvent.Type.PORTFOLIO == event.getType()) {
                    updatePortfolioMetrics();
                } else if (MetricsUpdateEvent.Type.PROJECT == event.getType()) {
                    updateProjectMetrics((Project) event.getTarget());
                } else if (MetricsUpdateEvent.Type.COMPONENT == event.getType()) {
                    updateComponentMetrics((Component) event.getTarget());
                } else if (MetricsUpdateEvent.Type.VULNERABILITY == event.getType()) {
                    updateVulnerabilityMetrics();
                }
            } catch (Exception ex) {
                LOGGER.error("An unknown error occurred while updating metrics", ex);
            }
            LOGGER.debug("Metrics update complete");
        }
    }

    /**
     * Performs high-level metric updates on the portfolio.
     * <p>
     * Portfolio metrics are the aggregate of all project metrics.
     * <p>
     * A forced refresh of all project metrics is performed by dispatching a {@link MetricsUpdateEvent}
     * for each project in the portfolio. This is done in batches of size equal to the number of CPU cores,
     * as a means of applying back-pressure and not clogging the event bus.
     */
    private void updatePortfolioMetrics() throws Exception {
        LOGGER.info("Executing portfolio metrics update");
        final var counters = new Counters();

        // The amount of projects to calculate metrics for concurrently.
        // This should be low enough to not clog the event bus, and high
        // enough to provide a benefit of faster metrics updates.
        //
        // There's also point of diminishing returns when it comes to concurrency.
        // The database can only handle SO MUCH. At some point, more work in parallel
        // will just cause each unit of work to take more time.
        // CPU core count seems to be a nice middle ground for most systems.
        final long batchSize = SystemUtil.getCpuCores();

        try (final var qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();

            LOGGER.trace("Fetching first " + batchSize + " projects");
            List<Project> activeProjects = getActiveProjects(pm, batchSize, 0);

            while (!activeProjects.isEmpty()) {
                final long firstId = activeProjects.get(0).getId();
                final long lastId = activeProjects.get(activeProjects.size() - 1).getId();
                final int batchCount = activeProjects.size();

                final var countDownLatch = new CountDownLatch(batchCount);

                for (final Project project : activeProjects) {
                    final var eventProject = new Project();
                    eventProject.setId(project.getId());
                    eventProject.setUuid(project.getUuid());

                    LOGGER.debug("Dispatching metrics update event for project " + project.getUuid());
                    final var callbackEvent = new CallbackEvent(countDownLatch::countDown);
                    Event.dispatch(new MetricsUpdateEvent(eventProject)
                            .onSuccess(callbackEvent)
                            .onFailure(callbackEvent));
                }

                LOGGER.debug("Waiting for metrics updates for projects " + firstId + "-" + lastId + " to complete");
                if (!countDownLatch.await(30, TimeUnit.MINUTES)) {
                    // Depending on the system load, it may take a while for the queued events
                    // to be processed. Depending on how large the projects are, it may take a
                    // while for the processing of the respective event to complete.
                    // It is unlikely though that either of these situations causes a block for
                    // over 30 minutes.
                    LOGGER.warn("Updating metrics for projects " + firstId + "-" + lastId +
                            " took longer than expected (30m); Proceeding with potentially stale data");
                }
                LOGGER.debug("Completed metrics updates for projects " + firstId + "-" + lastId);

                for (final Project project : activeProjects) {
                    LOGGER.debug("Processing latest metrics for project " + project.getUuid());
                    try (final Query<ProjectMetrics> query = pm.newQuery(ProjectMetrics.class)) {
                        query.setFilter("project.id == :projectId");
                        query.setOrdering("lastOccurrence desc");
                        query.setParameters(project.getId());
                        query.setRange(0, 1);

                        final ProjectMetrics metrics = query.executeUnique();
                        if (metrics == null) {
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
                }

                LOGGER.trace("Fetching next " + batchSize + " projects");
                activeProjects = getActiveProjects(pm, batchSize, lastId);
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
     * @param project {@link Project} of the project to update metrics for
     */
    private void updateProjectMetrics(final Project project) throws Exception {
        final var counters = new Counters();

        try (final QueryManager qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();

            LOGGER.trace("Fetching first components page for project " + project.getUuid());
            List<Component> components = getComponents(pm, project, 0);

            while (!components.isEmpty()) {
                for (final Component component : components) {
                    final Counters componentCounters;
                    try {
                        componentCounters = updateComponentMetrics(component);
                    } catch (Exception e) {
                        LOGGER.error("An unexpected error occurred while updating metrics of component " + component.getUuid(), e);
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

                LOGGER.trace("Fetching next components page for project " + project.getUuid());
                components = getComponents(pm, project, components.get(components.size() - 1).getId());
            }
        }

        try (final var qm = new QueryManager()) {
            final Project actualProject = qm.getObjectById(Project.class, project.getId());

            Transaction trx = qm.getPersistenceManager().currentTransaction();
            try {
                trx.begin();
                final ProjectMetrics latestMetrics = qm.getMostRecentProjectMetrics(actualProject);
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
                    LOGGER.debug("Metrics of project " + project.getUuid() + " did not change");
                    latestMetrics.setLastOccurrence(counters.measuredAt);
                } else {
                    LOGGER.debug("Metrics of project " + project.getUuid() + " changed");
                    final var metrics = new ProjectMetrics();
                    metrics.setProject(actualProject);
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

            if (actualProject.getLastInheritedRiskScore() == null ||
                    actualProject.getLastInheritedRiskScore() != counters.inheritedRiskScore) {
                LOGGER.debug("Updating inherited risk score of project " + project.getUuid());
                trx = qm.getPersistenceManager().currentTransaction();
                try {
                    trx.begin();
                    actualProject.setLastInheritedRiskScore(counters.inheritedRiskScore);
                    trx.commit();
                } finally {
                    if (trx.isActive()) {
                        trx.rollback();
                    }
                }
            }
        }

        LOGGER.info("Completed metrics update for project " + project.getUuid() + " in " +
                DurationFormatUtils.formatDuration(new Date().getTime() - counters.measuredAt.getTime(), "mm:ss:SS"));
    }

    /**
     * Perform metric updates on a specific component.
     *
     * @param component ID of the component to update metrics for
     * @return A {@link Counters} instance resembling the calculated metrics
     */
    private Counters updateComponentMetrics(final Component component) throws Exception {
        final var counters = new Counters();

        try (final PersistenceManager pm = PersistenceManagerFactory.createPersistenceManager()) {
            for (final VulnerabilityProjection vulnerability : getVulnerabilities(pm, component)) {
                counters.vulnerabilities++;

                // Replicate the behavior of Vulnerability#getSeverity
                final Severity severity;
                if (vulnerability.severity != null) {
                    severity = Severity.valueOf(vulnerability.severity);
                } else {
                    severity = VulnerabilityUtil.getSeverity(vulnerability.cvssV2BaseScore, vulnerability.cvssV3BaseScore);
                }

                switch (severity) {
                    case CRITICAL -> counters.critical++;
                    case HIGH -> counters.high++;
                    case MEDIUM -> counters.medium++;
                    case LOW, INFO -> counters.low++;
                    case UNASSIGNED -> counters.unassigned++;
                }
            }
            counters.findingsTotal = toIntExact(counters.vulnerabilities);
            counters.findingsAudited = toIntExact(getTotalAuditedFindings(pm, component));
            counters.findingsUnaudited = counters.findingsTotal - counters.findingsAudited;
            counters.suppressions = toIntExact(getTotalSuppressedFindings(pm, component));
            counters.inheritedRiskScore = Metrics.inheritedRiskScore(counters.critical, counters.high, counters.medium, counters.low, counters.unassigned);

            for (final PolicyViolationProjection violation : getPolicyViolations(pm, component)) {
                counters.policyViolationsTotal++;

                switch (PolicyViolation.Type.valueOf(violation.type)) {
                    case LICENSE -> counters.policyViolationsLicenseTotal++;
                    case OPERATIONAL -> counters.policyViolationsOperationalTotal++;
                    case SECURITY -> counters.policyViolationsSecurityTotal++;
                }

                switch (Policy.ViolationState.valueOf(violation.violationState)) {
                    case FAIL -> counters.policyViolationsFail++;
                    case WARN -> counters.policyViolationsWarn++;
                    case INFO -> counters.policyViolationsInfo++;
                }
            }
            if (counters.policyViolationsLicenseTotal > 0) {
                counters.policyViolationsLicenseAudited = toIntExact(getTotalAuditedPolicyViolations(pm, component, PolicyViolation.Type.LICENSE));
                counters.policyViolationsLicenseUnaudited = counters.policyViolationsLicenseTotal - counters.policyViolationsLicenseAudited;
            }
            if (counters.policyViolationsOperationalTotal > 0) {
                counters.policyViolationsOperationalAudited = toIntExact(getTotalAuditedPolicyViolations(pm, component, PolicyViolation.Type.OPERATIONAL));
                counters.policyViolationsOperationalUnaudited = counters.policyViolationsOperationalTotal - counters.policyViolationsOperationalAudited;
            }
            if (counters.policyViolationsSecurityTotal > 0) {
                counters.policyViolationsSecurityAudited = toIntExact(getTotalAuditedPolicyViolations(pm, component, PolicyViolation.Type.SECURITY));
                counters.policyViolationsSecurityUnaudited = counters.policyViolationsSecurityTotal - counters.policyViolationsSecurityAudited;
            }
            counters.policyViolationsAudited = counters.policyViolationsLicenseAudited +
                    counters.policyViolationsOperationalAudited +
                    counters.policyViolationsSecurityAudited;
            counters.policyViolationsUnaudited = counters.policyViolationsTotal - counters.policyViolationsAudited;
        }

        try (final var qm = new QueryManager()) {
            final Component actualComponent = qm.getObjectById(Component.class, component.getId());

            Transaction trx = qm.getPersistenceManager().currentTransaction();
            try {
                trx.begin();
                final DependencyMetrics latestMetrics = qm.getMostRecentDependencyMetrics(actualComponent);
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
                    LOGGER.debug("Metrics of component " + component.getUuid() + " did not change");
                    latestMetrics.setLastOccurrence(counters.measuredAt);
                } else {
                    LOGGER.debug("Metrics of component " + component.getUuid() + " changed");
                    final var metrics = new DependencyMetrics();
                    metrics.setComponent(actualComponent);
                    metrics.setProject(actualComponent.getProject());
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

            if (actualComponent.getLastInheritedRiskScore() == null ||
                    actualComponent.getLastInheritedRiskScore() != counters.inheritedRiskScore) {
                LOGGER.debug("Updating inherited risk score of component " + component.getUuid());
                trx = qm.getPersistenceManager().currentTransaction();
                try {
                    trx.begin();
                    actualComponent.setLastInheritedRiskScore(counters.inheritedRiskScore);
                    trx.commit();
                } finally {
                    if (trx.isActive()) {
                        trx.rollback();
                    }
                }
            }
        }

        LOGGER.debug("Completed metrics update for component " + component.getUuid() + " in " +
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
     * Fetch {@link Project}s of active projects in pages of {@code limit}.
     * <p>
     * Note: JDOQL instead of raw SQL is used, because LIMIT X / FETCH FIRST X ROWS ONLY clauses
     * are implemented differently across RDBMS. DataNucleus will choose the correct clause for us.
     *
     * @param pm     The {@link  PersistenceManager} to use
     * @param limit  Maximum number of IDs to fetch
     * @param lastId Highest ID of the previously fetched page
     * @return Up to {@code limit} {@link Project}s
     * @throws Exception If the query could not be closed
     */
    private List<Project> getActiveProjects(final PersistenceManager pm, final long limit, final long lastId) throws Exception {
        try (final Query<?> query = pm.newQuery(Project.class)) {
            query.setFilter("id > :lastId");
            query.setOrdering("id asc");
            query.setParameters(lastId);
            query.setResult("id, uuid");
            query.range(0, limit);
            return List.copyOf(query.executeResultList(Project.class));
        }
    }

    /**
     * Fetch {@link Component}s of a given {@link Project}s in pages of {@code 500}.
     * <p>
     * Note: JDOQL instead of raw SQL is used, because LIMIT X / FETCH FIRST X ROWS ONLY clauses
     * are implemented differently across RDBMS. DataNucleus will choose the correct clause for us.
     *
     * @param pm      The {@link  PersistenceManager} to use
     * @param project The {@link Project} to fetch {@link Component}s for
     * @param lastId  Highest ID of the previously fetched page
     * @return Up to {@code 500} {@link Component}s
     * @throws Exception If the query could not be closed
     */
    private List<Component> getComponents(final PersistenceManager pm, final Project project, final long lastId) throws Exception {
        try (final Query<?> query = pm.newQuery(Component.class)) {
            query.setFilter("project.id == :projectId && id > :lastId");
            query.setOrdering("id asc");
            query.setParameters(project.getId(), lastId);
            query.setResult("id, uuid");
            query.range(0, 500);
            return List.copyOf(query.executeResultList(Component.class));
        }
    }

    private List<VulnerabilityProjection> getVulnerabilities(final PersistenceManager pm, final Component component) throws Exception {
        try (final Query<?> query = pm.newQuery(Query.SQL, """
                SELECT
                    "VULNERABILITY"."SEVERITY",
                    "VULNERABILITY"."CVSSV2BASESCORE",
                    "VULNERABILITY"."CVSSV3BASESCORE"
                FROM "COMPONENTS_VULNERABILITIES"
                    INNER JOIN "COMPONENT" ON "COMPONENT"."ID" = "COMPONENTS_VULNERABILITIES"."COMPONENT_ID"
                    INNER JOIN "VULNERABILITY" ON "VULNERABILITY"."ID" = "COMPONENTS_VULNERABILITIES"."VULNERABILITY_ID"
                    LEFT JOIN "ANALYSIS"
                        ON "ANALYSIS"."COMPONENT_ID" = "COMPONENTS_VULNERABILITIES"."COMPONENT_ID"
                        AND "ANALYSIS"."VULNERABILITY_ID" = "COMPONENTS_VULNERABILITIES"."VULNERABILITY_ID"
                WHERE "COMPONENTS_VULNERABILITIES"."COMPONENT_ID" = ?
                    AND ("ANALYSIS"."SUPPRESSED" IS NULL OR "ANALYSIS"."SUPPRESSED" = ?)
                ORDER BY "VULNERABILITY"."ID"
                """)) {
            query.setParameters(component.getId(), false);
            return List.copyOf(query.executeResultList(VulnerabilityProjection.class));
        }
    }

    private long getTotalAuditedFindings(final PersistenceManager pm, final Component component) throws Exception {
        try (final Query<?> query = pm.newQuery(Query.SQL, """
                SELECT COUNT(*) FROM "ANALYSIS"
                WHERE "COMPONENT_ID" = ?
                    AND "SUPPRESSED" = ?
                    AND "STATE" IS NOT NULL
                    AND "STATE" != ?
                    AND "STATE" != ?
                """)) {
            query.setParameters(component.getId(), false,
                    AnalysisState.NOT_SET.name(),
                    AnalysisState.IN_TRIAGE.name());
            return query.executeResultUnique(Long.class);
        }
    }

    private long getTotalSuppressedFindings(final PersistenceManager pm, final Component component) throws Exception {
        try (final Query<?> query = pm.newQuery(Query.SQL, """
                SELECT COUNT(*) FROM "ANALYSIS"
                WHERE "COMPONENT_ID" = ?
                    AND "SUPPRESSED" = ?
                """)) {
            query.setParameters(component.getId(), true);
            return query.executeResultUnique(Long.class);
        }
    }

    private List<PolicyViolationProjection> getPolicyViolations(final PersistenceManager pm, final Component component) throws Exception {
        try (final Query<?> query = pm.newQuery(Query.SQL, """
                SELECT "POLICYVIOLATION"."TYPE", "POLICY"."VIOLATIONSTATE"
                FROM "POLICYVIOLATION"
                    INNER JOIN "POLICYCONDITION" ON "POLICYCONDITION"."ID" = "POLICYVIOLATION"."POLICYCONDITION_ID"
                    INNER JOIN "POLICY" ON "POLICY"."ID" = "POLICYCONDITION"."POLICY_ID"
                    LEFT JOIN "VIOLATIONANALYSIS"
                        ON "VIOLATIONANALYSIS"."COMPONENT_ID" = "POLICYVIOLATION"."COMPONENT_ID"
                        AND "VIOLATIONANALYSIS"."POLICYVIOLATION_ID" = "POLICYVIOLATION"."ID"
                WHERE "POLICYVIOLATION"."COMPONENT_ID" = ?
                    AND ("VIOLATIONANALYSIS"."SUPPRESSED" IS NULL OR "VIOLATIONANALYSIS"."SUPPRESSED" = ?)
                """)) {
            query.setParameters(component.getId(), false);
            return List.copyOf(query.executeResultList(PolicyViolationProjection.class));
        }
    }

    private long getTotalAuditedPolicyViolations(final PersistenceManager pm, final Component component, final PolicyViolation.Type violationType) throws Exception {
        try (final Query<?> query = pm.newQuery(Query.SQL, """
                SELECT COUNT(*) FROM "VIOLATIONANALYSIS"
                    INNER JOIN "POLICYVIOLATION" ON "POLICYVIOLATION"."ID" = "VIOLATIONANALYSIS"."POLICYVIOLATION_ID"
                WHERE "VIOLATIONANALYSIS"."COMPONENT_ID" = ?
                    AND "POLICYVIOLATION"."TYPE" = ?
                    AND "VIOLATIONANALYSIS"."SUPPRESSED" = ?
                    AND "VIOLATIONANALYSIS"."STATE" IS NOT NULL
                    AND "VIOLATIONANALYSIS"."STATE" != ?
                """)) {
            query.setParameters(component.getId(), violationType.name(),
                    false, ViolationAnalysisState.NOT_SET.name());
            return query.executeResultUnique(Long.class);
        }
    }

    /**
     * Fetch {@link VulnerabilityDateProjection}s in pages of {@code 500}.
     * <p>
     * Note: JDOQL instead of raw SQL is used, because LIMIT X / FETCH FIRST X ROWS ONLY clauses
     * are implemented differently across RDBMS. DataNucleus will choose the correct clause for us.
     *
     * @param pm     The {@link  PersistenceManager} to use
     * @param lastId Highest ID of the previously fetched page
     * @return Up to {@code 500} {@link VulnerabilityDateProjection} objects
     * @throws Exception If the query could not be closed
     */
    private List<VulnerabilityDateProjection> getVulnerabilityDates(final PersistenceManager pm, final long lastId) throws Exception {
        try (final Query<?> query = pm.newQuery(Vulnerability.class)) {
            query.setFilter("id > :lastId");
            query.setOrdering("id ASC");
            query.setParameters(lastId);
            query.setResult("id, created, published");
            query.range(0, 500);
            return List.copyOf(query.executeResultList(VulnerabilityDateProjection.class));
        }
    }

    /**
     * Projection of a {@link PolicyViolation} that holds the information
     * needed to calculate component metrics.
     *
     * @since 4.6.0
     */
    public record PolicyViolationProjection(String type, String violationState) {
    }

    /**
     * Projection of a {@link Vulnerability} that contains the information
     * needed to calculate component metrics.
     *
     * @since 4.6.0
     */
    public record VulnerabilityProjection(String severity, BigDecimal cvssV2BaseScore, BigDecimal cvssV3BaseScore) {
    }

    /**
     * Projection of a {@link Vulnerability} that holds the information
     * needed to calculate vulnerabilities metrics.
     *
     * @since 4.6.0
     */
    public record VulnerabilityDateProjection(long id, Date created, Date published) {
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
