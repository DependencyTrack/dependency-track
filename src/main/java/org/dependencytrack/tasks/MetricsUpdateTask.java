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
import org.dependencytrack.event.MetricsUpdateEvent;
import org.dependencytrack.metrics.Metrics;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyViolation;
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
                } else if (MetricsUpdateEvent.Type.VULNERABILITY == event.getType()) {
                    updateVulnerabilitiesMetrics(qm);
                }
            } catch (Exception ex) {
                LOGGER.error("An unknown error occurred while updating metrics", ex);
            }
            LOGGER.debug("Metrics update complete");
        }
    }

    /**
     * Performs high-level metric updates on the portfolio.
     * @param qm a QueryManager instance
     */
    private void updatePortfolioMetrics(final QueryManager qm) {
        LOGGER.info("Executing portfolio metrics update");
        final Date measuredAt = new Date();

        // Retrieve list of all ACTIVE projects
        final List<Project> projects = qm.getAllProjects(true);
        LOGGER.debug("Portfolio metrics will include " + projects.size() + " active projects");

        // Setup metrics
        final MetricCounters portfolioCounters = new MetricCounters();
        final List<MetricCounters> projectCountersList = new ArrayList<>();

        // Iterate through all projects
        LOGGER.debug("Iterating through active projects");
        for (final Project project: projects) {
            try {
                // Update the projects metrics
                final MetricCounters projectMetrics = updateProjectMetrics(qm, project.getId());
                projectCountersList.add(projectMetrics);
            } catch (Exception e) {
                LOGGER.error("An unexpected error occurred while updating portfolio metrics and iterating through projects. The error occurred while updating metrics for project: " + project.getUuid().toString(), e);
            }
        }

        LOGGER.debug("Project iteration complete. Iterating through all project metrics");
        // Iterate through the metrics from all project
        for (final MetricCounters projectMetrics: projectCountersList) {
            // Add individual project metrics to the overall portfolio metrics
            portfolioCounters.projects++;
            portfolioCounters.critical += projectMetrics.critical;
            portfolioCounters.high += projectMetrics.high;
            portfolioCounters.medium += projectMetrics.medium;
            portfolioCounters.low += projectMetrics.low;
            portfolioCounters.unassigned += projectMetrics.unassigned;

            // All vulnerabilities
            portfolioCounters.vulnerabilities += projectMetrics.severitySum();

            // Only vulnerable projects
            if (projectMetrics.severitySum() > 0) {
                portfolioCounters.vulnerableProjects++;
            }
            portfolioCounters.vulnerableComponents += projectMetrics.vulnerableComponents;

            // Policy violations
            portfolioCounters.policyViolationsFail += projectMetrics.policyViolationsFail;
            portfolioCounters.policyViolationsWarn += projectMetrics.policyViolationsWarn;
            portfolioCounters.policyViolationsInfo += projectMetrics.policyViolationsInfo;
            portfolioCounters.policyViolationsTotal += projectMetrics.policyViolationsTotal;
            portfolioCounters.policyViolationsAudited += projectMetrics.policyViolationsAudited;
            portfolioCounters.policyViolationsUnaudited += projectMetrics.policyViolationsUnaudited;
            portfolioCounters.policyViolationsSecurityTotal += projectMetrics.policyViolationsSecurityTotal;
            portfolioCounters.policyViolationsSecurityAudited += projectMetrics.policyViolationsSecurityAudited;
            portfolioCounters.policyViolationsSecurityUnaudited += projectMetrics.policyViolationsSecurityUnaudited;
            portfolioCounters.policyViolationsLicenseTotal += projectMetrics.policyViolationsLicenseTotal;
            portfolioCounters.policyViolationsLicenseAudited += projectMetrics.policyViolationsLicenseAudited;
            portfolioCounters.policyViolationsLicenseUnaudited += projectMetrics.policyViolationsLicenseUnaudited;
            portfolioCounters.policyViolationsOperationalTotal += projectMetrics.policyViolationsOperationalTotal;
            portfolioCounters.policyViolationsOperationalAudited += projectMetrics.policyViolationsOperationalAudited;
            portfolioCounters.policyViolationsOperationalUnaudited += projectMetrics.policyViolationsOperationalUnaudited;
        }
        LOGGER.debug("Project metric iteration complete");
        LOGGER.debug("Retrieving total suppression count for portfolio");

        // Total number of components
        portfolioCounters.components += toIntExact(qm.getCount(Component.class));

        // Total number of suppressions regardless if they are dependencies or components not associated to a project
        portfolioCounters.suppressions = toIntExact(qm.getSuppressedCount());

        // For the time being finding and vulnerability counts are the same.
        // However, vulns may be defined as 'confirmed' in a future release.
        portfolioCounters.findingsTotal = portfolioCounters.severitySum();
        portfolioCounters.findingsAudited = toIntExact(qm.getAuditedCount());
        portfolioCounters.findingsUnaudited = portfolioCounters.findingsTotal - portfolioCounters.findingsAudited;

        // Query for an existing PortfolioMetrics
        final PortfolioMetrics last = qm.getMostRecentPortfolioMetrics();
        if (last != null
                && last.getCritical() == portfolioCounters.critical
                && last.getHigh() == portfolioCounters.high
                && last.getMedium() == portfolioCounters.medium
                && last.getLow() == portfolioCounters.low
                && last.getUnassigned() == portfolioCounters.unassigned
                && last.getVulnerabilities() == portfolioCounters.vulnerabilities
                && last.getInheritedRiskScore() == portfolioCounters.getInheritedRiskScore()
                && last.getPolicyViolationsFail() == portfolioCounters.policyViolationsFail
                && last.getPolicyViolationsWarn() == portfolioCounters.policyViolationsWarn
                && last.getPolicyViolationsInfo() == portfolioCounters.policyViolationsInfo
                && last.getPolicyViolationsTotal() == portfolioCounters.policyViolationsTotal
                && last.getPolicyViolationsAudited() == portfolioCounters.policyViolationsAudited
                && last.getPolicyViolationsUnaudited() == portfolioCounters.policyViolationsUnaudited
                && last.getPolicyViolationsSecurityTotal() == portfolioCounters.policyViolationsSecurityTotal
                && last.getPolicyViolationsSecurityAudited() == portfolioCounters.policyViolationsSecurityAudited
                && last.getPolicyViolationsSecurityUnaudited() == portfolioCounters.policyViolationsSecurityUnaudited
                && last.getPolicyViolationsLicenseTotal() == portfolioCounters.policyViolationsLicenseTotal
                && last.getPolicyViolationsLicenseAudited() == portfolioCounters.policyViolationsLicenseAudited
                && last.getPolicyViolationsLicenseUnaudited() == portfolioCounters.policyViolationsLicenseUnaudited
                && last.getPolicyViolationsOperationalTotal() == portfolioCounters.policyViolationsOperationalTotal
                && last.getPolicyViolationsOperationalAudited() == portfolioCounters.policyViolationsOperationalAudited
                && last.getPolicyViolationsOperationalUnaudited() == portfolioCounters.policyViolationsOperationalUnaudited
                && last.getComponents() == portfolioCounters.components
                && last.getVulnerableComponents() == portfolioCounters.vulnerableComponents
                && last.getSuppressed() == portfolioCounters.suppressions
                && last.getFindingsTotal() == portfolioCounters.findingsTotal
                && last.getFindingsAudited() == portfolioCounters.findingsAudited
                && last.getFindingsUnaudited() == portfolioCounters.findingsUnaudited
                && last.getProjects() == portfolioCounters.projects
                && last.getVulnerableProjects() == portfolioCounters.vulnerableProjects) {

            LOGGER.debug("Portfolio Metrics unchanged. Updating last occurrence");
            // Matches... Update the last occurrence timestamp instead of creating a new record with the same info
            last.setLastOccurrence(measuredAt);
            LOGGER.debug("Persisting portfolio metrics");
            qm.persist(last);
        } else {
            LOGGER.debug("Portfolio metrics have changed (or were never previously measured)");
            final PortfolioMetrics portfolioMetrics = new PortfolioMetrics();
            portfolioMetrics.setCritical(portfolioCounters.critical);
            portfolioMetrics.setHigh(portfolioCounters.high);
            portfolioMetrics.setMedium(portfolioCounters.medium);
            portfolioMetrics.setLow(portfolioCounters.low);
            portfolioMetrics.setUnassigned(portfolioCounters.unassigned);
            portfolioMetrics.setVulnerabilities(portfolioCounters.vulnerabilities);
            portfolioMetrics.setComponents(portfolioCounters.components);
            portfolioMetrics.setVulnerableComponents(portfolioCounters.vulnerableComponents);
            portfolioMetrics.setSuppressed(portfolioCounters.suppressions);
            portfolioMetrics.setFindingsTotal(portfolioCounters.findingsTotal);
            portfolioMetrics.setFindingsAudited(portfolioCounters.findingsAudited);
            portfolioMetrics.setFindingsUnaudited(portfolioCounters.findingsUnaudited);
            portfolioMetrics.setProjects(portfolioCounters.projects);
            portfolioMetrics.setVulnerableProjects(portfolioCounters.vulnerableProjects);
            portfolioMetrics.setInheritedRiskScore(
                    Metrics.inheritedRiskScore(
                            portfolioCounters.critical,
                            portfolioCounters.high,
                            portfolioCounters.medium,
                            portfolioCounters.low,
                            portfolioCounters.unassigned)
            );
            portfolioMetrics.setPolicyViolationsFail(portfolioCounters.policyViolationsFail);
            portfolioMetrics.setPolicyViolationsWarn(portfolioCounters.policyViolationsWarn);
            portfolioMetrics.setPolicyViolationsInfo(portfolioCounters.policyViolationsInfo);
            portfolioMetrics.setPolicyViolationsTotal(portfolioCounters.policyViolationsTotal);
            portfolioMetrics.setPolicyViolationsAudited(portfolioCounters.policyViolationsAudited);
            portfolioMetrics.setPolicyViolationsUnaudited(portfolioCounters.policyViolationsUnaudited);
            portfolioMetrics.setPolicyViolationsSecurityTotal(portfolioCounters.policyViolationsSecurityTotal);
            portfolioMetrics.setPolicyViolationsSecurityAudited(portfolioCounters.policyViolationsSecurityAudited);
            portfolioMetrics.setPolicyViolationsSecurityUnaudited(portfolioCounters.policyViolationsSecurityUnaudited);
            portfolioMetrics.setPolicyViolationsLicenseTotal(portfolioCounters.policyViolationsLicenseTotal);
            portfolioMetrics.setPolicyViolationsLicenseAudited(portfolioCounters.policyViolationsLicenseAudited);
            portfolioMetrics.setPolicyViolationsLicenseUnaudited(portfolioCounters.policyViolationsLicenseUnaudited);
            portfolioMetrics.setPolicyViolationsOperationalTotal(portfolioCounters.policyViolationsOperationalTotal);
            portfolioMetrics.setPolicyViolationsOperationalAudited(portfolioCounters.policyViolationsOperationalAudited);
            portfolioMetrics.setPolicyViolationsOperationalUnaudited(portfolioCounters.policyViolationsOperationalUnaudited);
            portfolioMetrics.setFirstOccurrence(measuredAt);
            portfolioMetrics.setLastOccurrence(measuredAt);
            LOGGER.debug("Persisting portfolio metrics");
            qm.persist(portfolioMetrics);
        }
        LOGGER.info("Completed portfolio metrics update");
    }

    /**
     * Performs metric updates on a specific project.
     * @param qm a QueryManager instance
     * @param oid the object ID of the project
     * @return MetricCounters
     */
    private MetricCounters updateProjectMetrics(final QueryManager qm, final long oid) {
        final Project project = qm.getObjectById(Project.class, oid);
        LOGGER.info("Executing metrics update for project: " + project.getUuid());
        final Date measuredAt = new Date();

        final MetricCounters counters = new MetricCounters();

        // Holds the metrics returned from all components that are dependencies of the project
        final List<MetricCounters> countersList = new ArrayList<>();

        // Retrieve all components for the project
        LOGGER.debug("Retrieving all components for project: " + project.getUuid());
        final List<Component> components = qm.getAllComponents(project);
        LOGGER.debug("Project metrics will include " + components.size() + " components");

        LOGGER.debug("Iterating through dependencies");
        // Iterate through all dependencies
        for (final Component component: components) {
            try {
                // Update the component metrics
                final MetricCounters componentMetrics = updateComponentMetrics(qm, component.getId());
                // Adds the metrics from the component to the list of metrics for the project
                countersList.add(componentMetrics);
            } catch (Exception e) {
                LOGGER.error("An unexpected error occurred while updating project metrics and iterating through components. The error occurred while updating metrics for project: " + project.getUuid().toString() + " and component: " + component.getUuid().toString(), e);
            }
        }
        LOGGER.debug("Component iteration complete");

        // Iterate through the metrics from all components that are dependencies of the project
        for (final MetricCounters depMetric: countersList) {
            // Add individual component metrics to the overall project metrics
            counters.components++;
            counters.critical += depMetric.critical;
            counters.high += depMetric.high;
            counters.medium += depMetric.medium;
            counters.low += depMetric.low;
            counters.unassigned += depMetric.unassigned;
            counters.vulnerabilities += depMetric.severitySum();

            if (depMetric.severitySum() > 0) {
                counters.vulnerableComponents++;
            }
            counters.policyViolationsFail += depMetric.policyViolationsFail;
            counters.policyViolationsWarn += depMetric.policyViolationsWarn;
            counters.policyViolationsInfo += depMetric.policyViolationsInfo;
            counters.policyViolationsTotal += depMetric.policyViolationsTotal;
            counters.policyViolationsAudited += depMetric.policyViolationsAudited;
            counters.policyViolationsUnaudited += depMetric.policyViolationsUnaudited;
            counters.policyViolationsSecurityTotal += depMetric.policyViolationsSecurityTotal;
            counters.policyViolationsSecurityAudited += depMetric.policyViolationsSecurityAudited;
            counters.policyViolationsSecurityUnaudited += depMetric.policyViolationsSecurityUnaudited;
            counters.policyViolationsLicenseTotal += depMetric.policyViolationsLicenseTotal;
            counters.policyViolationsLicenseAudited += depMetric.policyViolationsLicenseAudited;
            counters.policyViolationsLicenseUnaudited += depMetric.policyViolationsLicenseUnaudited;
            counters.policyViolationsOperationalTotal += depMetric.policyViolationsOperationalTotal;
            counters.policyViolationsOperationalAudited += depMetric.policyViolationsOperationalAudited;
            counters.policyViolationsOperationalUnaudited += depMetric.policyViolationsOperationalUnaudited;
        }

        // For the time being finding and vulnerability counts are the same.
        // However, vulns may be defined as 'confirmed' in a future release.
        counters.findingsTotal = counters.severitySum();
        LOGGER.debug("Retrieving existing audited count for project: " + project.getUuid());
        counters.findingsAudited = toIntExact(qm.getAuditedCount(project));
        counters.findingsUnaudited = counters.findingsTotal - counters.findingsAudited;

        LOGGER.debug("Retrieving existing suppression count for project: " + project.getUuid());
        counters.suppressions = toIntExact(qm.getSuppressedCount(project));

        // Query for an existing ProjectMetrics
        final ProjectMetrics last = qm.getMostRecentProjectMetrics(project);
        if (last != null
                && last.getCritical() == counters.critical
                && last.getHigh() == counters.high
                && last.getMedium() == counters.medium
                && last.getLow() == counters.low
                && last.getUnassigned() == counters.unassigned
                && last.getVulnerabilities() == counters.vulnerabilities
                && last.getSuppressed() == counters.suppressions
                && last.getFindingsTotal() == counters.findingsTotal
                && last.getFindingsAudited() == counters.findingsAudited
                && last.getFindingsUnaudited() == counters.findingsUnaudited
                && last.getInheritedRiskScore() == counters.getInheritedRiskScore()
                && last.getPolicyViolationsFail() == counters.policyViolationsFail
                && last.getPolicyViolationsWarn() == counters.policyViolationsWarn
                && last.getPolicyViolationsInfo() == counters.policyViolationsInfo
                && last.getPolicyViolationsTotal() == counters.policyViolationsTotal
                && last.getPolicyViolationsAudited() == counters.policyViolationsAudited
                && last.getPolicyViolationsUnaudited() == counters.policyViolationsUnaudited
                && last.getPolicyViolationsSecurityTotal() == counters.policyViolationsSecurityTotal
                && last.getPolicyViolationsSecurityAudited() == counters.policyViolationsSecurityAudited
                && last.getPolicyViolationsSecurityUnaudited() == counters.policyViolationsSecurityUnaudited
                && last.getPolicyViolationsLicenseTotal() == counters.policyViolationsLicenseTotal
                && last.getPolicyViolationsLicenseAudited() == counters.policyViolationsLicenseAudited
                && last.getPolicyViolationsLicenseUnaudited() == counters.policyViolationsLicenseUnaudited
                && last.getPolicyViolationsOperationalTotal() == counters.policyViolationsOperationalTotal
                && last.getPolicyViolationsOperationalAudited() == counters.policyViolationsOperationalAudited
                && last.getPolicyViolationsOperationalUnaudited() == counters.policyViolationsOperationalUnaudited
                && last.getComponents() == counters.components
                && last.getVulnerableComponents() == counters.vulnerableComponents) {

            LOGGER.debug("Metrics are unchanged for project: " + project.getUuid() + ". Updating last occurrence");
            // Matches... Update the last occurrence timestamp instead of creating a new record with the same info
            last.setLastOccurrence(measuredAt);
            LOGGER.debug("Persisting metrics for project: " + project.getUuid());
            qm.persist(last);
            LOGGER.debug("Updating Inherited Risk Score for project: " + project.getUuid());
            // Update the convenience fields in the Project object
            project.setLastInheritedRiskScore(last.getInheritedRiskScore());
            LOGGER.debug("Persisting metrics for project: " + project.getUuid());
            qm.persist(project);
        } else {
            LOGGER.debug("Metrics have changed (or were never previously measured) for project: " + project.getUuid());
            final ProjectMetrics projectMetrics = new ProjectMetrics();
            projectMetrics.setProject(project);
            projectMetrics.setCritical(counters.critical);
            projectMetrics.setHigh(counters.high);
            projectMetrics.setMedium(counters.medium);
            projectMetrics.setLow(counters.low);
            projectMetrics.setUnassigned(counters.unassigned);
            projectMetrics.setVulnerabilities(counters.vulnerabilities);
            projectMetrics.setComponents(counters.components);
            projectMetrics.setVulnerableComponents(counters.vulnerableComponents);
            projectMetrics.setSuppressed(counters.suppressions);
            projectMetrics.setFindingsTotal(counters.findingsTotal);
            projectMetrics.setFindingsAudited(counters.findingsAudited);
            projectMetrics.setFindingsUnaudited(counters.findingsUnaudited);
            projectMetrics.setInheritedRiskScore(counters.getInheritedRiskScore());
            projectMetrics.setPolicyViolationsFail(counters.policyViolationsFail);
            projectMetrics.setPolicyViolationsWarn(counters.policyViolationsWarn);
            projectMetrics.setPolicyViolationsInfo(counters.policyViolationsInfo);
            projectMetrics.setPolicyViolationsTotal(counters.policyViolationsTotal);
            projectMetrics.setPolicyViolationsAudited(counters.policyViolationsAudited);
            projectMetrics.setPolicyViolationsUnaudited(counters.policyViolationsUnaudited);
            projectMetrics.setPolicyViolationsSecurityTotal(counters.policyViolationsSecurityTotal);
            projectMetrics.setPolicyViolationsSecurityAudited(counters.policyViolationsSecurityAudited);
            projectMetrics.setPolicyViolationsSecurityUnaudited(counters.policyViolationsSecurityUnaudited);
            projectMetrics.setPolicyViolationsLicenseTotal(counters.policyViolationsLicenseTotal);
            projectMetrics.setPolicyViolationsLicenseAudited(counters.policyViolationsLicenseAudited);
            projectMetrics.setPolicyViolationsLicenseUnaudited(counters.policyViolationsLicenseUnaudited);
            projectMetrics.setPolicyViolationsOperationalTotal(counters.policyViolationsOperationalTotal);
            projectMetrics.setPolicyViolationsOperationalAudited(counters.policyViolationsOperationalAudited);
            projectMetrics.setPolicyViolationsOperationalUnaudited(counters.policyViolationsOperationalUnaudited);
            projectMetrics.setFirstOccurrence(measuredAt);
            projectMetrics.setLastOccurrence(measuredAt);
            LOGGER.debug("Persisting metrics for project: " + project.getUuid());
            qm.persist(projectMetrics);
            LOGGER.debug("Updating Inherited Risk Score for project: " + project.getUuid());
            // Update the convenience fields in the Project object
            project.setLastInheritedRiskScore(projectMetrics.getInheritedRiskScore());
            LOGGER.debug("Persisting metrics for project: " + project.getUuid());
            qm.persist(project);
        }
        LOGGER.info("Completed metrics update for project: " + project.getUuid());
        return counters;
    }

    /**
     * Performs metric updates on a specific component.
     * @param qm a QueryManager instance
     * @param oid object ID of the component to perform metric updates on
     * @return MetricCounters
     */
    private MetricCounters updateComponentMetrics(final QueryManager qm, final long oid) {
        final Component component = qm.getObjectById(Component.class, oid);
        LOGGER.debug("Executing metrics update for component: " + component.getUuid());
        final Date measuredAt = new Date();

        final MetricCounters counters = new MetricCounters();
        // Retrieve the non-suppressed vulnerabilities for the component
        for (final Vulnerability vuln: qm.getAllVulnerabilities(component)) {
            counters.updateSeverity(vuln.getSeverity());
        }
        LOGGER.debug("Retrieving existing suppression count for component: " + component.getUuid());
        counters.suppressions = toIntExact(qm.getSuppressedCount(component));

        // For the time being finding and vulnerability counts are the same.
        // However, vulns may be defined as 'confirmed' in a future release.
        counters.findingsTotal = counters.severitySum();
        LOGGER.debug("Retrieving existing audited count for component: " + component.getUuid());
        counters.findingsAudited = toIntExact(qm.getAuditedCount(component));
        counters.findingsUnaudited = counters.findingsTotal - counters.findingsAudited;

        for (final PolicyViolation violation: qm.getAllPolicyViolations(component)) {
            counters.policyViolationsTotal++;

            // Assign violation states
            if (Policy.ViolationState.FAIL == violation.getPolicyCondition().getPolicy().getViolationState()) {
                counters.policyViolationsFail++;
            } else if (Policy.ViolationState.WARN == violation.getPolicyCondition().getPolicy().getViolationState()) {
                counters.policyViolationsWarn++;
            } else if (Policy.ViolationState.INFO == violation.getPolicyCondition().getPolicy().getViolationState()) {
                counters.policyViolationsInfo++;
            }
            // Assign violation types
            if (PolicyViolation.Type.LICENSE == violation.getType()) {
                counters.policyViolationsLicenseTotal++;
                //counters.policyViolationsLicenseAudited = qm.getAuditedCount(violation, component);
                counters.policyViolationsLicenseUnaudited = counters.policyViolationsLicenseTotal - counters.policyViolationsLicenseAudited;
            } else if (PolicyViolation.Type.SECURITY == violation.getType()) {
                counters.policyViolationsSecurityTotal++;
                //counters.policyViolationsSecurityAudited = qm.getAuditedCount(violation, component);
                counters.policyViolationsSecurityUnaudited = counters.policyViolationsSecurityTotal - counters.policyViolationsSecurityAudited;
            } else if (PolicyViolation.Type.OPERATIONAL == violation.getType()) {
                counters.policyViolationsOperationalTotal++;
                //counters.policyViolationsOperationalAudited = qm.getAuditedCount(violation, component);
                counters.policyViolationsOperationalUnaudited = counters.policyViolationsOperationalTotal - counters.policyViolationsOperationalAudited;
            }
        }

        // Query for an existing ComponentMetrics
        final DependencyMetrics last = qm.getMostRecentDependencyMetrics(component);
        if (last != null
                && last.getCritical() == counters.critical
                && last.getHigh() == counters.high
                && last.getMedium() == counters.medium
                && last.getLow() == counters.low
                && last.getUnassigned() == counters.unassigned
                && last.getVulnerabilities() == counters.severitySum()
                && last.getSuppressed() == counters.suppressions
                && last.getFindingsTotal() == counters.findingsTotal
                && last.getFindingsAudited() == counters.findingsAudited
                && last.getFindingsUnaudited() == counters.findingsUnaudited
                && last.getInheritedRiskScore() == counters.getInheritedRiskScore()
                && last.getPolicyViolationsFail() == counters.policyViolationsFail
                && last.getPolicyViolationsWarn() == counters.policyViolationsWarn
                && last.getPolicyViolationsInfo() == counters.policyViolationsInfo
                && last.getPolicyViolationsTotal() == counters.policyViolationsTotal
                && last.getPolicyViolationsAudited() == counters.policyViolationsAudited
                && last.getPolicyViolationsUnaudited() == counters.policyViolationsUnaudited
                && last.getPolicyViolationsSecurityTotal() == counters.policyViolationsSecurityTotal
                && last.getPolicyViolationsSecurityAudited() == counters.policyViolationsSecurityAudited
                && last.getPolicyViolationsSecurityUnaudited() == counters.policyViolationsSecurityUnaudited
                && last.getPolicyViolationsLicenseTotal() == counters.policyViolationsLicenseTotal
                && last.getPolicyViolationsLicenseAudited() == counters.policyViolationsLicenseAudited
                && last.getPolicyViolationsLicenseUnaudited() == counters.policyViolationsLicenseUnaudited
                && last.getPolicyViolationsOperationalTotal() == counters.policyViolationsOperationalTotal
                && last.getPolicyViolationsOperationalAudited() == counters.policyViolationsOperationalAudited
                && last.getPolicyViolationsOperationalUnaudited() == counters.policyViolationsOperationalUnaudited) {

            LOGGER.debug("Metrics are unchanged for component: " + component.getUuid() + ". Updating last occurrence");
            // Matches... Update the last occurrence timestamp instead of creating a new record with the same info
            last.setLastOccurrence(measuredAt);
            LOGGER.debug("Persisting metrics for component: " + component.getUuid());
            qm.persist(last);
            LOGGER.debug("Updating Inherited Risk Score for component: " + component.getUuid());
            // Update the convenience fields in the Component object
            component.setLastInheritedRiskScore(last.getInheritedRiskScore());
            LOGGER.debug("Persisting metrics for component: " + component.getUuid());
            qm.persist(component);
        } else {
            LOGGER.debug("Metrics have changed (or were never previously measured) for component: " + component.getUuid());
            final DependencyMetrics componentMetrics = new DependencyMetrics();
            componentMetrics.setProject(component.getProject());
            componentMetrics.setComponent(component);
            componentMetrics.setCritical(counters.critical);
            componentMetrics.setHigh(counters.high);
            componentMetrics.setMedium(counters.medium);
            componentMetrics.setLow(counters.low);
            componentMetrics.setUnassigned(counters.unassigned);
            componentMetrics.setVulnerabilities(counters.severitySum());
            componentMetrics.setSuppressed(counters.suppressions);
            componentMetrics.setFindingsTotal(counters.findingsTotal);
            componentMetrics.setFindingsAudited(counters.findingsAudited);
            componentMetrics.setFindingsUnaudited(counters.findingsUnaudited);
            componentMetrics.setInheritedRiskScore(counters.getInheritedRiskScore());
            componentMetrics.setPolicyViolationsFail(counters.policyViolationsFail);
            componentMetrics.setPolicyViolationsWarn(counters.policyViolationsWarn);
            componentMetrics.setPolicyViolationsInfo(counters.policyViolationsInfo);
            componentMetrics.setPolicyViolationsTotal(counters.policyViolationsTotal);
            componentMetrics.setPolicyViolationsAudited(counters.policyViolationsAudited);
            componentMetrics.setPolicyViolationsUnaudited(counters.policyViolationsUnaudited);
            componentMetrics.setPolicyViolationsSecurityTotal(counters.policyViolationsSecurityTotal);
            componentMetrics.setPolicyViolationsSecurityAudited(counters.policyViolationsSecurityAudited);
            componentMetrics.setPolicyViolationsSecurityUnaudited(counters.policyViolationsSecurityUnaudited);
            componentMetrics.setPolicyViolationsLicenseTotal(counters.policyViolationsLicenseTotal);
            componentMetrics.setPolicyViolationsLicenseAudited(counters.policyViolationsLicenseAudited);
            componentMetrics.setPolicyViolationsLicenseUnaudited(counters.policyViolationsLicenseUnaudited);
            componentMetrics.setPolicyViolationsOperationalTotal(counters.policyViolationsOperationalTotal);
            componentMetrics.setPolicyViolationsOperationalAudited(counters.policyViolationsOperationalAudited);
            componentMetrics.setPolicyViolationsOperationalUnaudited(counters.policyViolationsOperationalUnaudited);
            componentMetrics.setFirstOccurrence(measuredAt);
            componentMetrics.setLastOccurrence(measuredAt);
            LOGGER.debug("Persisting metrics for component: " + component.getUuid());
            qm.persist(componentMetrics);
            LOGGER.debug("Updating Inherited Risk Score for component: " + component.getUuid());
            // Update the convenience fields in the Component object
            component.setLastInheritedRiskScore(componentMetrics.getInheritedRiskScore());
            LOGGER.debug("Persisting metrics for component: " + component.getUuid());
            qm.persist(component);
        }
        LOGGER.debug("Completed metrics update for component: " + component.getUuid());
        return counters;
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
        private int projects, vulnerableProjects, components, vulnerableComponents,
                vulnerabilities, suppressions, findingsTotal, findingsAudited, findingsUnaudited,
                policyViolationsFail, policyViolationsWarn, policyViolationsInfo, policyViolationsTotal,
                policyViolationsAudited, policyViolationsUnaudited, policyViolationsSecurityTotal,
                policyViolationsSecurityAudited, policyViolationsSecurityUnaudited, policyViolationsLicenseTotal,
                policyViolationsLicenseAudited, policyViolationsLicenseUnaudited, policyViolationsOperationalTotal,
                policyViolationsOperationalAudited, policyViolationsOperationalUnaudited;

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
