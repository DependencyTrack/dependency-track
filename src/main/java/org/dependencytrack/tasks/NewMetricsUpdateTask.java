package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.server.persistence.PersistenceManagerFactory;
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
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.VulnerabilityUtil;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.Transaction;
import java.math.BigDecimal;
import java.util.Date;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

import static java.lang.Math.toIntExact;

public class NewMetricsUpdateTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(NewMetricsUpdateTask.class);
    private static final String QUERY_LANGUAGE_SQL = "javax.jdo.query.SQL";

    @Override
    public void inform(final Event e) {
        if (!(e instanceof MetricsUpdateEvent)) {
            return;
        }

        final var event = (MetricsUpdateEvent) e;
        try {
            if (MetricsUpdateEvent.Type.PORTFOLIO == event.getType()) {
                updatePortfolioMetrics();
            }
            if (MetricsUpdateEvent.Type.PROJECT == event.getType()) {
                updateProjectMetrics(((Project) event.getTarget()).getId());
            } else if (MetricsUpdateEvent.Type.COMPONENT == event.getType()) {
                updateComponentMetrics(((Component) event.getTarget()).getId());
            }
        } catch (Exception ex) {
            LOGGER.error("An unknown error occurred while updating metrics", ex);
        }
    }

    private Counters updatePortfolioMetrics() throws Exception {
        LOGGER.info("Executing portfolio metrics update");
        final var counters = new Counters();

        try (final PersistenceManager pm = PersistenceManagerFactory.createPersistenceManager()) {
            for (final long projectId : getActiveProjects(pm)) {
                final Counters projectCounters;
                try {
                    projectCounters = updateProjectMetrics(projectId);
                } catch (Exception e) {
                    LOGGER.error("An unexpected error occurred while updating portfolio metrics and iterating through projects. " +
                            "The error occurred while updating metrics for project: " + projectId, e);
                    continue;
                }

                counters.critical += projectCounters.critical;
                counters.high += projectCounters.high;
                counters.medium += projectCounters.medium;
                counters.low += projectCounters.low;
                counters.unassigned += projectCounters.unassigned;
                counters.vulnerabilities += projectCounters.vulnerabilities;

                counters.findingsTotal += projectCounters.findingsTotal;
                counters.findingsAudited += projectCounters.findingsAudited;
                counters.findingsUnaudited += projectCounters.findingsUnaudited;
                counters.suppressions += projectCounters.suppressions;
                counters.inheritedRiskScore = Metrics.inheritedRiskScore(counters.critical, counters.high, counters.medium, counters.low, counters.unassigned);

                counters.projects++;
                if (projectCounters.vulnerabilities > 0) {
                    counters.vulnerableProjects++;
                }
                counters.components += projectCounters.components;
                counters.vulnerableComponents += projectCounters.vulnerableComponents;

                counters.policyViolationsFail += projectCounters.policyViolationsFail;
                counters.policyViolationsWarn += projectCounters.policyViolationsWarn;
                counters.policyViolationsInfo += projectCounters.policyViolationsInfo;
                counters.policyViolationsTotal += projectCounters.policyViolationsTotal;
                counters.policyViolationsAudited += projectCounters.policyViolationsAudited;
                counters.policyViolationsUnaudited += projectCounters.policyViolationsUnaudited;
                counters.policyViolationsSecurityTotal += projectCounters.policyViolationsSecurityTotal;
                counters.policyViolationsSecurityAudited += projectCounters.policyViolationsSecurityAudited;
                counters.policyViolationsSecurityUnaudited += projectCounters.policyViolationsSecurityUnaudited;
                counters.policyViolationsLicenseTotal += projectCounters.policyViolationsLicenseTotal;
                counters.policyViolationsLicenseAudited += projectCounters.policyViolationsLicenseAudited;
                counters.policyViolationsLicenseUnaudited += projectCounters.policyViolationsLicenseUnaudited;
                counters.policyViolationsOperationalTotal += projectCounters.policyViolationsOperationalTotal;
                counters.policyViolationsOperationalAudited += projectCounters.policyViolationsOperationalAudited;
                counters.policyViolationsOperationalUnaudited += projectCounters.policyViolationsOperationalUnaudited;
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
                    latestMetrics.setLastOccurrence(counters.measuredAt);
                } else {
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

        LOGGER.info("Completed portfolio metrics update");
        return counters;
    }

    private Counters updateProjectMetrics(final long projectId) throws Exception {
        final var counters = new Counters();
        final UUID projectUuid;

        try (final PersistenceManager pm = PersistenceManagerFactory.createPersistenceManager()) {
            projectUuid = getProjectUuid(pm, projectId)
                    .orElseThrow(() -> new NoSuchElementException("Project with ID " + projectId + " does not exist"));
            LOGGER.info("Executing metrics update for project: " + projectUuid);

            for (final long componentId : getComponents(pm, projectId)) {
                final Counters componentCounters;
                try {
                    componentCounters = updateComponentMetrics(componentId);
                } catch (Exception e) {
                    LOGGER.error("An unexpected error occurred while updating project metrics and iterating through components. " +
                            "The error occurred while updating metrics for project: " + projectId + " and component: " + componentId, e);
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
        }

        try (final var qm = new QueryManager()) {
            final Project project = qm.getObjectById(Project.class, projectId);
            final Double inheritedRiskScore;

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
                    latestMetrics.setLastOccurrence(counters.measuredAt);
                    inheritedRiskScore = latestMetrics.getInheritedRiskScore();
                } else {
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
                    inheritedRiskScore = metrics.getInheritedRiskScore();
                }
                trx.commit();
            } finally {
                if (trx.isActive()) {
                    trx.rollback();
                }
            }

            if (project.getLastInheritedRiskScore() != null &&
                    !inheritedRiskScore.equals(project.getLastInheritedRiskScore())) {
                trx = qm.getPersistenceManager().currentTransaction();
                try {
                    trx.begin();
                    project.setLastInheritedRiskScore(inheritedRiskScore);
                    trx.commit();
                } finally {
                    if (trx.isActive()) {
                        trx.rollback();
                    }
                }
            }
        }

        LOGGER.info("Completed metrics update for project: " + projectUuid);
        return counters;
    }

    private Counters updateComponentMetrics(final long componentId) throws Exception {
        final var counters = new Counters();
        final UUID componentUuid;

        try (final PersistenceManager pm = PersistenceManagerFactory.createPersistenceManager()) {
            componentUuid = getComponentUuid(pm, componentId)
                    .orElseThrow(() -> new NoSuchElementException("Component with ID " + componentId + " does not exist"));
            LOGGER.debug("Executing metrics update for component: " + componentUuid);

            for (final VulnerabilityProjection vulnerability : getVulnerabilities(pm, componentId)) {
                counters.vulnerabilities++;

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
            Component component = qm.getObjectById(Component.class, componentId);

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
                    latestMetrics.setLastOccurrence(counters.measuredAt);
                } else {
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
                    counters.inheritedRiskScore != component.getLastInheritedRiskScore()) {
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

        LOGGER.debug("Completed metrics update for component: " + componentUuid);
        return counters;
    }

    private List<Long> getActiveProjects(final PersistenceManager pm) throws Exception {
        try (final Query<?> query = pm.newQuery(QUERY_LANGUAGE_SQL, "SELECT \"ID\" FROM \"PROJECT\" WHERE \"ACTIVE\" IS NULL OR \"ACTIVE\" = true")) {
            return List.copyOf(query.executeResultList(Long.class));
        }
    }

    private Optional<UUID> getProjectUuid(final PersistenceManager pm, final long projectId) throws Exception {
        try (final Query<?> query = pm.newQuery(QUERY_LANGUAGE_SQL, "SELECT \"UUID\" FROM \"PROJECT\" WHERE \"ID\" = ?")) {
            query.setParameters(projectId);
            return Optional.ofNullable(query.executeResultUnique(String.class)).map(UUID::fromString);
        }
    }

    private List<Long> getComponents(final PersistenceManager pm, final long projectId) throws Exception {
        try (final Query<?> query = pm.newQuery(QUERY_LANGUAGE_SQL, "SELECT \"ID\" FROM \"COMPONENT\" WHERE \"PROJECT_ID\" = ?")) {
            query.setParameters(projectId);
            return List.copyOf(query.executeResultList(Long.class));
        }
    }

    private Optional<UUID> getComponentUuid(final PersistenceManager pm, final long componentId) throws Exception {
        try (final Query<?> query = pm.newQuery(QUERY_LANGUAGE_SQL, "SELECT \"UUID\" FROM \"COMPONENT\" WHERE \"ID\" = ?")) {
            query.setParameters(componentId);
            return Optional.ofNullable(query.executeResultUnique(String.class)).map(UUID::fromString);
        }
    }

    private List<VulnerabilityProjection> getVulnerabilities(final PersistenceManager pm, final long componentId) throws Exception {
        try (final Query<?> query = pm.newQuery(QUERY_LANGUAGE_SQL, "" +
                "SELECT \"v\".\"SEVERITY\", \"v\".\"CVSSV2BASESCORE\", \"v\".\"CVSSV3BASESCORE\" " +
                "FROM \"COMPONENTS_VULNERABILITIES\" AS \"cv\" " +
                "  INNER JOIN \"COMPONENT\" AS \"c\" ON \"c\".\"ID\" = \"cv\".\"COMPONENT_ID\" " +
                "  INNER JOIN \"VULNERABILITY\" AS \"v\" ON \"v\".\"ID\" = \"cv\".\"VULNERABILITY_ID\" " +
                "  LEFT JOIN \"ANALYSIS\" AS \"a\" " +
                "    ON \"a\".\"COMPONENT_ID\" = \"cv\".\"COMPONENT_ID\" " +
                "    AND \"a\".\"VULNERABILITY_ID\" = \"cv\".\"VULNERABILITY_ID\" " +
                "WHERE \"cv\".\"COMPONENT_ID\" = ? " +
                "  AND (\"a\".\"SUPPRESSED\" IS NULL OR \"a\".\"SUPPRESSED\" = false) " +
                "ORDER BY \"v\".\"ID\"")) {
            query.setParameters(componentId);
            return List.copyOf(query.executeResultList(VulnerabilityProjection.class));
        }
    }

    private long getTotalAuditedFindings(final PersistenceManager pm, final long componentId) throws Exception {
        try (final Query<?> query = pm.newQuery(QUERY_LANGUAGE_SQL, "" +
                "SELECT COUNT(*) FROM \"ANALYSIS\" " +
                "WHERE \"COMPONENT_ID\" = ? " +
                "  AND \"SUPPRESSED\" = false " +
                "  AND \"STATE\" IS NOT NULL " +
                "  AND \"STATE\" != ? " +
                "  AND \"STATE\" != ?")) {
            query.setParameters(componentId,
                    AnalysisState.NOT_SET.name(),
                    AnalysisState.IN_TRIAGE.name());
            return query.executeResultUnique(Long.class);
        }
    }

    private long getTotalSuppressedFindings(final PersistenceManager pm, final long componentId) throws Exception {
        try (final Query<?> query = pm.newQuery(QUERY_LANGUAGE_SQL, "" +
                "SELECT COUNT(*) FROM \"ANALYSIS\" " +
                "WHERE \"COMPONENT_ID\" = ? " +
                "  AND \"SUPPRESSED\" = true")) {
            query.setParameters(componentId);
            return query.executeResultUnique(Long.class);
        }
    }

    private List<PolicyViolationProjection> getPolicyViolations(final PersistenceManager pm, final long componentId) throws Exception {
        try (final Query<?> query = pm.newQuery(QUERY_LANGUAGE_SQL, "" +
                "SELECT \"pv\".\"TYPE\", \"p\".\"VIOLATIONSTATE\" " +
                "FROM \"POLICYVIOLATION\" AS \"pv\" " +
                "  INNER JOIN \"POLICYCONDITION\" AS \"pc\" ON \"pc\".\"ID\" = \"pv\".\"POLICYCONDITION_ID\" " +
                "  INNER JOIN \"POLICY\" AS \"p\" ON \"p\".\"ID\" = \"pc\".\"POLICY_ID\" " +
                "  LEFT JOIN \"VIOLATIONANALYSIS\" AS \"va\" " +
                "    ON \"va\".\"COMPONENT_ID\" = \"pv\".\"COMPONENT_ID\" " +
                "    AND \"va\".\"POLICYVIOLATION_ID\" = \"pv\".\"ID\" " +
                "WHERE \"pv\".\"COMPONENT_ID\" = ? " +
                "  AND (\"va\".\"SUPPRESSED\" IS NULL OR \"va\".\"SUPPRESSED\" = false)")) {
            query.setParameters(componentId);
            return List.copyOf(query.executeResultList(PolicyViolationProjection.class));
        }
    }

    private long getTotalAuditedPolicyViolations(final PersistenceManager pm, final long componentId, final PolicyViolation.Type violationType) throws Exception {
        try (final Query<?> query = pm.newQuery(QUERY_LANGUAGE_SQL, "" +
                "SELECT COUNT(*) FROM \"VIOLATIONANALYSIS\" AS \"va\" " +
                "  INNER JOIN \"POLICYVIOLATION\" AS \"pv\" ON \"pv\".\"ID\" = \"va\".\"POLICYVIOLATION_ID\" " +
                "WHERE \"va\".\"COMPONENT_ID\" = ? " +
                "  AND \"pv\".\"TYPE\" = ?")) {
            query.setParameters(componentId, violationType.name());
            return query.executeResultUnique(Long.class);
        }
    }

    public static final class PolicyViolationProjection {
        private PolicyViolation.Type type;
        private Policy.ViolationState violationState;

        public void setType(final String type) {
            this.type = PolicyViolation.Type.valueOf(type);
        }

        public void setViolationState(final String violationState) {
            if (violationState != null) {
                this.violationState = Policy.ViolationState.valueOf(violationState);
            }
        }
    }

    public static final class VulnerabilityProjection {
        private Severity severity;
        private BigDecimal cvssV2BaseScore;
        private BigDecimal cvssV3BaseScore;

        public void setSeverity(final String severity) {
            if (severity != null) {
                this.severity = Severity.valueOf(severity);
            }
        }

        public void setCvssV2BaseScore(final BigDecimal cvssV2BaseScore) {
            this.cvssV2BaseScore = cvssV2BaseScore;
        }

        public void setCvssV3BaseScore(final BigDecimal cvssV3BaseScore) {
            this.cvssV3BaseScore = cvssV3BaseScore;
        }
    }

    private static class Counters {
        private int critical, high, medium, low, unassigned;
        private double inheritedRiskScore;
        private int components, vulnerableComponents, projects, vulnerableProjects;
        private int vulnerabilities, suppressions, findingsTotal, findingsAudited, findingsUnaudited,
                policyViolationsFail, policyViolationsWarn, policyViolationsInfo, policyViolationsTotal,
                policyViolationsAudited, policyViolationsUnaudited, policyViolationsSecurityTotal,
                policyViolationsSecurityAudited, policyViolationsSecurityUnaudited, policyViolationsLicenseTotal,
                policyViolationsLicenseAudited, policyViolationsLicenseUnaudited, policyViolationsOperationalTotal,
                policyViolationsOperationalAudited, policyViolationsOperationalUnaudited;
        private final Date measuredAt;

        private Counters() {
            this.measuredAt = new Date();
        }
    }

}
