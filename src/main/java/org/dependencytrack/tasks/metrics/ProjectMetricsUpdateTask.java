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
import javax.jdo.Transaction;
import java.util.Date;
import java.util.List;

/**
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
                LOGGER.error("An unexpected error occurred while updating project metrics");
            }
        }
    }

    private void updateMetrics(Project project) throws Exception {
        LOGGER.info("Executing metrics update for project " + project.getUuid());
        final var counters = new Counters();

        try (final QueryManager qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();

            project = pm.getObjectById(Project.class, project.getId());
            if (project == null) {
                LOGGER.warn("dfasdfgsdfgsdf");
                return;
            }

            LOGGER.trace("Fetching first components page for project " + project.getUuid());
            List<Component> components = seekComponents(pm, project, 0);
            if (components.isEmpty()) {
                LOGGER.warn("No components found for project " + project.getUuid());
            }

            while (!components.isEmpty()) {
                for (final Component component : components) {
                    final Counters componentCounters;
                    try {
                        componentCounters = ComponentMetricsUpdateTask.updateMetrics(component);
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

                LOGGER.trace("Fetching next components page for project " + project.getUuid());
                final long lastId = components.get(components.size() - 1).getId();
                components = seekComponents(pm, project, lastId);
            }

            Transaction trx = pm.currentTransaction();
            try {
                trx.begin();
                final ProjectMetrics latestMetrics = qm.getMostRecentProjectMetrics(project);
                if (!counters.hasChanged(latestMetrics)) {
                    LOGGER.debug("Metrics of project " + project.getUuid() + " did not change");
                    latestMetrics.setLastOccurrence(counters.measuredAt);
                } else {
                    LOGGER.debug("Metrics of project " + project.getUuid() + " changed");
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
                LOGGER.debug("Updating inherited risk score of project " + project.getUuid());
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

            LOGGER.info("Completed metrics update for project " + project.getUuid() + " in " +
                    DurationFormatUtils.formatDuration(new Date().getTime() - counters.measuredAt.getTime(), "mm:ss:SS"));
        }
    }

    private List<Component> seekComponents(final PersistenceManager pm, final Project project, final long lastId) throws Exception {
        try (final Query<Component> query = pm.newQuery(Component.class)) {
            query.setFilter("project == :project && id > :lastId");
            query.setParameters(project, lastId);
            query.setOrdering("id asc");
            query.setRange(0, 500);
            return List.copyOf(query.executeList());
        }
    }

}
