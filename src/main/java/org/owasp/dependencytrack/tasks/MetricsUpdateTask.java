/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.tasks;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import alpine.persistence.PaginatedResult;
import org.owasp.dependencytrack.event.MetricsUpdateEvent;
import org.owasp.dependencytrack.metrics.Metrics;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.ComponentMetrics;
import org.owasp.dependencytrack.model.Dependency;
import org.owasp.dependencytrack.model.PortfolioMetrics;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.model.ProjectMetrics;
import org.owasp.dependencytrack.model.Severity;
import org.owasp.dependencytrack.model.Vulnerability;
import org.owasp.dependencytrack.persistence.QueryManager;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Subscriber task that performs calculations of various Metircs.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class MetricsUpdateTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(MetricsUpdateTask.class);

    /**
     * {@inheritDoc}
     */
    public void inform(Event e) {
        if (e instanceof MetricsUpdateEvent) {
            final MetricsUpdateEvent event = (MetricsUpdateEvent) e;

            LOGGER.info("Starting metrics update task");
            try (QueryManager qm = new QueryManager()) {
                if (event.getTarget() == null) {
                    updateMetrics(qm);
                } else if (event.getTarget() instanceof Project) {
                    updateMetrics(qm, (Project) event.getTarget());
                } else if (event.getTarget() instanceof Component) {
                    updateMetrics(qm, (Component) event.getTarget());
                }
            } catch (Exception ex) {
                LOGGER.error(ex.getMessage());
            }
            LOGGER.info("Metrics update complete");
        }
    }

    /**
     * Performs high-level metric updates on the portfolio.
     * @param qm a QueryManager instance
     */
    private void updateMetrics(QueryManager qm) {
        LOGGER.info("Executing metrics update on portfolio");
        final Date measuredAt = new Date();

        // Retrieve list of all projects
        final PaginatedResult projectResult = qm.getProjects();
        final List<Project> projects = projectResult.getList(Project.class);

        // Setup metrics
        final MetricCounters portfolioCounters = new MetricCounters();
        final List<MetricCounters> projectCountersList = new ArrayList<>();

        // Iterate through all projects
        for (Project project: projects) {
            // Update the projects metrics
            final MetricCounters projectMetrics = updateMetrics(qm, project);
            projectCountersList.add(projectMetrics);
        }

        // Iterate through the metrics from all project
        for (MetricCounters projectMetrics: projectCountersList) {
            // Add individual project metrics to the overall portfolio metrics
            portfolioCounters.projects++;
            portfolioCounters.critical = portfolioCounters.critical + projectMetrics.critical;
            portfolioCounters.high = portfolioCounters.high + projectMetrics.high;
            portfolioCounters.medium = portfolioCounters.medium + projectMetrics.medium;
            portfolioCounters.low = portfolioCounters.low + projectMetrics.low;

            // All vulnerabilities
            portfolioCounters.vulnerabilities = portfolioCounters.vulnerabilities + projectMetrics.chmlTotal();

            // All dependant components
            portfolioCounters.components = portfolioCounters.components + projectMetrics.components;

            // Only vulnerable components
            portfolioCounters.vulnerableComponents = portfolioCounters.vulnerableComponents + projectMetrics.vulnerableComponents;

            // Only vulnerable projects
            if (projectMetrics.chmlTotal() > 0) {
                portfolioCounters.vulnerableProjects = portfolioCounters.vulnerableProjects + 1;
            }
        }

        // Query for an existing PortfolioMetrics
        final PortfolioMetrics last = qm.getMostRecentPortfolioMetrics();
        if (last != null && last.getCritical() == portfolioCounters.critical && last.getHigh() == portfolioCounters.high
                && last.getMedium() == portfolioCounters.medium && last.getLow() == portfolioCounters.low
                && last.getVulnerabilities() == portfolioCounters.vulnerabilities
                && last.getInheritedRiskScore() == portfolioCounters.getInheritedRiskScore()
                && last.getComponents() == portfolioCounters.components
                && last.getVulnerableComponents() == portfolioCounters.vulnerableComponents
                && last.getProjects() == portfolioCounters.projects
                && last.getVulnerableProjects() == portfolioCounters.vulnerableProjects) {

            // Matches... Update the last occurrence timestamp instead of creating a new record with the same info
            last.setLastOccurrence(measuredAt);
            qm.persist(last);
        } else {
            final PortfolioMetrics portfolioMetrics = new PortfolioMetrics();
            portfolioMetrics.setCritical(portfolioCounters.critical);
            portfolioMetrics.setHigh(portfolioCounters.high);
            portfolioMetrics.setMedium(portfolioCounters.medium);
            portfolioMetrics.setLow(portfolioCounters.low);
            portfolioMetrics.setVulnerabilities(portfolioCounters.vulnerabilities);
            portfolioMetrics.setComponents(portfolioCounters.components);
            portfolioMetrics.setVulnerableComponents(portfolioCounters.vulnerableComponents);
            portfolioMetrics.setProjects(portfolioCounters.projects);
            portfolioMetrics.setVulnerableProjects(portfolioCounters.vulnerableProjects);
            portfolioMetrics.setInheritedRiskScore(
                    Metrics.inheritedRiskScore(portfolioCounters.critical, portfolioCounters.high, portfolioCounters.medium, portfolioCounters.low)
            );
            portfolioMetrics.setFirstOccurrence(measuredAt);
            portfolioMetrics.setLastOccurrence(measuredAt);
            qm.persist(portfolioMetrics);
        }
    }

    /**
     * Performs metric updates on a specific project.
     * @param qm a QueryManager instance
     * @param project the project to perform metric updates on
     * @return MetricCounters
     */
    private MetricCounters updateMetrics(QueryManager qm, Project project) {
        LOGGER.debug("Executing metrics update on project: " + project.getUuid());
        final Date measuredAt = new Date();

        final MetricCounters counters = new MetricCounters();

        // Holds the metrics returned from all components that are dependencies of the project
        final List<MetricCounters> countersList = new ArrayList<>();

        // Retrieve all component dependencies for the project
        final PaginatedResult result = qm.getDependencies(project);

        // Iterate through all dependencies
        final List<Dependency> dependencies = result.getList(Dependency.class);
        for (Dependency dependency: dependencies) {

            // Get the component
            final Component component = dependency.getComponent();

            // Update the components metrics
            final MetricCounters componentMetrics = updateMetrics(qm, component);

            // Adds the metrics from the component to the list of metrics for the project
            countersList.add(componentMetrics);
        }

        // Iterate through the metrics from all components that are dependencies of the project
        for (MetricCounters compMetric: countersList) {
            // Add individual component metrics to the overall project metrics
            counters.components++;
            counters.critical = counters.critical + compMetric.critical;
            counters.high = counters.high + compMetric.high;
            counters.medium = counters.medium + compMetric.medium;
            counters.low = counters.low + compMetric.low;
            counters.vulnerabilities = counters.vulnerabilities + counters.chmlTotal();  // todo: is this correct?

            if (counters.chmlTotal() > 0) {
                counters.vulnerableComponents = counters.vulnerableComponents + 1;
            }
        }

        // Query for an existing ProjectMetrics
        final ProjectMetrics last = qm.getMostRecentProjectMetrics(project);
        if (last != null && last.getCritical() == counters.critical && last.getHigh() == counters.high
                && last.getMedium() == counters.medium && last.getLow() == counters.low
                && last.getVulnerabilities() == counters.vulnerabilities
                && last.getInheritedRiskScore() == counters.getInheritedRiskScore()
                && last.getComponents() == counters.components
                && last.getVulnerableComponents() == counters.vulnerableComponents) {

            // Matches... Update the last occurrence timestamp instead of creating a new record with the same info
            last.setLastOccurrence(measuredAt);
            qm.persist(last);
        } else {
            final ProjectMetrics projectMetrics = new ProjectMetrics();
            projectMetrics.setProject(project);
            projectMetrics.setCritical(counters.critical);
            projectMetrics.setHigh(counters.high);
            projectMetrics.setMedium(counters.medium);
            projectMetrics.setLow(counters.low);
            projectMetrics.setVulnerabilities(counters.vulnerabilities);
            projectMetrics.setComponents(counters.components);
            projectMetrics.setVulnerableComponents(counters.vulnerableComponents);
            projectMetrics.setInheritedRiskScore(counters.getInheritedRiskScore());
            projectMetrics.setFirstOccurrence(measuredAt);
            projectMetrics.setLastOccurrence(measuredAt);
            qm.persist(projectMetrics);
        }
        return counters;
    }

    /**
     * Performs metric updates on a specific component.
     * @param qm a QueryManager instance
     * @param component the component to perform metric updates on
     * @return MetricCounters
     */
    private MetricCounters updateMetrics(QueryManager qm, Component component) {
        LOGGER.debug("Executing metrics update on project: " + component.getUuid());
        final Date measuredAt = new Date();

        final MetricCounters counters = new MetricCounters();
        // Retrieve the vulnerabilities for the component
        for (Vulnerability vuln: component.getVulnerabilities()) {
            counters.updateSeverity(vuln.getSeverity());
        }

        // Query for an existing ComponentMetrics
        final ComponentMetrics last = qm.getMostRecentComponentMetrics(component);
        if (last != null && last.getCritical() == counters.critical && last.getHigh() == counters.high
                && last.getMedium() == counters.medium && last.getLow() == counters.low
                && last.getVulnerabilities() == counters.chmlTotal()
                && last.getInheritedRiskScore() == counters.getInheritedRiskScore()) {

            // Matches... Update the last occurrence timestamp instead of creating a new record with the same info
            last.setLastOccurrence(measuredAt);
            qm.persist(last);
        } else {
            final ComponentMetrics componentMetrics = new ComponentMetrics();
            componentMetrics.setComponent(component);
            componentMetrics.setCritical(counters.critical);
            componentMetrics.setHigh(counters.high);
            componentMetrics.setMedium(counters.medium);
            componentMetrics.setLow(counters.low);
            componentMetrics.setVulnerabilities(counters.chmlTotal());
            componentMetrics.setInheritedRiskScore(counters.getInheritedRiskScore());
            componentMetrics.setFirstOccurrence(measuredAt);
            componentMetrics.setLastOccurrence(measuredAt);
            qm.persist(componentMetrics);
        }
        return counters;
    }

    /**
     * A value object that holds various counters returned by the updating of metrics.
     */
    private class MetricCounters {

        private int critical, high, medium, low;
        private int projects, vulnerableProjects, components, vulnerableComponents, vulnerabilities;

        /**
         * Increments critical, high, medium, low counters based on the specified severity.
         * @param severity the severity to update counters on
         */
        private void updateSeverity(Severity severity) {
            if (Severity.CRITICAL == severity) {
                critical++;
            } else if (Severity.HIGH == severity) {
                high++;
            } else if (Severity.MEDIUM == severity) {
                medium++;
            } else if (Severity.LOW == severity) {
                low++;
            }
        }

        /**
         * Returns the sum of the total number of critical, high, medium, and low severity vulnerabilities.
         * @return the sum of the counters for critical, high, medium, and low.
         */
        private int chmlTotal() {
            return critical + high + medium + low;
        }

        /**
         * Returns the calculated Inherited Risk Score.
         * See: {@link Metrics#inheritedRiskScore(int, int, int, int)}
         * @return the calculated score
         */
        private double getInheritedRiskScore() {
            return Metrics.inheritedRiskScore(critical, high, medium, low);
        }
    }

}
