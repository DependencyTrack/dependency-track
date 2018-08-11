/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import alpine.resources.OrderDirection;
import alpine.resources.Pagination;
import org.dependencytrack.event.MetricsUpdateEvent;
import org.dependencytrack.metrics.Metrics;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentMetrics;
import org.dependencytrack.model.Dependency;
import org.dependencytrack.model.DependencyMetrics;
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

            LOGGER.debug("Starting metrics update task");
            try (QueryManager qm = new QueryManager()) {
                if (MetricsUpdateEvent.Type.PORTFOLIO == event.getType()) {
                    updatePortfolioMetrics(qm);
                } else if (event.getTarget() instanceof Project) {
                    updateProjectMetrics(qm, ((Project) event.getTarget()).getId());
                } else if (event.getTarget() instanceof Component) {
                    updateComponentMetrics(qm, ((Component) event.getTarget()).getId());
                } else if (event.getTarget() instanceof Dependency) {
                    updateDependencyMetrics(qm, ((Dependency) event.getTarget()).getId());
                } else if (MetricsUpdateEvent.Type.VULNERABILITY == event.getType()) {
                    updateVulnerabilitiesMetrics(qm);
                }
            } catch (Exception ex) {
                LOGGER.error(ex.getMessage());
            }
            LOGGER.debug("Metrics update complete");
        }
    }

    /**
     * Performs high-level metric updates on the portfolio.
     * @param qm a QueryManager instance
     */
    private void updatePortfolioMetrics(QueryManager qm) {
        LOGGER.info("Executing metrics update on portfolio");
        final Date measuredAt = new Date();

        // Retrieve list of all projects
        final List<Project> projects = qm.getAllProjects();

        // Setup metrics
        final MetricCounters portfolioCounters = new MetricCounters();
        final List<MetricCounters> projectCountersList = new ArrayList<>();

        // Iterate through all projects
        for (Project project: projects) {
            // Update the projects metrics
            final MetricCounters projectMetrics = updateProjectMetrics(qm, project.getId());
            projectCountersList.add(projectMetrics);
        }

        // Iterate through the metrics from all project
        for (MetricCounters projectMetrics: projectCountersList) {
            // Add individual project metrics to the overall portfolio metrics
            portfolioCounters.projects++;
            portfolioCounters.critical += projectMetrics.critical;
            portfolioCounters.high += projectMetrics.high;
            portfolioCounters.medium += projectMetrics.medium;
            portfolioCounters.low += projectMetrics.low;

            // All vulnerabilities
            portfolioCounters.vulnerabilities += projectMetrics.chmlTotal();

            // All dependant components
            portfolioCounters.dependencies += projectMetrics.dependencies;

            // Only vulnerable components
            portfolioCounters.vulnerableDependencies += projectMetrics.vulnerableDependencies;

            // Only vulnerable projects
            if (projectMetrics.chmlTotal() > 0) {
                portfolioCounters.vulnerableProjects++;
            }
        }
        // Total number of suppressions regardless if they are dependencies or components not associated to a project
        portfolioCounters.suppressions = toIntExact(qm.getSuppressedCount());

        // There will be a high probability of having a large number of components. Setup paging.
        final AlpineRequest alpineRequest = new AlpineRequest(
                null, new Pagination(Pagination.Strategy.OFFSET, 0, 1000), null, "id", OrderDirection.ASCENDING
        );
        // Page through a list of components (these are global component objects - not dependencies)
        try (QueryManager qm2 = new QueryManager(alpineRequest)) {
            final long total = qm2.getCount(Component.class);
            long count = 0;
            while (count < total) {
                final PaginatedResult result = qm2.getComponents();
                portfolioCounters.components = toIntExact(result.getTotal());
                for (Component component: result.getList(Component.class)) {
                    final MetricCounters componentMetrics = updateComponentMetrics(qm, component.getId());
                    // Only vulnerable components
                    if (componentMetrics.chmlTotal() > 0) {
                        portfolioCounters.vulnerableComponents++;
                    }
                }
                count += result.getObjects().size();
                qm.advancePagination();
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
                && last.getDependencies() == portfolioCounters.dependencies
                && last.getVulnerableDependencies() == portfolioCounters.vulnerableDependencies
                && last.getSuppressed() == portfolioCounters.suppressions
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
            portfolioMetrics.setDependencies(portfolioCounters.dependencies);
            portfolioMetrics.setVulnerableDependencies(portfolioCounters.vulnerableDependencies);
            portfolioMetrics.setSuppressed(portfolioCounters.suppressions);
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
     * @param oid the object ID of the project
     * @return MetricCounters
     */
    private MetricCounters updateProjectMetrics(QueryManager qm, long oid) {
        Project project = qm.getObjectById(Project.class, oid);
        LOGGER.info("Executing metrics update on project: " + project.getUuid());
        final Date measuredAt = new Date();

        final MetricCounters counters = new MetricCounters();

        // Holds the metrics returned from all components that are dependencies of the project
        final List<MetricCounters> countersList = new ArrayList<>();

        // Retrieve all component dependencies for the project
        final List<Dependency> dependencies = qm.getAllDependencies(project);

        // Iterate through all dependencies
        for (Dependency dependency: dependencies) {

            // Get the component
            final Component component = dependency.getComponent();

            // Update the dependency metrics
            final MetricCounters dependencyMetrics = updateDependencyMetrics(qm, dependency.getId());

            // Adds the metrics from the dependency to the list of metrics for the project
            countersList.add(dependencyMetrics);
        }

        // Iterate through the metrics from all components that are dependencies of the project
        for (MetricCounters depMetric: countersList) {
            // Add individual component metrics to the overall project metrics
            counters.dependencies++;
            counters.critical += depMetric.critical;
            counters.high += depMetric.high;
            counters.medium += depMetric.medium;
            counters.low += depMetric.low;
            counters.vulnerabilities += depMetric.chmlTotal();

            if (depMetric.chmlTotal() > 0) {
                counters.vulnerableDependencies++;
            }
        }

        // Query for an existing ProjectMetrics
        final ProjectMetrics last = qm.getMostRecentProjectMetrics(project);
        if (last != null && last.getCritical() == counters.critical && last.getHigh() == counters.high
                && last.getMedium() == counters.medium && last.getLow() == counters.low
                && last.getVulnerabilities() == counters.vulnerabilities
                && last.getSuppressed() == counters.suppressions
                && last.getInheritedRiskScore() == counters.getInheritedRiskScore()
                && last.getComponents() == counters.dependencies // at a project level, the field is actually 'components'
                && last.getVulnerableComponents() == counters.vulnerableDependencies) {

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
            projectMetrics.setComponents(counters.dependencies);
            projectMetrics.setVulnerableComponents(counters.vulnerableDependencies);
            projectMetrics.setSuppressed(counters.suppressions);
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
     * @param oid object ID of the component to perform metric updates on
     * @return MetricCounters
     */
    private MetricCounters updateComponentMetrics(QueryManager qm, long oid) {
        Component component = qm.getObjectById(Component.class, oid);
        LOGGER.debug("Executing metrics update on component: " + component.getUuid());
        final Date measuredAt = new Date();

        final MetricCounters counters = new MetricCounters();
        // Retrieve the non-suppressed vulnerabilities for the component
        for (Vulnerability vuln: qm.getAllVulnerabilities(component)) {
            counters.updateSeverity(vuln.getSeverity());
        }
        counters.suppressions = toIntExact(qm.getSuppressedCount(component));

        // Query for an existing ComponentMetrics
        final ComponentMetrics last = qm.getMostRecentComponentMetrics(component);
        if (last != null && last.getCritical() == counters.critical && last.getHigh() == counters.high
                && last.getMedium() == counters.medium && last.getLow() == counters.low
                && last.getVulnerabilities() == counters.chmlTotal()
                && last.getSuppressed() == counters.suppressions
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
            componentMetrics.setSuppressed(counters.suppressions);
            componentMetrics.setInheritedRiskScore(counters.getInheritedRiskScore());
            componentMetrics.setFirstOccurrence(measuredAt);
            componentMetrics.setLastOccurrence(measuredAt);
            qm.persist(componentMetrics);
        }
        return counters;
    }

    /**
     * Performs metric updates on a specific dependency.
     * @param qm a QueryManager instance
     * @param oid object ID of the dependency to perform metric updates on
     * @return MetricCounters
     */
    private MetricCounters updateDependencyMetrics(QueryManager qm, long oid) {
        Dependency dependency = qm.getObjectById(Dependency.class, oid);
        LOGGER.debug("Executing metrics update on dependency: " + dependency.getId());
        final Date measuredAt = new Date();

        final MetricCounters counters = new MetricCounters();
        final Project project = dependency.getProject();
        final Component component = dependency.getComponent();

        // Retrieve the non-suppressed vulnerabilities for the component
        for (Vulnerability vuln: qm.getAllVulnerabilities(dependency)) {
            counters.updateSeverity(vuln.getSeverity());
        }
        counters.suppressions = toIntExact(qm.getSuppressedCount(project, component));

        // Query for an existing DependencyMetrics
        final DependencyMetrics last = qm.getMostRecentDependencyMetrics(dependency);
        if (last != null && last.getCritical() == counters.critical && last.getHigh() == counters.high
                && last.getMedium() == counters.medium && last.getLow() == counters.low
                && last.getVulnerabilities() == counters.chmlTotal()
                && last.getSuppressed() == counters.suppressions
                && last.getInheritedRiskScore() == counters.getInheritedRiskScore()) {

            // Matches... Update the last occurrence timestamp instead of creating a new record with the same info
            last.setLastOccurrence(measuredAt);
            qm.persist(last);
        } else {
            final DependencyMetrics dependencyMetrics = new DependencyMetrics();
            dependencyMetrics.setProject(project);
            dependencyMetrics.setComponent(component);
            dependencyMetrics.setCritical(counters.critical);
            dependencyMetrics.setHigh(counters.high);
            dependencyMetrics.setMedium(counters.medium);
            dependencyMetrics.setLow(counters.low);
            dependencyMetrics.setVulnerabilities(counters.chmlTotal());
            dependencyMetrics.setSuppressed(counters.suppressions);
            dependencyMetrics.setInheritedRiskScore(counters.getInheritedRiskScore());
            dependencyMetrics.setFirstOccurrence(measuredAt);
            dependencyMetrics.setLastOccurrence(measuredAt);
            qm.persist(dependencyMetrics);
        }
        return counters;
    }

    /**
     * Performs metric updates on the entire vulnerability database.
     * @param qm a QueryManager instance
     */
    private void updateVulnerabilitiesMetrics(QueryManager qm) {
        LOGGER.info("Executing metrics update on vulnerability database");
        final Date measuredAt = new Date();
        final VulnerabilityMetricCounters yearMonthCounters = new VulnerabilityMetricCounters(measuredAt, true);
        final VulnerabilityMetricCounters yearCounters = new VulnerabilityMetricCounters(measuredAt, false);
        final PaginatedResult vulnsResult = qm.getVulnerabilities();
        for (Vulnerability vulnerability: vulnsResult.getList(Vulnerability.class)) {
            if (vulnerability.getCreated() != null) {
                yearMonthCounters.updateMetics(vulnerability.getCreated());
                yearCounters.updateMetics(vulnerability.getCreated());
            } else if (vulnerability.getPublished() != null) {
                yearMonthCounters.updateMetics(vulnerability.getPublished());
                yearCounters.updateMetics(vulnerability.getPublished());
            }
        }
        for (VulnerabilityMetrics metric: yearMonthCounters.getMetrics()) {
            qm.synchronizeVulnerabilityMetrics(metric);
        }
        for (VulnerabilityMetrics metric: yearCounters.getMetrics()) {
            qm.synchronizeVulnerabilityMetrics(metric);
        }
    }

    /**
     * A value object that holds various counters returned by the updating of metrics.
     */
    private class VulnerabilityMetricCounters {

        private Date measuredAt;
        private boolean trackMonth;
        private List<VulnerabilityMetrics> metrics = new ArrayList<>();

        private VulnerabilityMetricCounters(Date measuredAt, boolean trackMonth) {
            this.measuredAt = measuredAt;
            this.trackMonth = trackMonth;
        }

        private void updateMetics(Date timestamp) {
            LocalDateTime date = LocalDateTime.ofInstant(timestamp.toInstant(), ZoneId.systemDefault());
            int year = date.getYear();
            int month = date.getMonthValue();

            boolean found = false;
            for (VulnerabilityMetrics metric: metrics) {
                if (trackMonth && metric.getYear() == year && metric.getMonth() == month) {
                    metric.setCount(metric.getCount() + 1);
                    found = true;
                } else if (!trackMonth && metric.getYear() == year) {
                    metric.setCount(metric.getCount() + 1);
                    found = true;
                }
            }
            if (!found) {
                VulnerabilityMetrics metric = new VulnerabilityMetrics();
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

        private int critical, high, medium, low;
        private int projects, vulnerableProjects, components, vulnerableComponents, dependencies, vulnerableDependencies, vulnerabilities, suppressions;

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
