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
package org.dependencytrack.persistence;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;

import org.apache.commons.lang3.time.DateUtils;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.VulnerabilityMetrics;
import org.dependencytrack.util.MetricsUtils;

import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;


public class MetricsQueryManager extends QueryManager implements IQueryManager {

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    MetricsQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    MetricsQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Retrieves the current VulnerabilityMetrics
     * @return a VulnerabilityMetrics object
     */
    public List<VulnerabilityMetrics> getVulnerabilityMetrics() {
        final Query<VulnerabilityMetrics> query = pm.newQuery(VulnerabilityMetrics.class);
        query.setOrdering("year asc, month asc");
        return execute(query).getList(VulnerabilityMetrics.class);
    }

    /**
     * Retrieve all the projects suitable for portfolio
     */
    private List<Project> getProjectsForPortfolio() {
        if (principal != null
                && isEnabled(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED)
                && isEnabled(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_PORTFOLIOMETRICS_ENABLED)) {
            if (hasAccessManagementPermission(principal)) {
                return null;
            }

            return getAllProjects(true, true);
        }
        return null;   
    }

    /**
     * Retrieves the most recent PortfolioMetrics.
     * @return a PortfolioMetrics object
     */
    public PortfolioMetrics getMostRecentPortfolioMetrics() {
        final List<Project> projects = getProjectsForPortfolio();
        if (projects != null) {
            // Fetch up to 2 days to ensure metrics have been computed
            final List<ProjectMetrics> lastMetrics = getProjectMetricsSince(projects, DateUtils.addDays(new Date(), -2));

            final List<PortfolioMetrics> portfolioMetrics = MetricsUtils.sum(lastMetrics, true);
            return portfolioMetrics.stream()
                .reduce((i, j) -> j)
                .orElse(null);
        }

        final Query<PortfolioMetrics> query = pm.newQuery(PortfolioMetrics.class);
        query.setOrdering("lastOccurrence desc");
        query.setRange(0, 1);
        return singleResult(query.execute());
    }

    /**
     * Retrieves PortfolioMetrics in ascending order starting with the oldest since the date specified.
     * @return a List of metrics
     */
    @SuppressWarnings("unchecked")
    public List<PortfolioMetrics> getPortfolioMetricsSince(Date since) {
        final List<Project> projects = getProjectsForPortfolio();
        if (projects != null) {
            final var metrics = getProjectMetricsSince(projects, since);
            return MetricsUtils.sum(metrics, true);
        }

        final Query<PortfolioMetrics> query = pm.newQuery(PortfolioMetrics.class, "lastOccurrence >= :since");
        query.setOrdering("lastOccurrence asc");
        return (List<PortfolioMetrics>)query.execute(since);
    }

    /**
     * Retrieves the most recent ProjectMetrics.
     * @param project the Project to retrieve metrics for
     * @return a ProjectMetrics object
     */
    public ProjectMetrics getMostRecentProjectMetrics(Project project) {
        final Query<ProjectMetrics> query = pm.newQuery(ProjectMetrics.class, "project == :project");
        query.setOrdering("lastOccurrence desc");
        query.setRange(0, 1);
        return singleResult(query.execute(project));
    }

    /**
     * Retrieves ProjectMetrics in descending order starting with the most recent.
     * @param project the Project to retrieve metrics for
     * @return a PaginatedResult object
     */
    public PaginatedResult getProjectMetrics(Project project) {
        final List<Project> projects = new ArrayList<>();
        projects.add(project);
        return getProjectMetrics(projects);
    }

    /**
     * Retrieves ProjectMetrics in descending order starting with the most recent.
     * @param projects the Projects to retrieve metrics for
     * @return a PaginatedResult object
     */
    public PaginatedResult getProjectMetrics(List<Project> projects) {
        final Query<ProjectMetrics> query = pm.newQuery(ProjectMetrics.class, ":project.contains(project)");
        query.setOrdering("lastOccurrence desc");
        return execute(query, projects);
    }

    /**
     * Retrieves ProjectMetrics in ascending order starting with the oldest since the date specified.
     * @param project the Project to retrieve metrics for
     * @since first date for lookup
     * @return a List of metrics
     */
    public List<ProjectMetrics> getProjectMetricsSince(Project project, Date since) {
        final List<Project> projects = new ArrayList<>();
        projects.add(project);
        return getProjectMetricsSince(projects, since);
    }

    /**
     * Retrieves ProjectMetrics in ascending order starting with the oldest since the date specified.
     * @param projects the Projects to retrieve metrics for
     * @since first date for lookup
     * @return a List of metrics
     */
    @SuppressWarnings("unchecked")
    public List<ProjectMetrics> getProjectMetricsSince(List<Project> projects, Date since) {
        final Query<ProjectMetrics> query = pm.newQuery(ProjectMetrics.class, ":project.contains(project) && lastOccurrence >= :since");
        query.setOrdering("lastOccurrence asc");
        return (List<ProjectMetrics>)query.execute(projects, since);
    }

    /**
     * Retrieves the most recent DependencyMetrics.
     * @param component the Component to retrieve metrics for
     * @return a DependencyMetrics object
     */
    public DependencyMetrics getMostRecentDependencyMetrics(Component component) {
        final Query<DependencyMetrics> query = pm.newQuery(DependencyMetrics.class, "component == :component");
        query.setOrdering("lastOccurrence desc");
        query.setRange(0, 1);
        return singleResult(query.execute(component));
    }

    /**
     * Retrieves DependencyMetrics in descending order starting with the most recent.
     * @param component the Component to retrieve metrics for
     * @return a PaginatedResult object
     */
    public PaginatedResult getDependencyMetrics(Component component) {
        final Query<DependencyMetrics> query = pm.newQuery(DependencyMetrics.class, "component == :component");
        query.setOrdering("lastOccurrence desc");
        return execute(query, component);
    }

    /**
     * Retrieves DependencyMetrics in ascending order starting with the oldest since the date specified.
     * @return a List of metrics
     */
    @SuppressWarnings("unchecked")
    public List<DependencyMetrics> getDependencyMetricsSince(Component component, Date since) {
        final Query<DependencyMetrics> query = pm.newQuery(DependencyMetrics.class, "component == :component && lastOccurrence >= :since");
        query.setOrdering("lastOccurrence asc");
        return (List<DependencyMetrics>)query.execute(component, since);
    }

    public void synchronizeVulnerabilityMetrics(List<VulnerabilityMetrics> metrics) {
        pm.currentTransaction().begin();
        // No need for complex updating, just replace the existing ~400 rows with new ones
        // Unless we have a contract with clients that the ID of metric records cannot change?

        final Query<VulnerabilityMetrics> delete = pm.newQuery("DELETE FROM org.dependencytrack.model.VulnerabilityMetrics");
        delete.execute();

        // This still does ~400 queries, probably because not all databases can do bulk insert with autogenerated PKs
        // Or because Datanucleus is trying to be smart as it wants to cache all these instances
        pm.makePersistentAll(metrics);
        pm.currentTransaction().commit();
    }

    /**
     * Delete all metrics associated for the specified Project.
     * @param project the Project to delete metrics for
     */
    void deleteMetrics(Project project) {
        final Query<ProjectMetrics> query = pm.newQuery(ProjectMetrics.class, "project == :project");
        query.deletePersistentAll(project);

        final Query<DependencyMetrics> query2 = pm.newQuery(DependencyMetrics.class, "project == :project");
        query2.deletePersistentAll(project);
    }

    /**
     * Delete all metrics associated for the specified Component.
     * @param component the Component to delete metrics for
     */
    void deleteMetrics(Component component) {
        final Query<DependencyMetrics> query = pm.newQuery(DependencyMetrics.class, "component == :component");
        query.deletePersistentAll(component);
    }
 
}
