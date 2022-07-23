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

import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.apache.commons.collections4.CollectionUtils;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.VulnerabilityMetrics;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.Date;
import java.util.List;

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
     * Retrieves the most recent PortfolioMetrics.
     * @return a PortfolioMetrics object
     */
    public PortfolioMetrics getMostRecentPortfolioMetrics() {
        final Query<PortfolioMetrics> query = pm.newQuery(PortfolioMetrics.class);
        query.setOrdering("lastOccurrence desc");
        query.setRange(0, 1);
        return singleResult(query.execute());
    }

    /**
     * Retrieves PortfolioMetrics in descending order starting with the most recent.
     * @return a PaginatedResult object
     */
    public PaginatedResult getPortfolioMetrics() {
        final Query<PortfolioMetrics> query = pm.newQuery(PortfolioMetrics.class);
        query.setOrdering("lastOccurrence desc");
        return execute(query);
    }

    /**
     * Retrieves PortfolioMetrics in ascending order starting with the oldest since the date specified.
     * @return a List of metrics
     */
    @SuppressWarnings("unchecked")
    public List<PortfolioMetrics> getPortfolioMetricsSince(Date since) {
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
        final Query<ProjectMetrics> query = pm.newQuery(ProjectMetrics.class, "project == :project");
        query.setOrdering("lastOccurrence desc");
        return execute(query, project);
    }

    /**
     * Retrieves ProjectMetrics in ascending order starting with the oldest since the date specified.
     * @return a List of metrics
     */
    @SuppressWarnings("unchecked")
    public List<ProjectMetrics> getProjectMetricsSince(Project project, Date since) {
        final Query<ProjectMetrics> query = pm.newQuery(ProjectMetrics.class, "project == :project && lastOccurrence >= :since");
        query.setOrdering("lastOccurrence asc");
        return (List<ProjectMetrics>)query.execute(project, since);
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

    /**
     * Synchronizes VulnerabilityMetrics.
     */
    public void synchronizeVulnerabilityMetrics(VulnerabilityMetrics metric) {
        final Query<VulnerabilityMetrics> query;
        final List<VulnerabilityMetrics> result;
        if (metric.getMonth() == null) {
            query = pm.newQuery(VulnerabilityMetrics.class, "year == :year && month == null");
            result = execute(query, metric.getYear()).getList(VulnerabilityMetrics.class);
        } else {
            query = pm.newQuery(VulnerabilityMetrics.class, "year == :year && month == :month");
            result = execute(query, metric.getYear(), metric.getMonth()).getList(VulnerabilityMetrics.class);
        }
        if (result.size() == 1) {
            final VulnerabilityMetrics m = result.get(0);
            m.setCount(metric.getCount());
            m.setMeasuredAt(metric.getMeasuredAt());
            persist(m);
        } else if (CollectionUtils.isEmpty(result)) {
            persist(metric);
        } else {
            delete(result);
            persist(metric);
        }
    }

    /**
     * Deleted all metrics associated for the specified Project.
     * @param project the Project to delete metrics for
     */
    void deleteMetrics(Project project) {
        final Query<ProjectMetrics> query = pm.newQuery(ProjectMetrics.class, "project == :project");
        query.deletePersistentAll(project);

        final Query<DependencyMetrics> query2 = pm.newQuery(DependencyMetrics.class, "project == :project");
        query2.deletePersistentAll(project);
    }

    /**
     * Deleted all metrics associated for the specified Component.
     * @param component the Component to delete metrics for
     */
    void deleteMetrics(Component component) {
        final Query<DependencyMetrics> query = pm.newQuery(DependencyMetrics.class, "component == :component");
        query.deletePersistentAll(component);
    }
}
