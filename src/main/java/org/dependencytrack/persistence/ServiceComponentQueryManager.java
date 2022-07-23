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

import alpine.event.framework.Event;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;

import javax.jdo.FetchPlan;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.List;

final class ServiceComponentQueryManager extends QueryManager implements IQueryManager {

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    ServiceComponentQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    ServiceComponentQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns a service component by matching its identity information.
     * @param project the Project the component is a dependency of
     * @param cid the identity values of the component
     * @return a ServiceComponent object, or null if not found
     */
    public ServiceComponent matchServiceIdentity(final Project project, final ComponentIdentity cid) {
        final Query<ServiceComponent> query = pm.newQuery(ServiceComponent.class, "project == :project && group == :group && name == :name && version == :version");
        query.setRange(0, 1);
        return singleResult(query.executeWithArray(project, cid.getGroup(), cid.getName(), cid.getVersion()));
    }

    /**
     * Intelligently adds service components that are not already a dependency
     * of the specified project and removes the dependency relationship for service components
     * that are not in the list of specified components.
     * @param project the project to bind components to
     * @param existingProjectServices the complete list of existing dependent service components
     * @param services the complete list of service components that should be dependencies of the project
     */
    public void reconcileServiceComponents(Project project, List<ServiceComponent> existingProjectServices, List<ServiceComponent> services) {
        // Removes components as dependencies to the project for all
        // components not included in the list provided
        List<ServiceComponent> markedForDeletion = new ArrayList<>();
        for (final ServiceComponent existingService: existingProjectServices) {
            boolean keep = false;
            for (final ServiceComponent service: services) {
                if (service.getId() == existingService.getId()) {
                    keep = true;
                    break;
                }
            }
            if (!keep) {
                markedForDeletion.add(existingService);
            }
        }
        if (!markedForDeletion.isEmpty()) {
            for (ServiceComponent sc: markedForDeletion) {
                this.recursivelyDelete(sc, false);
            }
            //this.delete(markedForDeletion);
        }
    }

    /**
     * Creates a new ServiceComponent.
     * @param service the ServiceComponent to persist
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a new ServiceComponent
     */
    public ServiceComponent createServiceComponent(ServiceComponent service, boolean commitIndex) {
        final ServiceComponent result = persist(service);
        Event.dispatch(new IndexEvent(IndexEvent.Action.CREATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, ServiceComponent.class);
        return result;
    }

    /**
     * Returns a list of all service components.
     * This method if designed NOT to provide paginated results.
     * @return a List of ServiceComponent objects
     */
    public List<ServiceComponent> getAllServiceComponents() {
        final Query<ServiceComponent> query = pm.newQuery(ServiceComponent.class);
        query.setOrdering("id asc");
        return query.executeList();
    }

    /**
     * Returns a List of all ServiceComponent for the specified Project.
     * This method if designed NOT to provide paginated results.
     * @param project the Project to retrieve dependencies of
     * @return a List of ServiceComponent objects
     */
    @SuppressWarnings("unchecked")
    public List<ServiceComponent> getAllServiceComponents(Project project) {
        final Query<ServiceComponent> query = pm.newQuery(ServiceComponent.class, "project == :project");
        query.getFetchPlan().setMaxFetchDepth(2);
        query.setOrdering("name asc");
        return (List<ServiceComponent>)query.execute(project);
    }

    /**
     * Returns a list of all ServiceComponents defined in the datastore.
     * @return a List of ServiceComponents
     */
    public PaginatedResult getServiceComponents() {
        return getServiceComponents(false);
    }

    /**
     * Returns a list of all ServiceComponents defined in the datastore.
     * @return a List of ServiceComponents
     */
    public PaginatedResult getServiceComponents(final boolean includeMetrics) {
        final PaginatedResult result;
        final Query<ServiceComponent> query = pm.newQuery(ServiceComponent.class);
        if (orderBy == null) {
            query.setOrdering("name asc, version desc");
        }
        if (filter != null) {
            query.setFilter("name.toLowerCase().matches(:name)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            result = execute(query, filterString);
        } else {
            result = execute(query);
        }
        if (includeMetrics) {
            // TODO: Add metrics
            // Populate each Component object in the paginated result with transitive related
            // data to minimize the number of round trips a client needs to make, process, and render.
            //for (ServiceComponent service : result.getList(ServiceComponent.class)) {
            //    service.setMetrics(getMostRecentDependencyMetrics(service));
            //}
        }
        return result;
    }

    /**
     * Returns a List of ServiceComponents for the specified Project.
     * @param project the Project to retrieve dependencies of
     * @return a List of ServiceComponent objects
     */
    public PaginatedResult getServiceComponents(final Project project, final boolean includeMetrics) {
        final PaginatedResult result;
        final Query<ServiceComponent> query = pm.newQuery(ServiceComponent.class, "project == :project");
        query.getFetchPlan().setMaxFetchDepth(2);
        if (orderBy == null) {
            query.setOrdering("name asc, version desc");
        }
        if (filter != null) {
            query.setFilter("project == :project && name.toLowerCase().matches(:name)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            result = execute(query, project, filterString);
        } else {
            result = execute(query, project);
        }
        if (includeMetrics) {
            // TODO
        }
        return result;
    }

    public ServiceComponent cloneServiceComponent(ServiceComponent sourceService, Project destinationProject, boolean commitIndex) {
        final ServiceComponent service = new ServiceComponent();
        service.setProvider(sourceService.getProvider());
        service.setGroup(sourceService.getGroup());
        service.setName(sourceService.getName());
        service.setVersion(sourceService.getVersion());
        service.setDescription(sourceService.getDescription());
        service.setEndpoints(sourceService.getEndpoints());
        service.setAuthenticated(sourceService.getAuthenticated());
        service.setCrossesTrustBoundary(sourceService.getCrossesTrustBoundary());
        service.setData(sourceService.getData());
        service.setExternalReferences(sourceService.getExternalReferences());
        // TODO Add support for parent component and children components
        service.setNotes(sourceService.getNotes());
        service.setVulnerabilities(sourceService.getVulnerabilities());
        service.setProject(destinationProject);
        return createServiceComponent(sourceService, commitIndex);
    }

    /**
     * Updated an existing ServiceComponent.
     * @param transientServiceComponent the service to update
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a Component
     */
    public ServiceComponent updateServiceComponent(ServiceComponent transientServiceComponent, boolean commitIndex) {
        final ServiceComponent service = getObjectByUuid(ServiceComponent.class, transientServiceComponent.getUuid());
        service.setName(transientServiceComponent.getName());
        service.setVersion(transientServiceComponent.getVersion());
        service.setGroup(transientServiceComponent.getGroup());
        service.setDescription(transientServiceComponent.getDescription());
        final ServiceComponent result = persist(service);
        Event.dispatch(new IndexEvent(IndexEvent.Action.UPDATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, ServiceComponent.class);
        return result;
    }

    /**
     * Deletes all services for the specified Project.
     * @param project the Project to delete services of
     */
    private void deleteServiceComponents(Project project) {
        final Query<ServiceComponent> query = pm.newQuery(ServiceComponent.class, "project == :project");
        query.deletePersistentAll(project);
    }

    /**
     * Deletes a ServiceComponent and all objects dependant on the service.
     * @param service the ServiceComponent to delete
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     */
    public void recursivelyDelete(ServiceComponent service, boolean commitIndex) {
        if (service.getChildren() != null) {
            for (final ServiceComponent child: service.getChildren()) {
                recursivelyDelete(child, false);
            }
        }
        pm.getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
        final ServiceComponent result = pm.getObjectById(ServiceComponent.class, service.getId());
        Event.dispatch(new IndexEvent(IndexEvent.Action.DELETE, pm.detachCopy(result)));
        // TODO: Add these in when these features are supported by service components
        //deleteAnalysisTrail(service);
        //deleteViolationAnalysisTrail(service);
        //deleteMetrics(service);
        //deleteFindingAttributions(service);
        //deletePolicyViolations(service);
        delete(service);
        commitSearchIndex(commitIndex, ServiceComponent.class);
    }
}
