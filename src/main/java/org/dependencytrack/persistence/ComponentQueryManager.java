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
import alpine.model.ApiKey;
import alpine.model.Team;
import alpine.model.UserPrincipal;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import javax.jdo.FetchPlan;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class ComponentQueryManager extends QueryManager implements IQueryManager {

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    ComponentQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    ComponentQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns a list of all Components defined in the datastore.
     * @return a List of Components
     */
    public PaginatedResult getComponents(final boolean includeMetrics) {
        final PaginatedResult result;
        final Query<Component> query = pm.newQuery(Component.class);
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
            // Populate each Component object in the paginated result with transitive related
            // data to minimize the number of round trips a client needs to make, process, and render.
            for (Component component : result.getList(Component.class)) {
                component.setMetrics(getMostRecentDependencyMetrics(component));
            }
        }
        return result;
    }

    /**
     * Returns a list of all Components defined in the datastore.
     * @return a List of Components
     */
    public PaginatedResult getComponents() {
        return getComponents(false);
    }

    /**
     * Returns a list of all components.
     * This method if designed NOT to provide paginated results.
     * @return a List of Components
     */
    public List<Component> getAllComponents() {
        final Query<Component> query = pm.newQuery(Component.class);
        query.setOrdering("id asc");
        return query.executeList();
    }

    /**
     * Returns a List of all Components for the specified Project.
     * This method if designed NOT to provide paginated results.
     * @param project the Project to retrieve dependencies of
     * @return a List of Component objects
     */
    @SuppressWarnings("unchecked")
    public List<Component> getAllComponents(Project project) {
        final Query<Component> query = pm.newQuery(Component.class, "project == :project");
        query.getFetchPlan().setMaxFetchDepth(2);
        query.setOrdering("name asc");
        return (List<Component>)query.execute(project);
    }

    /**
     * Returns a List of Dependency for the specified Project.
     * @param project the Project to retrieve dependencies of
     * @return a List of Dependency objects
     */
    public PaginatedResult getComponents(final Project project, final boolean includeMetrics) {
        final PaginatedResult result;
        final Query<Component> query = pm.newQuery(Component.class, "project == :project");
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
            // Populate each Component object in the paginated result with transitive related
            // data to minimize the number of round trips a client needs to make, process, and render.
            for (Component component : result.getList(Component.class)) {
                component.setMetrics(getMostRecentDependencyMetrics(component));
                final PackageURL purl = component.getPurl();
                if (purl != null) {
                    final RepositoryType type = RepositoryType.resolve(purl);
                    if (RepositoryType.UNSUPPORTED != type) {
                        final RepositoryMetaComponent repoMetaComponent = getRepositoryMetaComponent(type, purl.getNamespace(), purl.getName());
                        component.setRepositoryMeta(repoMetaComponent);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Returns Components by their hash.
     * @param hash the hash of the component to retrieve
     * @return a list of components
     */
    public PaginatedResult getComponentByHash(String hash) {
        if (hash == null) {
            return null;
        }
        final Query<Component> query;
        final Map<String, Object> params = new HashMap<>();
        final String queryFilter;
        if (hash.length() == 32) {
            query = pm.newQuery(Component.class);
            queryFilter = "(md5 == :hash)";
        } else if (hash.length() == 40) {
            query = pm.newQuery(Component.class);
            queryFilter = "(sha1 == :hash)";
        } else if (hash.length() == 64) {
            query = pm.newQuery(Component.class);
            queryFilter = "(sha256 == :hash || sha3_256 == :hash || blake2b_256 == :hash)";
        } else if (hash.length() == 96) {
            query = pm.newQuery(Component.class);
            queryFilter = "(sha384 == :hash || sha3_384 == :hash || blake2b_384 == :hash)";
        } else if (hash.length() == 128) {
            query = pm.newQuery(Component.class);
            queryFilter = "(sha512 == :hash || sha3_512 == :hash || blake2b_512 == :hash)";
        } else {
            query = pm.newQuery(Component.class);
            queryFilter = "(blake3 == :hash)";
        }
        params.put("hash", hash);
        preprocessACLs(query, queryFilter, params, false);
        return execute(query, params);
    }

    /**
     * Returns Components by their identity.
     * @param identity the ComponentIdentity to query against
     * @return a list of components
     */
    public PaginatedResult getComponents(ComponentIdentity identity) {
        return getComponents(identity, false);
    }

    /**
     * Returns Components by their identity.
     * @param identity the ComponentIdentity to query against
     * @param includeMetrics whether or not to include component metrics or not
     * @return a list of components
     */
    public PaginatedResult getComponents(ComponentIdentity identity, boolean includeMetrics) {
        if (identity == null) {
            return null;
        }
        final Query<Component> query;
        final PaginatedResult result;
        if (identity.getGroup() != null || identity.getName() != null || identity.getVersion() != null) {
            final Map<String, Object> map = new HashMap<>();
            String queryFilter = "";
            if (identity.getGroup() != null || identity.getName() != null || identity.getVersion() != null) queryFilter += "(";
            if (identity.getGroup() != null) {
                queryFilter += " group.toLowerCase().matches(:group) ";
                final String filterString = ".*" + identity.getGroup().toLowerCase() + ".*";
                map.put("group", filterString);
            }
            if (identity.getName() != null) {
                if (identity.getGroup() != null) {
                    queryFilter += " && ";
                }
                queryFilter += " name.toLowerCase().matches(:name) ";
                final String filterString = ".*" + identity.getName().toLowerCase() + ".*";
                map.put("name", filterString);
            }
            if (identity.getVersion() != null) {
                if (identity.getGroup() != null || identity.getName() != null) {
                    queryFilter += " && ";
                }
                queryFilter += " version.toLowerCase().matches(:version) ";
                final String filterString = ".*" + identity.getVersion().toLowerCase() + ".*";
                map.put("version", filterString);
            }
            if (identity.getGroup() != null || identity.getName() != null || identity.getVersion() != null) queryFilter += ")";
            query = pm.newQuery(Component.class);
            if (orderBy == null) {
                query.setOrdering("id asc");
            }
            preprocessACLs(query, queryFilter, map, false);
            result = execute(query, map);
        } else if (identity.getPurl() != null) {
            query = pm.newQuery(Component.class);
            if (orderBy == null) {
                query.setOrdering("id asc");
            }
            final Map<String, Object> params = new HashMap<>();
            final String queryFilter = "(purl.toLowerCase().matches(:purl))";
            final String filterString = ".*" + identity.getPurl().canonicalize().toLowerCase() + ".*";
            params.put("purl", filterString);
            preprocessACLs(query, queryFilter, params, false);
            result = execute(query, params);
        } else if (identity.getCpe() != null) {
            query = pm.newQuery(Component.class);
            if (orderBy == null) {
                query.setOrdering("id asc");
            }
            final Map<String, Object> params = new HashMap<>();
            final String queryFilter = "(cpe.toLowerCase().matches(:cpe))";
            final String filterString = ".*" + identity.getCpe().toLowerCase() + ".*";
            params.put("cpe", filterString);
            preprocessACLs(query, queryFilter, params, false);
            result = execute(query, params);
        } else if (identity.getSwidTagId() != null) {
            query = pm.newQuery(Component.class);
            if (orderBy == null) {
                query.setOrdering("id asc");
            }
            final Map<String, Object> params = new HashMap<>();
            final String queryFilter = "(swidTagId.toLowerCase().matches(:swidTagId))";
            final String filterString = ".*" + identity.getSwidTagId().toLowerCase() + ".*";
            params.put("swidTagId", filterString);
            preprocessACLs(query, queryFilter, params, false);
            result = execute(query, params);
        } else {
            result = new PaginatedResult();
        }
        if (includeMetrics) {
            // Populate each Component object in the paginated result with transitive related
            // data to minimize the number of round trips a client needs to make, process, and render.
            for (Component component : result.getList(Component.class)) {
                component.setMetrics(getMostRecentDependencyMetrics(component));
                final PackageURL purl = component.getPurl();
                if (purl != null) {
                    final RepositoryType type = RepositoryType.resolve(purl);
                    if (RepositoryType.UNSUPPORTED != type) {
                        final RepositoryMetaComponent repoMetaComponent = getRepositoryMetaComponent(type, purl.getNamespace(), purl.getName());
                        component.setRepositoryMeta(repoMetaComponent);
                    }
                }
            }
        }
        for (Component component : result.getList(Component.class)) {
            component.getProject(); // Force loading of project
            component.getProject().getGroup();
            component.getProject().getName();
            component.getProject().getVersion();
            component.getProject().getSwidTagId();
            component.getProject().getCpe();
            component.getProject().getUuid();
        }
        return result;
    }

    /**
     * Creates a new Component.
     * @param component the Component to persist
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a new Component
     */
    public Component createComponent(Component component, boolean commitIndex) {
        final Component result = persist(component);
        Event.dispatch(new IndexEvent(IndexEvent.Action.CREATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, Component.class);
        return result;
    }

    public Component cloneComponent(Component sourceComponent, Project destinationProject, boolean commitIndex) {
        final Component component = new Component();
        component.setGroup(sourceComponent.getGroup());
        component.setName(sourceComponent.getName());
        component.setVersion(sourceComponent.getVersion());
        component.setClassifier(sourceComponent.getClassifier());
        component.setFilename(sourceComponent.getFilename());
        component.setExtension(sourceComponent.getExtension());
        component.setMd5(sourceComponent.getMd5());
        component.setSha1(sourceComponent.getSha1());
        component.setSha256(sourceComponent.getSha256());
        component.setSha384(sourceComponent.getSha384());
        component.setSha512(sourceComponent.getSha512());
        component.setSha3_256(sourceComponent.getSha3_256());
        component.setSha3_384(sourceComponent.getSha3_384());
        component.setSha3_512(sourceComponent.getSha3_512());
        component.setBlake2b_256(sourceComponent.getBlake2b_256());
        component.setBlake2b_384(sourceComponent.getBlake2b_384());
        component.setBlake2b_512(sourceComponent.getBlake2b_512());
        component.setBlake3(sourceComponent.getBlake3());
        component.setCpe(sourceComponent.getCpe());
        component.setPurl(sourceComponent.getPurl());
        component.setPurlCoordinates(sourceComponent.getPurlCoordinates());
        component.setInternal(sourceComponent.isInternal());
        component.setDescription(sourceComponent.getDescription());
        component.setCopyright(sourceComponent.getCopyright());
        component.setLicense(sourceComponent.getLicense());
        component.setResolvedLicense(sourceComponent.getResolvedLicense());
        // TODO Add support for parent component and children components
        component.setProject(destinationProject);
        return createComponent(component, commitIndex);
    }

    /**
     * Updated an existing Component.
     * @param transientComponent the component to update
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a Component
     */
    public Component updateComponent(Component transientComponent, boolean commitIndex) {
        final Component component = getObjectByUuid(Component.class, transientComponent.getUuid());
        component.setName(transientComponent.getName());
        component.setVersion(transientComponent.getVersion());
        component.setGroup(transientComponent.getGroup());
        component.setFilename(transientComponent.getFilename());
        component.setMd5(transientComponent.getMd5());
        component.setSha1(transientComponent.getSha1());
        component.setSha256(transientComponent.getSha256());
        component.setSha512(transientComponent.getSha512());
        component.setSha3_256(transientComponent.getSha3_256());
        component.setSha3_512(transientComponent.getSha3_512());
        component.setDescription(transientComponent.getDescription());
        component.setCopyright(transientComponent.getCopyright());
        component.setLicense(transientComponent.getLicense());
        component.setResolvedLicense(transientComponent.getResolvedLicense());
        component.setParent(transientComponent.getParent());
        component.setCpe(transientComponent.getCpe());
        component.setPurl(transientComponent.getPurl());
        component.setInternal(transientComponent.isInternal());
        final Component result = persist(component);
        Event.dispatch(new IndexEvent(IndexEvent.Action.UPDATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, Component.class);
        return result;
    }

    /**
     * Deletes all components for the specified Project.
     * @param project the Project to delete components of
     */
    protected void deleteComponents(Project project) {
        final Query<Component> query = pm.newQuery(Component.class, "project == :project");
        query.deletePersistentAll(project);
    }

    /**
     * Deletes a Component and all objects dependant on the component.
     * @param component the Component to delete
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     */
    public void recursivelyDelete(Component component, boolean commitIndex) {
        if (component.getChildren() != null) {
            for (final Component child: component.getChildren()) {
                recursivelyDelete(child, false);
            }
        }
        pm.getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
        final Component result = pm.getObjectById(Component.class, component.getId());
        Event.dispatch(new IndexEvent(IndexEvent.Action.DELETE, pm.detachCopy(result)));

        deleteAnalysisTrail(component);
        deleteViolationAnalysisTrail(component);
        deleteMetrics(component);
        deleteFindingAttributions(component);
        deletePolicyViolations(component);
        delete(component);
        commitSearchIndex(commitIndex, Component.class);
    }

    /**
     * Returns a component by matching its identity information.
     * @param project the Project the component is a dependency of
     * @param cid the identity values of the component
     * @return a Component object, or null if not found
     */
    public Component matchIdentity(final Project project, final ComponentIdentity cid) {
        String purlString = null;
        String purlCoordinates = null;
        if (cid.getPurl() != null) {
            try {
                final PackageURL purl = cid.getPurl();
                purlString = cid.getPurl().canonicalize();
                purlCoordinates = new PackageURL(purl.getType(), purl.getNamespace(), purl.getName(), purl.getVersion(), null, null).canonicalize();
            } catch (MalformedPackageURLException e) { // throw it away
            }
        }
        final Query<Component> query = pm.newQuery(Component.class, "project == :project && ((purl != null && purl == :purl) || (purlCoordinates != null && purlCoordinates == :purlCoordinates) || (swidTagId != null && swidTagId == :swidTagId) || (cpe != null && cpe == :cpe) || (group == :group && name == :name && version == :version))");
        return singleResult(query.executeWithArray(project, purlString, purlCoordinates, cid.getSwidTagId(), cid.getCpe(), cid.getGroup(), cid.getName(), cid.getVersion()));
    }

    /**
     * Returns a List of components by matching identity information.
     * @param cid the identity values of the component
     * @return a List of Component objects
     */
    @SuppressWarnings("unchecked")
    public List<Component> matchIdentity(final ComponentIdentity cid) {
        String purlString = null;
        String purlCoordinates = null;
        if (cid.getPurl() != null) {
            purlString = cid.getPurl().canonicalize();
            try {
                final PackageURL purl = cid.getPurl();
                purlCoordinates = new PackageURL(purl.getType(), purl.getNamespace(), purl.getName(), purl.getVersion(), null, null).canonicalize();
            } catch (MalformedPackageURLException e) { // throw it away
            }
        }
        final Query<Component> query = pm.newQuery(Component.class, "(purl != null && purl == :purl) || (purlCoordinates != null && purlCoordinates == :purlCoordinates) || (swidTagId != null && swidTagId == :swidTagId) || (cpe != null && cpe == :cpe) || (group == :group && name == :name && version == :version)");
        return (List<Component>) query.executeWithArray(purlString, purlCoordinates, cid.getSwidTagId(), cid.getCpe(), cid.getGroup(), cid.getName(), cid.getVersion());
    }

    /**
     * Intelligently adds dependencies for components that are not already a dependency
     * of the specified project and removes the dependency relationship for components
     * that are not in the list of specified components.
     * @param project the project to bind components to
     * @param existingProjectComponents the complete list of existing dependent components
     * @param components the complete list of components that should be dependencies of the project
     */
    public void reconcileComponents(Project project, List<Component> existingProjectComponents, List<Component> components) {
        // Removes components as dependencies to the project for all
        // components not included in the list provided
        List<Component> markedForDeletion = new ArrayList<>();
        for (final Component existingComponent: existingProjectComponents) {
            boolean keep = false;
            for (final Component component: components) {
                if (component.getId() == existingComponent.getId()) {
                    keep = true;
                    break;
                }
            }
            if (!keep) {
                markedForDeletion.add(existingComponent);
            }
        }
        if (!markedForDeletion.isEmpty()) {
            for (Component c: markedForDeletion) {
                this.recursivelyDelete(c, false);
            }
            //this.delete(markedForDeletion);
        }
    }

    /**
     * A similar method exists in ProjectQueryManager
     */
    private void preprocessACLs(final Query<Component> query, final String inputFilter, final Map<String, Object> params, final boolean bypass) {
        if (super.principal != null && isEnabled(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED) && !bypass) {
            final List<Team> teams;
            if (super.principal instanceof UserPrincipal) {
                final UserPrincipal userPrincipal = ((UserPrincipal) super.principal);
                teams = userPrincipal.getTeams();
                if (super.hasAccessManagementPermission(userPrincipal)) {
                    query.setFilter(inputFilter);
                    return;
                }
            } else {
                final ApiKey apiKey = ((ApiKey) super.principal);
                teams = apiKey.getTeams();
                if (super.hasAccessManagementPermission(apiKey)) {
                    query.setFilter(inputFilter);
                    return;
                }
            }
            if (teams != null && teams.size() > 0) {
                final StringBuilder sb = new StringBuilder();
                for (int i = 0, teamsSize = teams.size(); i < teamsSize; i++) {
                    final Team team = super.getObjectById(Team.class, teams.get(i).getId());
                    sb.append(" project.accessTeams.contains(:team").append(i).append(") ");
                    params.put("team" + i, team);
                    if (i < teamsSize-1) {
                        sb.append(" || ");
                    }
                }
                if (inputFilter != null) {
                    query.setFilter(inputFilter + " && (" + sb.toString() + ")");
                } else {
                    query.setFilter(sb.toString());
                }
            }
        } else {
            query.setFilter(inputFilter);
        }
    }
}
