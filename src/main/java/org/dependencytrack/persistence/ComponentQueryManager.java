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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.persistence;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.model.IConfigProperty;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.commons.lang3.tuple.Pair;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.ComponentProperty;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.resources.v1.vo.DependencyGraphResponse;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonValue;
import javax.jdo.FetchPlan;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.dependencytrack.util.PersistenceUtil.assertNonPersistent;
import static org.dependencytrack.util.PersistenceUtil.assertPersistent;

final class ComponentQueryManager extends QueryManager implements IQueryManager {

    private static final Logger LOGGER = Logger.getLogger(ComponentQueryManager.class);

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
     * @param includeMetrics Optionally includes third-party metadata about the component from external repositories
     * @return a List of Dependency objects
     */
    public PaginatedResult getComponents(final Project project, final boolean includeMetrics) {
        return getComponents(project, includeMetrics, false, false);
    }
    /**
     * Returns a List of Dependency for the specified Project.
     * @param project the Project to retrieve dependencies of
     * @param includeMetrics Optionally includes third-party metadata about the component from external repositories
     * @param onlyOutdated Optionally exclude recent components so only outdated components are shown
     * @param onlyDirect Optionally exclude transitive dependencies so only direct dependencies are shown
     * @return a List of Dependency objects
     */
    public PaginatedResult getComponents(final Project project, final boolean includeMetrics, final boolean onlyOutdated, final boolean onlyDirect) {
        final PaginatedResult result;
        String querySring ="SELECT FROM org.dependencytrack.model.Component WHERE project == :project ";
        if (filter != null) {
            querySring += " && (project == :project) && (name.toLowerCase().matches(:filter) || group.toLowerCase().matches(:filter))";
        }
        if (onlyOutdated) {
            // Components are considered outdated when metadata does exists, but the version is different than latestVersion
            // Different should always mean version < latestVersion
            // Hack JDO using % instead of .* to get the SQL LIKE clause working:
            querySring +=
                " && !("+
                " SELECT FROM org.dependencytrack.model.RepositoryMetaComponent m " +
                " WHERE m.name == this.name " +
                " && m.namespace == this.group " +
                " && m.latestVersion != this.version " +
                " && this.purl.matches('pkg:' + m.repositoryType.toString().toLowerCase() + '/%') " +
                " ).isEmpty()";
        }
        if (onlyDirect) {
            querySring +=
                " && this.project.directDependencies.matches('%\"uuid\":\"'+this.uuid+'\"%') "; // only direct dependencies
        }
        final Query<?> query = pm.newQuery(Query.JDOQL, querySring);
        query.getFetchPlan().setMaxFetchDepth(2);
        if (orderBy == null) {
            query.setOrdering("name asc, version desc");
        }
        if (filter != null) {
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

        final String queryFilter = switch (hash.length()) {
            case 32 -> "(md5 == :hash)";
            case 40 -> "(sha1 == :hash)";
            case 64 -> "(sha256 == :hash || sha3_256 == :hash || blake2b_256 == :hash)";
            case 96 -> "(sha384 == :hash || sha3_384 == :hash || blake2b_384 == :hash)";
            case 128 -> "(sha512 == :hash || sha3_512 == :hash || blake2b_512 == :hash)";
            default -> "(blake3 == :hash)";
        };

        final Query<Component> query = pm.newQuery(Component.class);
        final var params = new HashMap<String, Object>();
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
        return getComponents(identity, null, false);
    }

    public PaginatedResult getComponents(ComponentIdentity identity, boolean includeMetrics) {
        return getComponents(identity, null, includeMetrics);
    }

    /**
     * Returns Components by their identity.
     * @param identity the ComponentIdentity to query against
     * @param project The {@link Project} the {@link Component}s shall belong to
     * @param includeMetrics whether or not to include component metrics or not
     * @return a list of components
     */
    public PaginatedResult getComponents(ComponentIdentity identity, Project project, boolean includeMetrics) {
        if (identity == null) {
            return null;
        }

        final var queryFilterElements = new ArrayList<String>();
        final var queryParams = new HashMap<String, Object>();

        if (project != null) {
            queryFilterElements.add(" project == :project ");
            queryParams.put("project", project);
        }

        final PaginatedResult result;
        if (identity.getGroup() != null || identity.getName() != null || identity.getVersion() != null) {
            if (identity.getGroup() != null) {
                queryFilterElements.add(" group.toLowerCase().matches(:group) ");
                queryParams.put("group", ".*" + identity.getGroup().toLowerCase() + ".*");
            }
            if (identity.getName() != null) {
                queryFilterElements.add(" name.toLowerCase().matches(:name) ");
                queryParams.put("name", ".*" + identity.getName().toLowerCase() + ".*");
            }
            if (identity.getVersion() != null) {
                queryFilterElements.add(" version.toLowerCase().matches(:version) ");
                queryParams.put("version", ".*" + identity.getVersion().toLowerCase() + ".*");
            }

            result = loadComponents("(" + String.join(" && ", queryFilterElements) + ")", queryParams);
        } else if (identity.getPurl() != null) {
            queryFilterElements.add("purl.toLowerCase().matches(:purl)");
            queryParams.put("purl", ".*" + identity.getPurl().canonicalize().toLowerCase() + ".*");

            result = loadComponents("(" + String.join(" && ", queryFilterElements) + ")", queryParams);
        } else if (identity.getCpe() != null) {
            queryFilterElements.add("cpe.toLowerCase().matches(:cpe)");
            queryParams.put("cpe", ".*" + identity.getCpe().toLowerCase() + ".*");

            result = loadComponents("(" + String.join(" && ", queryFilterElements) + ")", queryParams);
        } else if (identity.getSwidTagId() != null) {
            queryFilterElements.add("swidTagId.toLowerCase().matches(:swidTagId)");
            queryParams.put("swidTagId", ".*" + identity.getSwidTagId().toLowerCase() + ".*");

            result = loadComponents("(" + String.join(" && ", queryFilterElements) + ")", queryParams);
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

    private PaginatedResult loadComponents(String queryFilter, Map<String, Object> params) {
        var query = pm.newQuery(Component.class);
        if (orderBy == null) {
            query.setOrdering("id asc");
        }
        preprocessACLs(query, queryFilter, params, false);
        return execute(query, params);
    }

    /**
     * Creates a new Component.
     * @param component the Component to persist
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a new Component
     */
    public Component createComponent(Component component, boolean commitIndex) {
        final Component result = persist(component);
        Event.dispatch(new IndexEvent(IndexEvent.Action.CREATE, result));
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
        component.setLicenseExpression(sourceComponent.getLicenseExpression());
        component.setLicenseUrl(sourceComponent.getLicenseUrl());
        component.setResolvedLicense(sourceComponent.getResolvedLicense());
        component.setAuthor(sourceComponent.getAuthor());
        component.setSupplier(sourceComponent.getSupplier());
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
        component.setLicenseExpression(transientComponent.getLicenseExpression());
        component.setLicenseUrl(transientComponent.getLicenseUrl());
        component.setResolvedLicense(transientComponent.getResolvedLicense());
        component.setParent(transientComponent.getParent());
        component.setCpe(transientComponent.getCpe());
        component.setPurl(transientComponent.getPurl());
        component.setInternal(transientComponent.isInternal());
        component.setAuthor(transientComponent.getAuthor());
        component.setSupplier(transientComponent.getSupplier());
        component.setExternalReferences(transientComponent.getExternalReferences());
        final Component result = persist(component);
        Event.dispatch(new IndexEvent(IndexEvent.Action.UPDATE, result));
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
        try {
            final Component result = pm.getObjectById(Component.class, component.getId());
            Event.dispatch(new IndexEvent(IndexEvent.Action.DELETE, result));
            deleteAnalysisTrail(component);
            deleteViolationAnalysisTrail(component);
            deleteMetrics(component);
            deleteFindingAttributions(component);
            deletePolicyViolations(component);
            delete(component);
            commitSearchIndex(commitIndex, Component.class);
        } catch (javax.jdo.JDOObjectNotFoundException | org.datanucleus.exceptions.NucleusObjectNotFoundException e) {
            LOGGER.warn("Deletion of component failed because it didn't exist anymore.");
        }

    }

    /**
     * Returns a component by matching its identity information.
     * <p>
     * Note that this method employs a stricter matching logic than {@link #matchIdentity(ComponentIdentity)}.
     * For example, if {@code purl} of the given {@link ComponentIdentity} is {@code null},
     * this method will use a query that explicitly checks for the {@code purl} column to be {@code null}.
     * Whereas other methods will simply not include {@code purl} in the query in such cases.
     *
     * @param project the Project the component is a dependency of
     * @param cid     the identity values of the component
     * @return a Component object, or null if not found
     * @since 4.11.0
     */
    public Component matchSingleIdentityExact(final Project project, final ComponentIdentity cid) {
        final Pair<String, Map<String, Object>> queryFilterParamsPair = buildExactComponentIdentityQuery(project, cid);
        final Query<Component> query = pm.newQuery(Component.class, queryFilterParamsPair.getKey());
        query.setNamedParameters(queryFilterParamsPair.getRight());
        try {
            return query.executeUnique();
        } finally {
            query.closeAll();
        }
    }

    /**
     * Returns the first component matching a given {@link ComponentIdentity} in a {@link Project}.
     *
     * @param project the Project the component is a dependency of
     * @param cid     the identity values of the component
     * @return a Component object, or null if not found
     * @since 4.11.0
     */
    public Component matchFirstIdentityExact(final Project project, final ComponentIdentity cid) {
        final Pair<String, Map<String, Object>> queryFilterParamsPair = buildExactComponentIdentityQuery(project, cid);
        final Query<Component> query = pm.newQuery(Component.class, queryFilterParamsPair.getKey());
        query.setNamedParameters(queryFilterParamsPair.getRight());
        query.setRange(0, 1);
        try {
            final List<Component> result = query.executeList();
            if (result.isEmpty()) {
                return null;
            }

            return result.get(0);
        } finally {
            query.closeAll();
        }
    }

    /**
     * Returns a list of components by matching its identity information.
     * @param project the Project the component is a dependency of
     * @param cid the identity values of the component
     * @return a List of Component objects, or null if not found
     */
    @SuppressWarnings("unchecked")
    public List<Component> matchIdentity(final Project project, final ComponentIdentity cid) {
        final Pair<String, Map<String, Object>> queryFilterParamsPair = buildComponentIdentityQuery(project, cid);
        final Query<Component> query = pm.newQuery(Component.class, queryFilterParamsPair.getLeft());
        return (List<Component>) query.executeWithMap(queryFilterParamsPair.getRight());
    }

    /**
     * Returns a List of components by matching identity information.
     * @param cid the identity values of the component
     * @return a List of Component objects
     */
    @SuppressWarnings("unchecked")
    public List<Component> matchIdentity(final ComponentIdentity cid) {
        final Pair<String, Map<String, Object>> queryFilterParamsPair = buildComponentIdentityQuery(null, cid);
        final Query<Component> query = pm.newQuery(Component.class, queryFilterParamsPair.getLeft());
        return (List<Component>) query.executeWithMap(queryFilterParamsPair.getRight());
    }

    private static Pair<String, Map<String, Object>> buildComponentIdentityQuery(final Project project, final ComponentIdentity cid) {
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

        final var filterParts = new ArrayList<String>();
        final var params = new HashMap<String, Object>();

        if (purlString != null) {
            filterParts.add("purl == :purl");
            params.put("purl", purlString);
        }
        if (purlCoordinates != null) {
            filterParts.add("purlCoordinates == :purlCoordinates");
            params.put("purlCoordinates", purlCoordinates);
        }
        if (cid.getCpe() != null) {
            filterParts.add("cpe == :cpe");
            params.put("cpe", cid.getCpe());
        }
        if (cid.getSwidTagId() != null) {
            filterParts.add("swidTagId == :swidTagId");
            params.put("swidTagId", cid.getSwidTagId());
        }

        final var coordinatesFilterParts = new ArrayList<String>();
        if (cid.getGroup() != null) {
            coordinatesFilterParts.add("group == :group");
            params.put("group", cid.getGroup());
        } else {
            coordinatesFilterParts.add("group == null");
        }
        if (cid.getName() != null) {
            coordinatesFilterParts.add("name == :name");
            params.put("name", cid.getName());
        } else {
            coordinatesFilterParts.add("name == null");
        }
        if (cid.getVersion() != null) {
            coordinatesFilterParts.add("version == :version");
            params.put("version", cid.getVersion());
        } else {
            coordinatesFilterParts.add("version == null");
        }
        filterParts.add("(%s)".formatted(String.join(" && ", coordinatesFilterParts)));

        if (project == null) {
            final String filter = String.join(" || ", filterParts);
            return Pair.of(filter, params);
        }

        final String filter = "project == :project && (%s)".formatted(String.join(" || ", filterParts));
        params.put("project", project);
        return Pair.of(filter, params);
    }

    private static Pair<String, Map<String, Object>> buildExactComponentIdentityQuery(final Project project, final ComponentIdentity cid) {
        var filterParts = new ArrayList<String>();
        final var params = new HashMap<String, Object>();

        if (cid.getPurl() != null) {
            filterParts.add("(purl != null && purl == :purl)");
            params.put("purl", cid.getPurl().canonicalize());
        } else {
            filterParts.add("purl == null");
        }

        if (cid.getCpe() != null) {
            filterParts.add("(cpe != null && cpe == :cpe)");
            params.put("cpe", cid.getCpe());
        } else {
            filterParts.add("cpe == null");
        }

        if (cid.getSwidTagId() != null) {
            filterParts.add("(swidTagId != null && swidTagId == :swidTagId)");
            params.put("swidTagId", cid.getSwidTagId());
        } else {
            filterParts.add("swidTagId == null");
        }

        var coordinatesFilter = "(";
        if (cid.getGroup() != null) {
            coordinatesFilter += "group == :group";
            params.put("group", cid.getGroup());
        } else {
            coordinatesFilter += "group == null";
        }
        coordinatesFilter += " && name == :name";
        params.put("name", cid.getName());
        if (cid.getVersion() != null) {
            coordinatesFilter += " && version == :version";
            params.put("version", cid.getVersion());
        } else {
            coordinatesFilter += " && version == null";
        }
        coordinatesFilter += ")";
        filterParts.add(coordinatesFilter);

        final var filter = "project == :project && (" + String.join(" && ", filterParts) + ")";
        params.put("project", project);

        return Pair.of(filter, params);
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

    public Map<String, Component> getDependencyGraphForComponents(Project project, List<Component> components) {
        Map<String, Component> dependencyGraph = new HashMap<>();
        if (project.getDirectDependencies() == null || project.getDirectDependencies().isBlank()) {
            return dependencyGraph;
        }

        for(Component component : components) {
            dependencyGraph.put(component.getUuid().toString(), component);
            getParentDependenciesOfComponent(project, component, dependencyGraph);
        }
        if (!dependencyGraph.isEmpty()){
            getRootDependencies(dependencyGraph, project);
            getDirectDependenciesForPathDependencies(dependencyGraph);
        }
        // Reduce size of JSON response
        for (Map.Entry<String, Component> entry : dependencyGraph.entrySet()) {
            Component transientComponent = new Component();
            transientComponent.setUuid(entry.getValue().getUuid());
            transientComponent.setName(entry.getValue().getName());
            transientComponent.setVersion(entry.getValue().getVersion());
            transientComponent.setPurl(entry.getValue().getPurl());
            transientComponent.setPurlCoordinates(entry.getValue().getPurlCoordinates());
            transientComponent.setDependencyGraph(entry.getValue().getDependencyGraph());
            transientComponent.setExpandDependencyGraph(entry.getValue().isExpandDependencyGraph());
            if (transientComponent.getPurl() != null) {
                final RepositoryType type = RepositoryType.resolve(transientComponent.getPurl());
                if (RepositoryType.UNSUPPORTED != type) {
                    final RepositoryMetaComponent repoMetaComponent = getRepositoryMetaComponent(type, transientComponent.getPurl().getNamespace(), transientComponent.getPurl().getName());
                    if (repoMetaComponent != null) {
                        RepositoryMetaComponent transientRepoMetaComponent = new RepositoryMetaComponent();
                        transientRepoMetaComponent.setLatestVersion(repoMetaComponent.getLatestVersion());
                        transientComponent.setRepositoryMeta(transientRepoMetaComponent);
                    }
                }
            }
            dependencyGraph.put(entry.getKey(), transientComponent);
        }
        return dependencyGraph;
    }

    /**
     * Returns a list of all {@link DependencyGraphResponse} objects by {@link Component} UUID.
     * @param uuids a list of {@link Component} UUIDs
     * @return a list of {@link DependencyGraphResponse} objects
     * @since 4.9.0
     */
    public List<DependencyGraphResponse> getDependencyGraphByUUID(final List<UUID> uuids) {
        final Query<Component> query = this.getObjectsByUuidsQuery(Component.class, uuids);
        query.setResult("uuid, name, version, purl, directDependencies, null");
        return List.copyOf(query.executeResultList(DependencyGraphResponse.class));
    }

    private void getParentDependenciesOfComponent(Project project, Component childComponent, Map<String, Component> dependencyGraph) {
        String queryUuid = ".*" + childComponent.getUuid().toString() + ".*";
        final Query<Component> query = pm.newQuery(Component.class, "directDependencies.matches(:queryUuid) && project == :project");
        query.setParameters(queryUuid, project);
        List<Component> parentComponents = executeAndCloseList(query);
        for (Component parentComponent : parentComponents) {
            parentComponent.setExpandDependencyGraph(true);
            if(parentComponent.getDependencyGraph() == null) {
                parentComponent.setDependencyGraph(new HashSet<>());
            }
            parentComponent.getDependencyGraph().add(childComponent.getUuid().toString());
            if (!dependencyGraph.containsKey(parentComponent.getUuid().toString())) {
                dependencyGraph.put(parentComponent.getUuid().toString(), parentComponent);
                getParentDependenciesOfComponent(project, parentComponent, dependencyGraph);
            }
        }
    }

    private void getRootDependencies(Map<String, Component> dependencyGraph, Project project) {
        JsonArray directDependencies = Json.createReader(new StringReader(project.getDirectDependencies())).readArray();
        for (JsonValue directDependency : directDependencies) {
            String uuid = directDependency.asJsonObject().getString("uuid");
            if (!dependencyGraph.containsKey(uuid)) {
                Component component = this.getObjectByUuid(Component.class, uuid);
                dependencyGraph.put(uuid, component);
            }
        }
        getDirectDependenciesForPathDependencies(dependencyGraph);
    }

    private void getDirectDependenciesForPathDependencies(Map<String, Component> dependencyGraph) {
        Map<String, Component> addToDependencyGraph = new HashMap<>();
        for (Component component : dependencyGraph.values()) {
            if (component.getDirectDependencies() != null && !component.getDirectDependencies().isEmpty()) {
                JsonArray directDependencies = Json.createReader(new StringReader(component.getDirectDependencies())).readArray();
                for (JsonValue directDependency : directDependencies) {
                    if (component.getDependencyGraph() == null) {
                        component.setDependencyGraph(new HashSet<>());
                    }
                    String uuid = directDependency.asJsonObject().getString("uuid");
                    if (!dependencyGraph.containsKey(uuid) && !addToDependencyGraph.containsKey(uuid)) {
                        Component childNode = this.getObjectByUuid(Component.class, uuid);
                        addToDependencyGraph.put(childNode.getUuid().toString(), childNode);
                        component.getDependencyGraph().add(childNode.getUuid().toString());
                    } else {
                        component.getDependencyGraph().add(uuid);
                    }
                }
            }
        }
        dependencyGraph.putAll(addToDependencyGraph);
    }

    @Override
    public List<ComponentProperty> getComponentProperties(final Component component, final String groupName, final String propertyName) {
        final Query<ComponentProperty> query = pm.newQuery(ComponentProperty.class);
        query.setFilter("component == :component && groupName == :groupName && propertyName == :propertyName");
        query.setParameters(component, groupName, propertyName);
        try {
            return List.copyOf(query.executeList());
        } finally {
            query.closeAll();
        }
    }

    @Override
    public List<ComponentProperty> getComponentProperties(final Component component) {
        final Query<ComponentProperty> query = pm.newQuery(ComponentProperty.class);
        query.setFilter("component == :component");
        query.setParameters(component);
        query.setOrdering("groupName ASC, propertyName ASC, id ASC");
        try {
            return List.copyOf(query.executeList());
        } finally {
            query.closeAll();
        }
    }

    @Override
    public ComponentProperty createComponentProperty(final Component component,
                                                     final String groupName,
                                                     final String propertyName,
                                                     final String propertyValue,
                                                     final IConfigProperty.PropertyType propertyType,
                                                     final String description) {
        final ComponentProperty property = new ComponentProperty();
        property.setComponent(component);
        property.setGroupName(groupName);
        property.setPropertyName(propertyName);
        property.setPropertyValue(propertyValue);
        property.setPropertyType(propertyType);
        property.setDescription(description);
        return persist(property);
    }

    @Override
    public long deleteComponentPropertyByUuid(final Component component, final UUID uuid) {
        final Query<ComponentProperty> query = pm.newQuery(ComponentProperty.class);
        query.setFilter("component == :component && uuid == :uuid");
        try {
            return query.deletePersistentAll(component, uuid);
        } finally {
            query.closeAll();
        }
    }

    public void synchronizeComponentProperties(final Component component, final List<ComponentProperty> properties) {
        assertPersistent(component, "component must be persistent");

        if (properties == null || properties.isEmpty()) {
            // TODO: We currently remove all existing properties that are no longer included in the BOM.
            //   This is to stay consistent with the BOM being the source of truth. However, this may feel
            //   counter-intuitive to some users, who might expect their manual changes to persist.
            //   If we want to support that, we need a way to track which properties were added and / or
            //   modified manually.
            if (component.getProperties() != null) {
                pm.deletePersistentAll(component.getProperties());
            }

            return;
        }

        properties.forEach(property -> assertNonPersistent(property, "property must not be persistent"));

        if (component.getProperties() == null || component.getProperties().isEmpty()) {
            for (final ComponentProperty property : properties) {
                property.setComponent(component);
                pm.makePersistent(property);
            }

            return;
        }

        // Group properties by group, name, and value. Because CycloneDX supports duplicate
        // property names, uniqueness can only be determined by also considering the value.
        final var existingPropertiesByIdentity = component.getProperties().stream()
                .collect(Collectors.toMap(ComponentProperty.Identity::new, Function.identity()));
        final var incomingPropertiesByIdentity = properties.stream()
                .collect(Collectors.toMap(ComponentProperty.Identity::new, Function.identity()));

        final var propertyIdentities = new HashSet<ComponentProperty.Identity>();
        propertyIdentities.addAll(existingPropertiesByIdentity.keySet());
        propertyIdentities.addAll(incomingPropertiesByIdentity.keySet());

        for (final ComponentProperty.Identity identity : propertyIdentities) {
            final ComponentProperty existingProperty = existingPropertiesByIdentity.get(identity);
            final ComponentProperty incomingProperty = incomingPropertiesByIdentity.get(identity);

            if (existingProperty == null) {
                incomingProperty.setComponent(component);
                pm.makePersistent(incomingProperty);
            } else if (incomingProperty == null) {
                pm.deletePersistent(existingProperty);
            }
        }
    }

}
