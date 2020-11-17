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
import alpine.model.ConfigProperty;
import alpine.notification.NotificationLevel;
import alpine.persistence.AlpineQueryManager;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import alpine.util.BooleanUtil;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.datanucleus.api.jdo.JDOQuery;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.*;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.Publisher;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import javax.jdo.FetchPlan;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.json.JsonObject;
import java.util.*;
import java.util.stream.Collectors;

/**
 * This QueryManager provides a concrete extension of {@link AlpineQueryManager} by
 * providing methods that operate on the Dependency-Track specific models.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@SuppressWarnings({"UnusedReturnValue", "unused"})
public class QueryManager extends AlpineQueryManager {

    /**
     * Default constructor.
     */
    public QueryManager() {
        super();
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    public QueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param request an AlpineRequest object
     */
    public QueryManager(final AlpineRequest request) {
        super(request);
    }

    /**
     * Returns a list of all projects.
     * @return a List of Projects
     */
    public PaginatedResult getProjects(final boolean includeMetrics, final boolean excludeInactive) {
        final PaginatedResult result;
        final Query<Project> query = pm.newQuery(Project.class);
        if (orderBy == null) {
            query.setOrdering("name asc, version desc");
        }
        if (filter != null) {
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            final Tag tag = getTagByName(filter.trim());
            if (tag != null) {
                if (excludeInactive) {
                    query.setFilter("(name.toLowerCase().matches(:name) || tags.contains(:tag)) && active == true");
                } else {
                    query.setFilter("name.toLowerCase().matches(:name) || tags.contains(:tag)");
                }
                result = execute(query, filterString, tag);
            } else {
                if (excludeInactive) {
                    query.setFilter("name.toLowerCase().matches(:name) && active == true");
                } else {
                    query.setFilter("name.toLowerCase().matches(:name)");
                }
                result = execute(query, filterString);
            }
        } else {
            if (excludeInactive) {
                query.setFilter("active == true");
            }
            result = execute(query);
        }
        if (includeMetrics) {
            // Populate each Project object in the paginated result with transitive related
            // data to minimize the number of round trips a client needs to make, process, and render.
            for (Project project : result.getList(Project.class)) {
                project.setMetrics(getMostRecentProjectMetrics(project));
            }
        }
        return result;
    }

    /**
     * Returns a list of all projects.
     * @return a List of Projects
     */
    public PaginatedResult getProjects(final boolean includeMetrics) {
        return getProjects(includeMetrics, false);
    }

    /**
     * Returns a list of all projects.
     * @return a List of Projects
     */
    public PaginatedResult getProjects() {
        return getProjects(false);
    }

    /**
     * Returns a list of all projects.
     * This method if designed NOT to provide paginated results.
     * @return a List of Projects
     */
    public List<Project> getAllProjects() {
        final Query<Project> query = pm.newQuery(Project.class);
        query.setOrdering("name asc");
        return query.executeResultList(Project.class);
    }

    /**
     * Returns a list of projects by it's name.
     * @param name the name of the Projects (required)
     * @return a List of Project objects
     */
    public PaginatedResult getProjects(final String name, final boolean excludeInactive) {
        final Query<Project> query = pm.newQuery(Project.class);
        if (orderBy == null) {
            query.setOrdering("version desc");
        }
        if (excludeInactive) {
            query.setFilter("name == :name && active == true");
        } else {
            query.setFilter("name == :name");
        }
        return execute(query, name);
    }

    /**
     * Returns a project by it's name and version.
     * @param name the name of the Project (required)
     * @param version the version of the Project (or null)
     * @return a Project object, or null if not found
     */
    public Project getProject(final String name, final String version) {
        final Query<Project> query = pm.newQuery(Project.class, "name == :name && version == :version");
        return singleResult(query.execute(name, version));
    }

    /**
     * Returns a paginated result of projects by tag.
     * @param tag the tag associated with the Project
     * @return a List of Projects that contain the tag
     */
    public PaginatedResult getProjects(final Tag tag, final boolean includeMetrics) {
        final PaginatedResult result;
        final Query<Project> query = pm.newQuery(Project.class, "tags.contains(:tag)");
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        result = execute(query, tag);
        if (includeMetrics) {
            // Populate each Project object in the paginated result with transitive related
            // data to minimize the number of round trips a client needs to make, process, and render.
            for (Project project : result.getList(Project.class)) {
                project.setMetrics(getMostRecentProjectMetrics(project));
            }
        }
        return result;
    }

    /**
     * Returns a paginated result of projects by tag.
     * @param tag the tag associated with the Project
     * @return a List of Projects that contain the tag
     */
    public PaginatedResult getProjects(final Tag tag) {
        return getProjects(tag, false);
    }

    /**
     * Returns a list of Tag objects what have been resolved. It resolved
     * tags by querying the database to retrieve the tag. If the tag does
     * not exist, the tag will be created and returned with other resolved
     * tags.
     * @param tags a List of Tags to resolve
     * @return List of resolved Tags
     */
    private synchronized List<Tag> resolveTags(final List<Tag> tags) {
        if (tags == null) {
            return new ArrayList<>();
        }
        final List<Tag> resolvedTags = new ArrayList<>();
        final List<String> unresolvedTags = new ArrayList<>();
        for (final Tag tag: tags) {
            final String trimmedTag = StringUtils.trimToNull(tag.getName());
            if (trimmedTag != null) {
                final Tag resolvedTag = getTagByName(trimmedTag);
                if (resolvedTag != null) {
                    resolvedTags.add(resolvedTag);
                } else {
                    unresolvedTags.add(trimmedTag);
                }
            }
        }
        resolvedTags.addAll(createTags(unresolvedTags));
        return resolvedTags;
    }

    /**
     * Returns a list of Tag objects by name.
     * @param name the name of the Tag
     * @return a Tag object
     */
    public Tag getTagByName(final String name) {
        final String trimmedTag = StringUtils.trimToNull(name);
        final Query<Tag> query = pm.newQuery(Tag.class, "name == :name");
        return singleResult(query.execute(trimmedTag));
    }

    /**
     * Creates a new Tag object with the specified name.
     * @param name the name of the Tag to create
     * @return the created Tag object
     */
    public Tag createTag(final String name) {
        final String trimmedTag = StringUtils.trimToNull(name);
        final Tag resolvedTag = getTagByName(trimmedTag);
        if (resolvedTag != null) {
            return resolvedTag;
        }
        final Tag tag = new Tag();
        tag.setName(trimmedTag);
        return persist(tag);
    }

    /**
     * Creates one or more Tag objects from the specified name(s).
     * @param names the name(s) of the Tag(s) to create
     * @return the created Tag object(s)
     */
    private List<Tag> createTags(final List<String> names) {
        final List<Tag> newTags = new ArrayList<>();
        for (final String name: names) {
            final String trimmedTag = StringUtils.trimToNull(name);
            if (getTagByName(trimmedTag) == null) {
                final Tag tag = new Tag();
                tag.setName(trimmedTag);
                newTags.add(tag);
            }
        }
        return new ArrayList<>(persist(newTags));
    }

    /**
     * Creates a new Project.
     * @param name the name of the project to create
     * @param description a description of the project
     * @param version the project version
     * @param tags a List of Tags - these will be resolved if necessary
     * @param parent an optional parent Project
     * @param purl an optional Package URL
     * @param active specified if the project is active
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return the created Project
     */
    public Project createProject(String name, String description, String version, List<Tag> tags, Project parent, String purl, boolean active, boolean commitIndex) {
        final Project project = new Project();
        project.setName(name);
        project.setDescription(description);
        project.setVersion(version);
        if (parent != null) {
            project.setParent(parent);
        }
        project.setPurl(purl);
        project.setActive(active);
        final Project result = persist(project);

        final List<Tag> resolvedTags = resolveTags(tags);
        bind(project, resolvedTags);

        Event.dispatch(new IndexEvent(IndexEvent.Action.CREATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, Project.class);
        return result;
    }

    /**
     * Updates an existing Project.
     * @param uuid the uuid of the project to update
     * @param name the name of the project
     * @param description a description of the project
     * @param version the project version
     * @param tags a List of Tags - these will be resolved if necessary
     * @param purl an optional Package URL
     * @param active specified if the project is active
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return the updated Project
     */
    public Project updateProject(UUID uuid, String name, String description, String version, List<Tag> tags, String purl, boolean active, boolean commitIndex) {
        final Project project = getObjectByUuid(Project.class, uuid);
        project.setName(name);
        project.setDescription(description);
        project.setVersion(version);
        project.setPurl(purl);
        project.setActive(active);

        final List<Tag> resolvedTags = resolveTags(tags);
        bind(project, resolvedTags);

        final Project result = persist(project);
        Event.dispatch(new IndexEvent(IndexEvent.Action.UPDATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, Project.class);
        return result;
    }

    public Project clone(UUID from, String newVersion, boolean includeTags, boolean includeProperties,
                         boolean includeDependencies, boolean includeAuditHistory) {
        final Project source = getObjectByUuid(Project.class, from, Project.FetchGroup.ALL.name());
        if (source == null) {
            return null;
        }
        Project project = new Project();
        project.setName(source.getName());
        project.setDescription(source.getDescription());
        project.setVersion(newVersion);
        project.setActive(source.isActive());
        if (project.getPurl() != null && newVersion != null) {
            try {
                final PackageURL sourcePurl = new PackageURL(project.getPurl());
                final PackageURL purl = new PackageURL(
                        sourcePurl.getType(),
                        sourcePurl.getNamespace(),
                        sourcePurl.getName(),
                        newVersion, null, null
                );
                project.setPurl(purl.canonicalize());
            } catch (MalformedPackageURLException e) {
                // throw it away
            }
        }
        project.setParent(source.getParent());
        project = persist(project);

        if (includeTags) {
            for (final Tag tag: source.getTags()) {
                tag.getProjects().add(project);
                persist(tag);
            }
        }

        if (includeProperties && source.getProperties() != null) {
            for (final ProjectProperty sourceProperty: source.getProperties()) {
                final ProjectProperty property = new ProjectProperty();
                property.setProject(project);
                property.setPropertyType(sourceProperty.getPropertyType());
                property.setGroupName(sourceProperty.getGroupName());
                property.setPropertyName(sourceProperty.getPropertyName());
                property.setPropertyValue(sourceProperty.getPropertyValue());
                property.setDescription(sourceProperty.getDescription());
                persist(property);
            }
        }

        if (includeDependencies) {
            final List<Component> sourceComponents = getAllComponents(source);
            if (sourceComponents != null) {
                for (final Component sourceComponent: sourceComponents) {
                    cloneComponent(sourceComponent, false);
                }
            }
        }

        if (includeAuditHistory) {
            final List<Analysis> analyses = getAnalyses(source);
            if (analyses != null) {
                for (final Analysis sourceAnalysis: analyses) {
                    Analysis analysis = new Analysis();
                    analysis.setAnalysisState(sourceAnalysis.getAnalysisState());
                    analysis.setComponent(sourceAnalysis.getComponent());
                    analysis.setVulnerability(sourceAnalysis.getVulnerability());
                    analysis.setSuppressed(sourceAnalysis.isSuppressed());
                    analysis = persist(analysis);
                    if (sourceAnalysis.getAnalysisComments() != null) {
                        for (final AnalysisComment sourceComment: sourceAnalysis.getAnalysisComments()) {
                            final AnalysisComment analysisComment = new AnalysisComment();
                            analysisComment.setAnalysis(analysis);
                            analysisComment.setTimestamp(sourceComment.getTimestamp());
                            analysisComment.setComment(sourceComment.getComment());
                            analysisComment.setCommenter(sourceComment.getCommenter());
                            persist(analysisComment);
                        }
                    }
                }
            }
        }

        project = getObjectById(Project.class, project.getId());
        Event.dispatch(new IndexEvent(IndexEvent.Action.CREATE, pm.detachCopy(project)));
        commitSearchIndex(true, Project.class);
        return project;
    }

    /**
     * Updates the last time a bom was imported.
     * @param date the date of the last bom import
     * @param bomFormat the format and version of the bom format
     * @return the updated Project
     */
    public Project updateLastBomImport(Project p, Date date, String bomFormat) {
        final Project project = getObjectById(Project.class, p.getId());
        project.setLastBomImport(date);
        project.setLastBomImportFormat(bomFormat);
        return persist(project);
    }

    /**
     * Deletes a Project and all objects dependant on the project.
     * @param project the Project to delete
     */
    public void recursivelyDelete(Project project) {
        if (project.getChildren() != null) {
            for (final Project child: project.getChildren()) {
                recursivelyDelete(child);
            }
        }
        pm.getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
        final Project result = pm.getObjectById(Project.class, project.getId());
        Event.dispatch(new IndexEvent(IndexEvent.Action.DELETE, pm.detachCopy(result)));

        deleteAnalysisTrail(project);
        deleteViolationAnalysisTrail(project);
        deleteMetrics(project);
        for (final Component c: getAllComponents(project)) {
            recursivelyDelete(c, false);
        }
        deleteBoms(project);
        removeProjectFromNotificationRules(project);
        delete(project.getProperties());
        delete(getBoms(project));
        delete(project.getChildren());
        delete(project);
    }

    /**
     * Creates a key/value pair (ProjectProperty) for the specified Project.
     * @param project the Project to create the property for
     * @param groupName the group name of the property
     * @param propertyName the name of the property
     * @param propertyValue the value of the property
     * @param propertyType the type of property
     * @param description a description of the property
     * @return the created ProjectProperty object
     */
    public ProjectProperty createProjectProperty(final Project project, final String groupName, final String propertyName,
                                                 final String propertyValue, final ProjectProperty.PropertyType propertyType,
                                                 final String description) {
        final ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName(groupName);
        property.setPropertyName(propertyName);
        property.setPropertyValue(propertyValue);
        property.setPropertyType(propertyType);
        property.setDescription(description);
        return persist(property);
    }

    /**
     * Returns a ProjectProperty with the specified groupName and propertyName.
     * @param project the project the property belongs to
     * @param groupName the group name of the config property
     * @param propertyName the name of the property
     * @return a ProjectProperty object
     */
    public ProjectProperty getProjectProperty(final Project project, final String groupName, final String propertyName) {
        final Query<ProjectProperty> query = this.pm.newQuery(ProjectProperty.class, "project == :project && groupName == :groupName && propertyName == :propertyName");
        return singleResult(query.execute(project, groupName, propertyName));
    }

    /**
     * Returns a List of ProjectProperty's for the specified project.
     * @param project the project the property belongs to
     * @return a List ProjectProperty objects
     */
    @SuppressWarnings("unchecked")
    public List<ProjectProperty> getProjectProperties(final Project project) {
        final Query<ProjectProperty> query = this.pm.newQuery(ProjectProperty.class, "project == :project");
        query.setOrdering("groupName asc, propertyName asc");
        return (List<ProjectProperty>)query.execute(project);
    }

    /**
     * Creates a new Bom.
     * @param project the Project to create a Bom for
     * @param imported the Date when the bom was imported
     * @return a new Bom object
     */
    public Bom createBom(Project project, Date imported, Bom.Format format, String version) {
        final Bom bom = new Bom();
        bom.setImported(imported);
        bom.setProject(project);
        bom.setBomFormat(format);
        bom.setSpecVersion(version);
        return persist(bom);
    }

    /**
     * Returns a list of all Bom for the specified Project.
     * @param project the Project to retrieve boms for
     * @return a List of Boms
     */
    @SuppressWarnings("unchecked")
    private List<Bom> getBoms(Project project) {
        final Query<Bom> query = pm.newQuery(Bom.class, "project == :project");
        return (List<Bom>) query.execute(project);
    }

    /**
     * Deletes boms belonging to the specified Project.
     * @param project the Project to delete boms for
     */
    private void deleteBoms(Project project) {
        final Query<Bom> query = pm.newQuery(Bom.class, "project == :project");
        query.deletePersistentAll(project);
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
        return query.executeResultList(Component.class);
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
        if (hash.length() == 32) {
            query = pm.newQuery(Component.class, "md5 == :hash");
        } else if (hash.length() == 40) {
            query = pm.newQuery(Component.class, "sha1 == :hash");
        } else if (hash.length() == 64) {
            query = pm.newQuery(Component.class, "sha256 == :hash || sha3_256 == :hash || blake2b_256 == :hash");
        } else if (hash.length() == 96) {
            query = pm.newQuery(Component.class, "sha384 == :hash || sha3_384 == :hash || blake2b_384 == :hash");
        } else if (hash.length() == 128) {
            query = pm.newQuery(Component.class, "sha512 == :hash || sha3_512 == :hash || blake2b_512 == :hash");
        } else {
            query = pm.newQuery(Component.class, "blake3 == :hash");
        }
        return execute(query, hash);
    }

    /**
     * Returns Components by their identity.
     * @param identity the ComponentIdentity to query against
     * @return a list of components
     */
    public PaginatedResult getComponents(ComponentIdentity identity) {
        if (identity == null) {
            return null;
        }
        final Query<Component> query;
        if (identity.getGroup() != null || identity.getName() != null || identity.getVersion() != null) {
            final Map<String, String> map = new HashMap<>();
            String filter = "";
            if (identity.getGroup() != null) {
                filter += " group.toLowerCase().matches(:group) ";
                final String filterString = ".*" + identity.getGroup().toLowerCase() + ".*";
                map.put("group", filterString);
            }
            if (identity.getName() != null) {
                if (identity.getGroup() != null) {
                    filter += " && ";
                }
                filter += " name.toLowerCase().matches(:name) ";
                final String filterString = ".*" + identity.getName().toLowerCase() + ".*";
                map.put("name", filterString);
            }
            if (identity.getVersion() != null) {
                if (identity.getGroup() != null || identity.getName() != null) {
                    filter += " && ";
                }
                filter += " version.toLowerCase().matches(:version) ";
                final String filterString = ".*" + identity.getVersion().toLowerCase() + ".*";
                map.put("version", filterString);
            }
            query = pm.newQuery(Component.class, filter);
            return execute(query, map);
        } else if (identity.getPurl() != null) {
            query = pm.newQuery(Component.class, "purl.toLowerCase().matches(:purl)");
            final String filterString = ".*" + identity.getPurl().canonicalize().toLowerCase() + ".*";
            return execute(query, filterString);
        } else if (identity.getCpe() != null) {
            query = pm.newQuery(Component.class, "cpe.toLowerCase().matches(:cpe)");
            final String filterString = ".*" + identity.getCpe().toLowerCase() + ".*";
            return execute(query, filterString);
        } else if (identity.getSwidTagId() != null) {
            query = pm.newQuery(Component.class, "swidTagId.toLowerCase().matches(:swidTagId)");
            final String filterString = ".*" + identity.getSwidTagId().toLowerCase() + ".*";
            return execute(query, filterString);
        } else {
            return new PaginatedResult();
        }
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

    public Component cloneComponent(Component sourceComponent, boolean commitIndex) {
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
        component.setVulnerabilities(sourceComponent.getVulnerabilities());
        component.setProject(sourceComponent.getProject());
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
    private void deleteComponents(Project project) {
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
     * Returns a List of all License objects.
     * @return a List of all License objects
     */
    public PaginatedResult getLicenses() {
        final Query<License> query = pm.newQuery(License.class);
        query.getFetchPlan().addGroup(License.FetchGroup.ALL.name());
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        if (filter != null) {
            query.setFilter("name.toLowerCase().matches(:filter) || licenseId.toLowerCase().matches(:filter)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a concise List of all Licenses.
     * This method if designed NOT to provide paginated results.
     * @return a List of License objects
     */
    @SuppressWarnings("unchecked")
    public List<License> getAllLicensesConcise() {
        final Query<License> query = pm.newQuery(License.class);
        query.getFetchPlan().addGroup(License.FetchGroup.CONCISE.name());
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        return (List<License>)query.execute();
    }

    /**
     * Returns a License object from the specified SPDX license ID.
     * @param licenseId the SPDX license ID to retrieve
     * @return a License object, or null if not found
     */
    public License getLicense(String licenseId) {
        final Query<License> query = pm.newQuery(License.class, "licenseId == :licenseId");
        query.getFetchPlan().addGroup(License.FetchGroup.ALL.name());
        return singleResult(query.execute(licenseId));
    }

    /**
     * Creates a new License.
     * @param license the License object to create
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a created License object
     */
    private License createLicense(License license, boolean commitIndex) {
        final License result = persist(license);
        Event.dispatch(new IndexEvent(IndexEvent.Action.CREATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, License.class);
        return result;
    }

    /**
     * Updates a license.
     * @param transientLicense the license to update
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a License object
     */
    private License updateLicense(License transientLicense, boolean commitIndex) {
        final License license;
        if (transientLicense.getId() > 0) {
            license = getObjectById(License.class, transientLicense.getId());
        } else {
            license = getLicense(transientLicense.getLicenseId());
        }

        if (license != null) {
            license.setLicenseId(transientLicense.getLicenseId());
            license.setName(transientLicense.getName());
            license.setText(transientLicense.getText());
            license.setHeader(transientLicense.getHeader());
            license.setTemplate(transientLicense.getTemplate());
            license.setOsiApproved(transientLicense.isOsiApproved());
            license.setFsfLibre(transientLicense.isFsfLibre());
            license.setDeprecatedLicenseId(transientLicense.isDeprecatedLicenseId());
            license.setComment(transientLicense.getComment());
            license.setSeeAlso(transientLicense.getSeeAlso());

            final License result = persist(license);
            Event.dispatch(new IndexEvent(IndexEvent.Action.UPDATE, pm.detachCopy(result)));
            commitSearchIndex(commitIndex, License.class);
            return result;
        }
        return null;
    }

    /**
     * Synchronize a License, updating it if it needs updating, or creating it if it doesn't exist.
     * @param license the License object to synchronize
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a synchronize License object
     */
    License synchronizeLicense(License license, boolean commitIndex) {
        License result = updateLicense(license, commitIndex);
        if (result == null) {
            result = createLicense(license, commitIndex);
        }
        return result;
    }

    /**
     * Returns a List of all Policy objects.
     * @return a List of all Policy objects
     */
    public PaginatedResult getPolicies() {
        final Query<Policy> query = pm.newQuery(Policy.class);
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        if (filter != null) {
            query.setFilter("name.toLowerCase().matches(:filter)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a List of all Policy objects.
     * This method if designed NOT to provide paginated results.
     * @return a List of all Policy objects
     */
    public List<Policy> getAllPolicies() {
        final Query<Policy> query = pm.newQuery(Policy.class);
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        return query.executeResultList(Policy.class);
    }

    /**
     * Returns a policy by it's name.
     * @param name the name of the policy (required)
     * @return a Policy object, or null if not found
     */
    public Policy getPolicy(final String name) {
        final Query<Policy> query = pm.newQuery(Policy.class, "name == :name");
        return singleResult(query.execute(name));
    }

    /**
     * Creates a new Policy.
     * @param name the name of the policy to create
     * @param operator the operator
     * @param violationState the violation state
     * @return the created Policy
     */
    public Policy createPolicy(String name, Policy.Operator operator, Policy.ViolationState violationState) {
        final Policy policy = new Policy();
        policy.setName(name);
        policy.setOperator(operator);
        policy.setViolationState(violationState);
        return persist(policy);
    }

    /**
     * Creates a policy condition for the specified Project.
     * @return the created PolicyCondition object
     */
    public PolicyCondition createPolicyCondition(final Policy policy, final PolicyCondition.Subject subject,
                                                 final PolicyCondition.Operator operator, final String value) {
        final PolicyCondition pc = new PolicyCondition();
        pc.setPolicy(policy);
        pc.setSubject(subject);
        pc.setOperator(operator);
        pc.setValue(value);
        return persist(pc);
    }

    /**
     * Updates a policy condition.
     * @return the updated PolicyCondition object
     */
    public PolicyCondition updatePolicyCondition(final PolicyCondition policyCondition) {
        final PolicyCondition pc = getObjectByUuid(PolicyCondition.class, policyCondition.getUuid());
        pc.setSubject(policyCondition.getSubject());
        pc.setOperator(policyCondition.getOperator());
        pc.setValue(policyCondition.getValue());
        return persist(pc);
    }

    /**
     * Intelligently adds dependencies for components that are not already a dependency
     * of the specified project and removes the dependency relationship for components
     * that are not in the list of specified components.
     * @param component the project to bind components to
     * @param policyViolations the complete list of existing dependent components
     */
    public synchronized void reconcilePolicyViolations(final Component component, final List<PolicyViolation> policyViolations) {
        // Removes violations as dependencies to the project for all
        // components not included in the list provided
        List<PolicyViolation> markedForDeletion = new ArrayList<>();
        for (final PolicyViolation existingViolation: getAllPolicyViolations(component)) {
            boolean keep = false;
            for (final PolicyViolation violation: policyViolations) {
                if (violation.getType() == existingViolation.getType()
                        && violation.getPolicyCondition().getId() == existingViolation.getPolicyCondition().getId()
                        && violation.getComponent().getId() == existingViolation.getComponent().getId())
                {
                    keep = true;
                    break;
                }
            }
            if (!keep) {
                markedForDeletion.add(existingViolation);
            }
        }
        if (!markedForDeletion.isEmpty()) {
            delete(markedForDeletion);
        }
    }

    /**
     * Adds a policy violation
     * @param pv the policy violation to add
     */
    public synchronized PolicyViolation addPolicyViolationIfNotExist(final PolicyViolation pv) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class, "type == :type && component == :component && policyCondition == :policyCondition");
        PolicyViolation result = singleResult(query.execute(pv.getType(), pv.getComponent(), pv.getPolicyCondition()));
        if (result == null) {
            result = persist(pv);
        }
        return result;
    }

    /**
     * Returns a List of all Policy objects.
     * This method if designed NOT to provide paginated results.
     * @return a List of all Policy objects
     */
    public List<PolicyViolation> getAllPolicyViolations() {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class);
        if (orderBy == null) {
            query.setOrdering("timestamp desc, project.name, project.version, component.name, component.version");
        }
        return query.executeResultList(PolicyViolation.class);
    }

    /**
     * Returns a List of all Policy objects.
     * This method if designed NOT to provide paginated results.
     * @return a List of all Policy objects
     */
    @SuppressWarnings("unchecked")
    public List<PolicyViolation> getAllPolicyViolations(final PolicyCondition policyCondition) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class, "policyCondition.id == :pid");
        if (orderBy == null) {
            query.setOrdering("timestamp desc, project.name, project.version, component.name, component.version");
        }
        return (List<PolicyViolation>)query.execute(policyCondition.getId());
    }

    /**
     * Returns a List of all Policy objects for a specific component.
     * This method if designed NOT to provide paginated results.
     * @return a List of all Policy objects
     */
    @SuppressWarnings("unchecked")
    public List<PolicyViolation> getAllPolicyViolations(final Component component) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class, "component.id == :cid");
        if (orderBy == null) {
            query.setOrdering("timestamp desc, project.name, project.version, component.name, component.version");
        }
        return (List<PolicyViolation>)query.execute(component.getId());
    }

    /**
     * Returns a List of all Policy objects for a specific component.
     * This method if designed NOT to provide paginated results.
     * @return a List of all Policy objects
     */
    @SuppressWarnings("unchecked")
    public List<PolicyViolation> getAllPolicyViolations(final Project project) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class, "project.id == :pid");
        if (orderBy == null) {
            query.setOrdering("timestamp desc, component.name, component.version");
        }
        return (List<PolicyViolation>)query.execute(project.getId());
    }

    /**
     * Returns a List of all Policy violations for a specific project.
     * @param project the project to retrieve violations for
     * @return a List of all Policy violations
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getPolicyViolations(final Project project) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class, "project.id == :pid");
        if (orderBy == null) {
            query.setOrdering("timestamp desc, component.name, component.version");
        }
        final PaginatedResult result = execute(query, project.getId());
        for (final PolicyViolation violation: result.getList(PolicyViolation.class)) {
            violation.getPolicyCondition().getPolicy(); // force policy to ne included since its not the default
            violation.getComponent().getResolvedLicense(); // force resolved license to ne included since its not the default
        }
        return result;
    }

    /**
     * Returns a List of all Policy violations for a specific component.
     * @param component the component to retrieve violations for
     * @return a List of all Policy violations
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getPolicyViolations(final Component component) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class, "component.id == :cid");
        if (orderBy == null) {
            query.setOrdering("timestamp desc");
        }
        final PaginatedResult result = execute(query, component.getId());
        for (final PolicyViolation violation: result.getList(PolicyViolation.class)) {
            violation.getPolicyCondition().getPolicy(); // force policy to ne included since its not the default
            violation.getComponent().getResolvedLicense(); // force resolved license to ne included since its not the default
        }
        return result;
    }

    /**
     * Returns a List of all Policy violations for the entire portfolio.
     * @return a List of all Policy violations
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult getPolicyViolations() {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class);
        if (orderBy == null) {
            query.setOrdering("timestamp desc, project.name, project.version, component.name, component.version");
        }
        final PaginatedResult result = execute(query);
        for (final PolicyViolation violation: result.getList(PolicyViolation.class)) {
            violation.getPolicyCondition().getPolicy(); // force policy to ne included since its not the default
            violation.getComponent().getResolvedLicense(); // force resolved license to ne included since its not the default
        }
        return result;
    }

    /**
     * Returns a ViolationAnalysis for the specified Component and PolicyViolation.
     * @param component the Component
     * @param policyViolation the PolicyViolation
     * @return a ViolationAnalysis object, or null if not found
     */
    public ViolationAnalysis getViolationAnalysis(Component component, PolicyViolation policyViolation) {
        final Query<ViolationAnalysis> query = pm.newQuery(ViolationAnalysis.class, "component == :component && policyViolation == :policyViolation");
        return singleResult(query.execute(component, policyViolation));
    }

    /**
     * Documents a new violation analysis. Creates a new ViolationAnalysis object if one doesn't already exists and appends
     * the specified comment along with a timestamp in the ViolationAnalysisComment trail.
     * @param component the Component
     * @param policyViolation the PolicyViolation
     * @return a ViolationAnalysis object
     */
    public ViolationAnalysis makeViolationAnalysis(Component component, PolicyViolation policyViolation,
                                 ViolationAnalysisState violationAnalysisState, Boolean isSuppressed) {
        if (violationAnalysisState == null) {
            violationAnalysisState = ViolationAnalysisState.NOT_SET;
        }
        ViolationAnalysis violationAnalysis = getViolationAnalysis(component, policyViolation);
        if (violationAnalysis == null) {
            violationAnalysis = new ViolationAnalysis();
            violationAnalysis.setComponent(component);
            violationAnalysis.setPolicyViolation(policyViolation);
        }
        if (isSuppressed != null) {
            violationAnalysis.setSuppressed(isSuppressed);
        }
        violationAnalysis.setViolationAnalysisState(violationAnalysisState);
        violationAnalysis = persist(violationAnalysis);
        return getViolationAnalysis(violationAnalysis.getComponent(), violationAnalysis.getPolicyViolation());
    }

    /**
     * Adds a new violation analysis comment to the specified violation analysis.
     * @param violationAnalysis the violation analysis object to add a comment to
     * @param comment the comment to make
     * @param commenter the name of the principal who wrote the comment
     * @return a new ViolationAnalysisComment object
     */
    public ViolationAnalysisComment makeViolationAnalysisComment(ViolationAnalysis violationAnalysis, String comment, String commenter) {
        if (violationAnalysis == null || comment == null) {
            return null;
        }
        final ViolationAnalysisComment violationAnalysisComment = new ViolationAnalysisComment();
        violationAnalysisComment.setViolationAnalysis(violationAnalysis);
        violationAnalysisComment.setTimestamp(new Date());
        violationAnalysisComment.setComment(comment);
        violationAnalysisComment.setCommenter(commenter);
        return persist(violationAnalysisComment);
    }

    /**
     * Deleted all violation analysis and comments associated for the specified Component.
     * @param component the Component to delete violation analysis for
     */
    private void deleteViolationAnalysisTrail(Component component) {
        final Query<ViolationAnalysis> query = pm.newQuery(ViolationAnalysis.class, "component == :component");
        query.deletePersistentAll(component);
    }

    /**
     * Deleted all violation analysis and comments associated for the specified Project.
     * @param project the Project to delete violation analysis for
     */
    private void deleteViolationAnalysisTrail(Project project) {
        final Query<ViolationAnalysis> query = pm.newQuery(ViolationAnalysis.class, "project == :project");
        query.deletePersistentAll(project);
    }

    /**
     * Deleted all violation analysis and comments associated for the specified Policy Condition.
     * @param policyViolation policy violation to delete violation analysis for
     */
    private void deleteViolationAnalysisTrail(PolicyViolation policyViolation) {
        final Query<ViolationAnalysis> query = pm.newQuery(ViolationAnalysis.class, "policyViolation.id == :pid");
        query.deletePersistentAll(policyViolation.getId());
    }

    /**
     * Returns a List of all LicenseGroup objects.
     * @return a List of all LicenseGroup objects
     */
    public PaginatedResult getLicenseGroups() {
        final Query<LicenseGroup> query = pm.newQuery(LicenseGroup.class);
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        if (filter != null) {
            query.setFilter("name.toLowerCase().matches(:filter)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a license group by it's name.
     * @param name the name of the license group (required)
     * @return a LicenseGroup object, or null if not found
     */
    public LicenseGroup getLicenseGroup(final String name) {
        final Query<LicenseGroup> query = pm.newQuery(LicenseGroup.class, "name == :name");
        return singleResult(query.execute(name));
    }

    /**
     * Creates a new LicenseGroup.
     * @param name the name of the license group to create
     * @return the created LicenseGroup
     */
    public LicenseGroup createLicenseGroup(String name) {
        final LicenseGroup licenseGroup = new LicenseGroup();
        licenseGroup.setName(name);
        return persist(licenseGroup);
    }

    /**
     * Determines if the specified LicenseGroup contains the specified License.
     * @param lg the LicenseGroup to query
     * @param license the License to query for
     * @return true if License is part of LicenseGroup, false if not
     */
    public boolean doesLicenseGroupContainLicense(final LicenseGroup lg, final License license) {
        final License l = getObjectById(License.class, license.getId());
        final Query<LicenseGroup> query = pm.newQuery(LicenseGroup.class, "id == :id && licenses.contains(:license)");
        return singleResult(query.execute(lg.getId(), l)) != null;
    }

    /**
     * Creates a new Vulnerability.
     * @param vulnerability the vulnerability to persist
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a new vulnerability object
     */
    public Vulnerability createVulnerability(Vulnerability vulnerability, boolean commitIndex) {
        final Vulnerability result = persist(vulnerability);
        Event.dispatch(new IndexEvent(IndexEvent.Action.CREATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, Vulnerability.class);
        return result;
    }

    /**
     * Updates a vulnerability.
     * @param transientVulnerability the vulnerability to update
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a Vulnerability object
     */
    public Vulnerability updateVulnerability(Vulnerability transientVulnerability, boolean commitIndex) {
        final Vulnerability vulnerability;
        if (transientVulnerability.getId() > 0) {
            vulnerability = getObjectById(Vulnerability.class, transientVulnerability.getId());
        } else {
            vulnerability = getVulnerabilityByVulnId(transientVulnerability.getSource(), transientVulnerability.getVulnId());
        }
        if (transientVulnerability.getCwe() != null) {
            transientVulnerability.setCwe(getCweById(transientVulnerability.getCwe().getCweId()));
        }
        if (vulnerability != null) {
            vulnerability.setCreated(transientVulnerability.getCreated());
            vulnerability.setPublished(transientVulnerability.getPublished());
            vulnerability.setUpdated(transientVulnerability.getUpdated());
            vulnerability.setVulnId(transientVulnerability.getVulnId());
            vulnerability.setSource(transientVulnerability.getSource());
            vulnerability.setCredits(transientVulnerability.getCredits());
            vulnerability.setVulnerableVersions(transientVulnerability.getVulnerableVersions());
            vulnerability.setPatchedVersions(transientVulnerability.getPatchedVersions());
            vulnerability.setDescription(transientVulnerability.getDescription());
            vulnerability.setTitle(transientVulnerability.getTitle());
            vulnerability.setSubTitle(transientVulnerability.getSubTitle());
            vulnerability.setReferences(transientVulnerability.getReferences());
            vulnerability.setRecommendation(transientVulnerability.getRecommendation());
            vulnerability.setSeverity(transientVulnerability.getSeverity());
            vulnerability.setCwe(transientVulnerability.getCwe());
            vulnerability.setCvssV2Vector(transientVulnerability.getCvssV2Vector());
            vulnerability.setCvssV2BaseScore(transientVulnerability.getCvssV2BaseScore());
            vulnerability.setCvssV2ImpactSubScore(transientVulnerability.getCvssV2ImpactSubScore());
            vulnerability.setCvssV2ExploitabilitySubScore(transientVulnerability.getCvssV2ExploitabilitySubScore());
            vulnerability.setCvssV3Vector(transientVulnerability.getCvssV3Vector());
            vulnerability.setCvssV3BaseScore(transientVulnerability.getCvssV3BaseScore());
            vulnerability.setCvssV3ImpactSubScore(transientVulnerability.getCvssV3ImpactSubScore());
            vulnerability.setCvssV3ExploitabilitySubScore(transientVulnerability.getCvssV3ExploitabilitySubScore());
            if (transientVulnerability.getVulnerableSoftware() != null) {
                vulnerability.setVulnerableSoftware(transientVulnerability.getVulnerableSoftware());
            }
            final Vulnerability result = persist(vulnerability);
            Event.dispatch(new IndexEvent(IndexEvent.Action.UPDATE, pm.detachCopy(result)));
            commitSearchIndex(commitIndex, Vulnerability.class);
            return result;
        }
        return null;
    }

    /**
     * Synchronizes a vulnerability. Method first checkes to see if the vulnerability already
     * exists and if so, updates the vulnerability. If the vulnerability does not already exist,
     * this method will create a new vulnerability.
     * @param vulnerability the vulnerability to synchronize
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a Vulnerability object
     */
    public Vulnerability synchronizeVulnerability(Vulnerability vulnerability, boolean commitIndex) {
        Vulnerability result = updateVulnerability(vulnerability, commitIndex);
        if (result == null) {
            result = createVulnerability(vulnerability, commitIndex);
        }
        return result;
    }

    /**
     * Returns a vulnerability by it's name (i.e. CVE-2017-0001) and source.
     * @param source the source of the vulnerability
     * @param vulnId the name of the vulnerability
     * @return the matching Vulnerability object, or null if not found
     */
    public Vulnerability getVulnerabilityByVulnId(String source, String vulnId) {
        final Query<Vulnerability> query = pm.newQuery(Vulnerability.class, "source == :source && vulnId == :vulnId");
        query.getFetchPlan().addGroup(Vulnerability.FetchGroup.COMPONENTS.name());
        return singleResult(query.execute(source, vulnId));
    }

    /**
     * Returns a vulnerability by it's name (i.e. CVE-2017-0001) and source.
     * @param source the source of the vulnerability
     * @param vulnId the name of the vulnerability
     * @return the matching Vulnerability object, or null if not found
     */
    public Vulnerability getVulnerabilityByVulnId(Vulnerability.Source source, String vulnId) {
        return getVulnerabilityByVulnId(source.name(), vulnId);
    }

    /**
     * Returns vulnerabilities for the specified npm module
     * @param module the NPM module to query on
     * @return a list of Vulnerability objects
     */
    @Deprecated
    @SuppressWarnings("unchecked")
    //todo: determine if this is needed and delete
    public List<Vulnerability> getVulnerabilitiesForNpmModule(String module) {
        final Query<Vulnerability> query = pm.newQuery(Vulnerability.class, "source == :source && subtitle == :module");
        query.getFetchPlan().addGroup(Vulnerability.FetchGroup.COMPONENTS.name());
        return (List<Vulnerability>) query.execute(Vulnerability.Source.NPM.name(), module);
    }

    /**
     * Adds a vulnerability to a component.
     * @param vulnerability the vulnerability to add
     * @param component the component affected by the vulnerability
     * @param analyzerIdentity the identify of the analyzer
     */
    public void addVulnerability(Vulnerability vulnerability, Component component, AnalyzerIdentity analyzerIdentity) {
        this.addVulnerability(vulnerability, component, analyzerIdentity, null, null);
    }

    /**
     * Adds a vulnerability to a component.
     * @param vulnerability the vulnerability to add
     * @param component the component affected by the vulnerability
     * @param analyzerIdentity the identify of the analyzer
     * @param alternateIdentifier the optional identifier if the analyzer refers to the vulnerability by an alternative identifier
     * @param referenceUrl the optional URL that references the occurrence of the vulnerability if uniquely identified
     */
    public void addVulnerability(Vulnerability vulnerability, Component component, AnalyzerIdentity analyzerIdentity,
                                 String alternateIdentifier, String referenceUrl) {
        if (!contains(vulnerability, component)) {
            component.addVulnerability(vulnerability);
            component = persist(component);
            persist(new FindingAttribution(component, vulnerability, analyzerIdentity, alternateIdentifier, referenceUrl));
        }
    }

    /**
     * Removes a vulnerability from a component.
     * @param vulnerability the vulnerabillity to remove
     * @param component the component unaffected by the vulnerabiity
     */
    public void removeVulnerability(Vulnerability vulnerability, Component component) {
        if (contains(vulnerability, component)) {
            pm.currentTransaction().begin();
            component.removeVulnerability(vulnerability);
            pm.currentTransaction().commit();
        }
        final FindingAttribution fa = getFindingAttribution(vulnerability, component);
        if (fa != null) {
            delete(fa);
        }
    }

    /**
     * Returns a FindingAttribution object form a given vulnerability and component.
     * @param vulnerability the vulnerabillity of the finding attribution
     * @param component the component of the finding attribution
     * @return a FindingAttribution object
     */
    public FindingAttribution getFindingAttribution(Vulnerability vulnerability, Component component) {
        final Query<FindingAttribution> query = pm.newQuery(FindingAttribution.class, "vulnerability == :vulnerability && component == :component");
        return singleResult(query.execute(vulnerability, component));
    }

    /**
     * Deleted all FindingAttributions associated for the specified Component.
     * @param component the Component to delete FindingAttributions for
     */
    private void deleteFindingAttributions(Component component) {
        final Query<FindingAttribution> query = pm.newQuery(FindingAttribution.class, "component == :component");
        query.deletePersistentAll(component);
    }

    /**
     * Deletes a {@link Policy}, including all related {@link PolicyViolation}s and {@link PolicyCondition}s.
     * @param policy the {@link Policy} to delete
     */
    public void deletePolicy(final Policy policy) {
        for (final PolicyCondition condition : policy.getPolicyConditions()) {
            deletePolicyCondition(condition);
        }
        delete(policy);
    }

    /**
     * Deleted all PolicyViolation associated for the specified Component.
     * @param component the Component to delete PolicyViolation for
     */
    private void deletePolicyViolations(Component component) {
        final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class, "component == :component");
        query.deletePersistentAll(component);
    }

    /**
     * Deleted all PolicyViolation associated for the specified PolicyCondition.
     * @param policyCondition the PolicyCondition to delete PolicyViolation for
     */
    public void deletePolicyCondition(PolicyCondition policyCondition) {
        final List<PolicyViolation> violations = getAllPolicyViolations(policyCondition);
        for (PolicyViolation violation: violations) {
            deleteViolationAnalysisTrail(violation);
        }
        delete(violations);
        delete(policyCondition);
    }

    /**
     * Determines if a Component is affected by a specific Vulnerability by checking
     * {@link Vulnerability#getSource()} and {@link Vulnerability#getVulnId()}.
     * @param vulnerability The vulnerability to check if associated with component
     * @param component The component to check against
     * @return true if vulnerability is associated with the component, false if not
     */
    public boolean contains(Vulnerability vulnerability, Component component) {
        vulnerability = getObjectById(Vulnerability.class, vulnerability.getId());
        component = getObjectById(Component.class, component.getId());
        for (final Vulnerability vuln: component.getVulnerabilities()) {
            if (vuln.getSource() != null && vuln.getSource().equals(vulnerability.getSource())
                    && vuln.getVulnId() != null && vuln.getVulnId().equals(vulnerability.getVulnId())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Synchronize a Cpe, updating it if it needs updating, or creating it if it doesn't exist.
     * @param cpe the Cpe object to synchronize
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a synchronize Cpe object
     */
    public Cpe synchronizeCpe(Cpe cpe, boolean commitIndex) {
        Cpe result = getCpeBy23(cpe.getCpe23());
        if (result == null) {
            result = persist(cpe);
            Event.dispatch(new IndexEvent(IndexEvent.Action.CREATE, pm.detachCopy(result)));
            commitSearchIndex(commitIndex, Cpe.class);
        }
        return result;
    }

    /**
     * Returns a CPE by it's CPE v2.3 string.
     * @param cpe23 the CPE 2.3 string
     * @return a CPE object, or null if not found
     */
    public Cpe getCpeBy23(String cpe23) {
        final Query<Cpe> query = pm.newQuery(Cpe.class, "cpe23 == :cpe23");
        return singleResult(query.execute(cpe23));
    }

    /**
     * Returns a List of all CPE objects.
     * @return a List of all CPE objects
     */
    public PaginatedResult getCpes() {
        final Query<Cpe> query = pm.newQuery(Cpe.class);
        if (orderBy == null) {
            query.setOrdering("id asc");
        }
        if (filter != null) {
            query.setFilter("vendor.toLowerCase().matches(:filter) || product.toLowerCase().matches(:filter)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a List of all CPE objects that match the specified CPE (v2.2 or v2.3) uri.
     * @return a List of matching CPE objects
     */
    @SuppressWarnings("unchecked")
    public List<Cpe> getCpes(final String cpeString) {
        final Query<Cpe> query = pm.newQuery(Cpe.class, "cpe23 == :cpeString || cpe22 == :cpeString");
        return (List<Cpe>)query.execute(cpeString);
    }

    /**
     * Returns a List of all CPE objects that match the specified vendor/product/version.
     * @return a List of matching CPE objects
     */
    @SuppressWarnings("unchecked")
    public List<Cpe> getCpes(final String part, final String vendor, final String product, final String version) {
        final Query<Cpe> query = pm.newQuery(Cpe.class);
        query.setFilter("part == :part && vendor == :vendor && product == :product && version == :version");
        return (List<Cpe>)query.executeWithArray(part, vendor, product, version);
    }

    /**
     * Returns a VulnerableSoftware by it's CPE v2.3 string.
     * @param cpe23 the CPE 2.3 string
     * @return a VulnerableSoftware object, or null if not found
     */
    public VulnerableSoftware getVulnerableSoftwareByCpe23(String cpe23,
                                                           String versionEndExcluding, String versionEndIncluding,
                                                           String versionStartExcluding, String versionStartIncluding) {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class);
        query.setFilter("cpe23 == :cpe23 && versionEndExcluding == :versionEndExcluding && versionEndIncluding == :versionEndIncluding && versionStartExcluding == :versionStartExcluding && versionStartIncluding == :versionStartIncluding");
        return singleResult(query.executeWithArray(cpe23, versionEndExcluding, versionEndIncluding, versionStartExcluding, versionStartIncluding));
    }

    /**
     * Returns a List of all VulnerableSoftware objects.
     * @return a List of all VulnerableSoftware objects
     */
    public PaginatedResult getVulnerableSoftware() {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class);
        if (orderBy == null) {
            query.setOrdering("id asc");
        }
        if (filter != null) {
            query.setFilter("vendor.toLowerCase().matches(:filter) || product.toLowerCase().matches(:filter)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a List of all VulnerableSoftware objects that match the specified CPE (v2.2 or v2.3) uri.
     * @return a List of matching VulnerableSoftware objects
     */
    @SuppressWarnings("unchecked")
    public List<VulnerableSoftware> getAllVulnerableSoftwareByCpe(final String cpeString) {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class, "cpe23 == :cpeString || cpe22 == :cpeString");
        return (List<VulnerableSoftware>)query.execute(cpeString);
    }

    /**
     * Returns a List of all VulnerableSoftware objects that match the specified vendor/product/version.
     * @return a List of matching VulnerableSoftware objects
     */
    @SuppressWarnings("unchecked")
    public List<VulnerableSoftware> getAllVulnerableSoftware(final String part, final String vendor, final String product, final String version) {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class);
        query.setFilter("part == :part && vendor == :vendor && product == :product && version == :version");
        return (List<VulnerableSoftware>)query.executeWithArray(part, vendor, product, version);
    }

    /**
     * Returns a List of all VulnerableSoftware objects that match the specified vendor/product.
     * @return a List of matching VulnerableSoftware objects
     */
    @SuppressWarnings("unchecked")
    public List<VulnerableSoftware> getAllVulnerableSoftware(final String part, final String vendor, final String product) {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class);
        query.setFilter("part == :part && vendor == :vendor && product == :product");
        return (List<VulnerableSoftware>)query.executeWithArray(part, vendor, product);
    }

    /**
     * Checks if the specified CWE id exists or not. If not, creates
     * a new CWE with the specified ID and name. In both cases, the
     * CWE will be returned.
     * @param id the CWE ID
     * @param name the name of the CWE
     * @return a CWE object
     */
    public Cwe createCweIfNotExist(int id, String name) {
        Cwe cwe = getCweById(id);
        if (cwe != null) {
            return cwe;
        }
        cwe = new Cwe();
        cwe.setCweId(id);
        cwe.setName(name);
        return persist(cwe);
    }

    /**
     * Returns a CWE by it's CWE-ID.
     * @param cweId the CWE-ID
     * @return a CWE object, or null if not found
     */
    public Cwe getCweById(int cweId) {
        final Query<Cwe> query = pm.newQuery(Cwe.class, "cweId == :cweId");
        return singleResult(query.execute(cweId));
    }

    /**
     * Returns a complete list of all CWE's.
     * @return a List of CWEs
     */
    public PaginatedResult getCwes() {
        final Query<Cwe> query = pm.newQuery(Cwe.class);
        if (orderBy == null) {
            query.setOrdering("id asc");
        }
        if (filter != null) {
            query.setFilter("cweId == :cweId || name.toLowerCase().matches(:name)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filter, filterString);
        }
        return execute(query);
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
     * Returns a List of all Vulnerabilities.
     * @return a List of Vulnerability objects
     */
    public PaginatedResult getVulnerabilities() {
        PaginatedResult result;
        final Query<Vulnerability> query = pm.newQuery(Vulnerability.class);
        if (orderBy == null) {
            query.setOrdering("id asc");
        }
        if (filter != null) {
            query.setFilter("vulnId.toLowerCase().matches(:vulnId)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            result = execute(query, filterString);
        } else {
            result = execute(query);
        }
        for (Vulnerability vulnerability: result.getList(Vulnerability.class)) {
            vulnerability.setAffectedProjectCount(this.getProjects(vulnerability).size());
        }
        return result;
    }

    /**
     * Returns a List of Vulnerability for the specified Component and excludes suppressed vulnerabilities.
     * @param component the Component to retrieve vulnerabilities of
     * @return a List of Vulnerability objects
     */
    public PaginatedResult getVulnerabilities(Component component) {
        return getVulnerabilities(component, false);
    }

    /**
     * Returns a List of Vulnerability for the specified Component.
     * @param component the Component to retrieve vulnerabilities of
     * @return a List of Vulnerability objects
     */
    public PaginatedResult getVulnerabilities(Component component, boolean includeSuppressed) {
        PaginatedResult result;
        final String componentFilter = (includeSuppressed) ? "components.contains(:component)" : "components.contains(:component)" + generateExcludeSuppressed(component.getProject(), component);
        final Query<Vulnerability> query = pm.newQuery(Vulnerability.class);
        if (orderBy == null) {
            query.setOrdering("id asc");
        }
        if (filter != null) {
            query.setFilter(componentFilter + " && vulnId.toLowerCase().matches(:vulnId)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            result = execute(query, component, filterString);
        } else {
            query.setFilter(componentFilter);
            result = execute(query, component);
        }
        return result;
    }

    /**
     * Returns a List of Vulnerability for the specified Component and excludes suppressed vulnerabilities.
     * This method if designed NOT to provide paginated results.
     * @param component the Component to retrieve vulnerabilities of
     * @return a List of Vulnerability objects
     */
    public List<Vulnerability> getAllVulnerabilities(Component component) {
        return getAllVulnerabilities(component, false);
    }

    /**
     * Returns a List of Vulnerability for the specified Component.
     * This method if designed NOT to provide paginated results.
     * @param component the Component to retrieve vulnerabilities of
     * @return a List of Vulnerability objects
     */
    @SuppressWarnings("unchecked")
    private List<Vulnerability> getAllVulnerabilities(Component component, boolean includeSuppressed) {
        final String filter = (includeSuppressed) ? "components.contains(:component)" : "components.contains(:component)" + generateExcludeSuppressed(component.getProject(), component);
        final Query<Vulnerability> query = pm.newQuery(Vulnerability.class, filter);
        return (List<Vulnerability>)query.execute(component);
    }

    /**
     * Returns the number of Vulnerability objects for the specified Project.
     * @param project the Project to retrieve vulnerabilities of
     * @return the total number of vulnerabilities for the project
     */
    public long getVulnerabilityCount(Project project, boolean includeSuppressed) {
        long total = 0;
        long suppressed = 0;
        final List<Component> components = getAllComponents(project);
        for (final Component component: components) {
            total += getCount(pm.newQuery(Vulnerability.class, "components.contains(:component)"), component);
            if (! includeSuppressed) {
                suppressed += getSuppressedCount(component); // account for globally suppressed components
                suppressed += getSuppressedCount(project, component); // account for per-project/component
            }
        }
        return total - suppressed;
    }

    /**
     * Returns a List of Vulnerability for the specified Project.
     * This method is unique and used by third-party integrations
     * such as ThreadFix for the retrieval of vulnerabilities from
     * a specific project along with the affected component(s).
     * @param project the Project to retrieve vulnerabilities of
     * @return a List of Vulnerability objects
     */
    public List<Vulnerability> getVulnerabilities(Project project, boolean includeSuppressed) {
        final List<Vulnerability> vulnerabilities = new ArrayList<>();
        final List<Component> components = getAllComponents(project);
        for (final Component component: components) {
            final Collection<Vulnerability> componentVulns = pm.detachCopyAll(
                    getAllVulnerabilities(component, includeSuppressed)
            );
            for (final Vulnerability componentVuln: componentVulns) {
                componentVuln.setComponents(Collections.singletonList(pm.detachCopy(component)));
            }
            vulnerabilities.addAll(componentVulns);
        }
        return vulnerabilities;
    }

    /**
     * Returns the number of audited findings for the portfolio.
     * @return the total number of analysis decisions
     */
    public long getAuditedCount() {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "analysisState != null && analysisState != :notSet && analysisState != :inTriage");
        return getCount(query, AnalysisState.NOT_SET, AnalysisState.IN_TRIAGE);
    }

    /**
     * Returns the number of audited findings for the specified Project.
     * @param project the Project to retrieve audit counts for
     * @return the total number of analysis decisions for the project
     */
    public long getAuditedCount(Project project) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "project == :project && analysisState != null && analysisState != :notSet && analysisState != :inTriage");
        return getCount(query, project, AnalysisState.NOT_SET, AnalysisState.IN_TRIAGE);
    }

    /**
     * Returns the number of audited findings for the specified Component.
     * @param component the Component to retrieve audit counts for
     * @return the total number of analysis decisions for the component
     */
    public long getAuditedCount(Component component) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "project == null && component == :component && analysisState != null && analysisState != :notSet && analysisState != :inTriage");
        return getCount(query, component, AnalysisState.NOT_SET, AnalysisState.IN_TRIAGE);
    }

    /**
     * Returns the number of audited findings for the specified Project / Component.
     * @param project the Project to retrieve audit counts for
     * @param component the Component to retrieve audit counts for
     * @return the total number of analysis decisions for the project / component
     */
    public long getAuditedCount(Project project, Component component) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "project == :project && component == :component && analysisState != null && analysisState != :notSet && analysisState != :inTriage");
        return getCount(query, project, component, AnalysisState.NOT_SET, AnalysisState.IN_TRIAGE);
    }

    /**
     * Returns the number of suppressed vulnerabilities for the portfolio.
     * @return the total number of suppressed vulnerabilities
     */
    public long getSuppressedCount() {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "suppressed == true");
        return getCount(query);
    }

    /**
     * Returns the number of suppressed vulnerabilities for the specified Project
     * @param project the Project to retrieve suppressed vulnerabilities of
     * @return the total number of suppressed vulnerabilities for the project
     */
    public long getSuppressedCount(Project project) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "project == :project && suppressed == true");
        return getCount(query, project);
    }

    /**
     * Returns the number of suppressed vulnerabilities for the specified Component.
     * @param component the Component to retrieve suppressed vulnerabilities of
     * @return the total number of suppressed vulnerabilities for the component
     */
    public long getSuppressedCount(Component component) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "project == null && component == :component && suppressed == true");
        return getCount(query, component);
    }

    /**
     * Returns the number of suppressed vulnerabilities for the specified Project / Component.
     * @param project the Project to retrieve suppressed vulnerabilities of
     * @param component the Component to retrieve suppressed vulnerabilities of
     * @return the total number of suppressed vulnerabilities for the project / component
     */
    public long getSuppressedCount(Project project, Component component) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "project == :project && component == :component && suppressed == true");
        return getCount(query, project, component);
    }

    /**
     * Generates partial JDOQL statement excluding suppressed vulnerabilities for this project.
     * @param project the project to query on
     * @return a partial where clause
     */
    private String generateExcludeSuppressed(Project project) {
        return generateExcludeSuppressed(project, null);
    }

    /**
     * Generates partial JDOQL statement excluding suppressed vulnerabilities for this project/component
     * and for globally suppressed vulnerabilities against the specified component.
     * @param component the component to query on
     * @param project the project to query on
     * @return a partial where clause
     */
    @SuppressWarnings("unchecked")
    private String generateExcludeSuppressed(Project project, Component component) {
        // Retrieve a list of all suppressed vulnerabilities
        final Query<Analysis> analysisQuery = pm.newQuery(Analysis.class, "project == :project && component == :component && suppressed == true");
        final List<Analysis> analysisList = (List<Analysis>)analysisQuery.execute(project, component);
        // Construct exclude clause based on above results
        String excludeClause = analysisList.stream().map(analysis -> "id != " + analysis.getVulnerability().getId() + " && ").collect(Collectors.joining());
        if (StringUtils.trimToNull(excludeClause) != null) {
            excludeClause = " && (" + excludeClause.substring(0, excludeClause.lastIndexOf(" && ")) + ")";
        }
        return excludeClause;
    }

    /**
     * Returns a List of Projects affected by a specific vulnerability.
     * @param vulnerability the vulnerability to query on
     * @return a List of Projects
     */
    public List<Project> getProjects(Vulnerability vulnerability) {
        final List<Project> projects = new ArrayList<>();
        for (final Component component: vulnerability.getComponents()) {
            boolean affected = true;
            final Analysis projectAnalysis = getAnalysis(component, vulnerability);
            if (projectAnalysis != null && projectAnalysis.isSuppressed()) {
                affected = false;
            }
            if (affected) {
                projects.add(component.getProject());
            }
        }
        // Force removal of duplicates by taking the List and populating a Set and back again.
        final Set<Project> set = new LinkedHashSet<>(projects);
        projects.clear();
        projects.addAll(set);
        return projects;
    }

    /**
     * Returns a List Analysis for the specified Project.
     * @param project the Project
     * @return a List of Analysis objects, or null if not found
     */
    @SuppressWarnings("unchecked")
    private List<Analysis> getAnalyses(Project project) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "project == :project");
        return (List<Analysis>) query.execute(project);
    }

    /**
     * Returns a Analysis for the specified Project, Component, and Vulnerability.
     * @param component the Component
     * @param vulnerability the Vulnerability
     * @return a Analysis object, or null if not found
     */
    public Analysis getAnalysis(Component component, Vulnerability vulnerability) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "component == :component && vulnerability == :vulnerability");
        return singleResult(query.execute(component, vulnerability));
    }

    /**
     * Documents a new analysis. Creates a new Analysis object if one doesn't already exists and appends
     * the specified comment along with a timestamp in the AnalysisComment trail.
     * @param component the Component
     * @param vulnerability the Vulnerability
     * @return an Analysis object
     */
    public Analysis makeAnalysis(Component component, Vulnerability vulnerability,
                                 AnalysisState analysisState, Boolean isSuppressed) {
        if (analysisState == null) {
            analysisState = AnalysisState.NOT_SET;
        }
        Analysis analysis = getAnalysis(component, vulnerability);
        if (analysis == null) {
            analysis = new Analysis();
            analysis.setComponent(component);
            analysis.setVulnerability(vulnerability);
        }
        if (isSuppressed != null) {
            analysis.setSuppressed(isSuppressed);
        }
        analysis.setAnalysisState(analysisState);
        analysis = persist(analysis);
        return getAnalysis(analysis.getComponent(), analysis.getVulnerability());
    }

    /**
     * Adds a new analysis comment to the specified analysis.
     * @param analysis the analysis object to add a comment to
     * @param comment the comment to make
     * @param commenter the name of the principal who wrote the comment
     * @return a new AnalysisComment object
     */
    public AnalysisComment makeAnalysisComment(Analysis analysis, String comment, String commenter) {
        if (analysis == null || comment == null) {
            return null;
        }
        final AnalysisComment analysisComment = new AnalysisComment();
        analysisComment.setAnalysis(analysis);
        analysisComment.setTimestamp(new Date());
        analysisComment.setComment(comment);
        analysisComment.setCommenter(commenter);
        return persist(analysisComment);
    }

    /**
     * Deleted all analysis and comments associated for the specified Component.
     * @param component the Component to delete analysis for
     */
    private void deleteAnalysisTrail(Component component) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "component == :component");
        query.deletePersistentAll(component);
    }

    /**
     * Deleted all analysis and comments associated for the specified Project.
     * @param project the Project to delete analysis for
     */
    private void deleteAnalysisTrail(Project project) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "project == :project");
        query.deletePersistentAll(project);
    }

    /**
     * Returns a List of Finding objects for the specified project.
     * @param project the project to retrieve findings for
     * @return a List of Finding objects
     */
    @SuppressWarnings("unchecked")
    public List<Finding> getFindings(Project project) {
        return getFindings(project, false);
    }

    /**
     * Returns a List of Finding objects for the specified project.
     * @param project the project to retrieve findings for
     * @param includeSuppressed determines if suppressed vulnerabilities should be included or not
     * @return a List of Finding objects
     */
    @SuppressWarnings("unchecked")
    public List<Finding> getFindings(Project project, boolean includeSuppressed) {
        final Query<Object[]> query = pm.newQuery(JDOQuery.SQL_QUERY_LANGUAGE, Finding.QUERY);
        query.setParameters(project.getId());
        final List<Object[]> list = query.executeList();
        final List<Finding> findings = new ArrayList<>();
        for (final Object[] o: list) {
            final Finding finding = new Finding(project.getUuid(), o);
            final Component component = getObjectByUuid(Component.class, (String)finding.getComponent().get("uuid"));
            final Vulnerability vulnerability = getObjectByUuid(Vulnerability.class, (String)finding.getVulnerability().get("uuid"));
            final Analysis analysis = getAnalysis(component, vulnerability);
            if (includeSuppressed || analysis == null || !analysis.isSuppressed()) { // do not add globally suppressed findings
                // These are CLOB fields. Handle these here so that database-specific deserialization doesn't need to be performed (in Finding)
                finding.getVulnerability().put("description", vulnerability.getDescription());
                finding.getVulnerability().put("recommendation", vulnerability.getRecommendation());
                findings.add(finding);
            }
        }
        return findings;
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
    private void deleteMetrics(Project project) {
        final Query<ProjectMetrics> query = pm.newQuery(ProjectMetrics.class, "project == :project");
        query.deletePersistentAll(project);

        final Query<DependencyMetrics> query2 = pm.newQuery(DependencyMetrics.class, "project == :project");
        query2.deletePersistentAll(project);
    }

    /**
     * Deleted all metrics associated for the specified Component.
     * @param component the Component to delete metrics for
     */
    private void deleteMetrics(Component component) {
        final Query<DependencyMetrics> query = pm.newQuery(DependencyMetrics.class, "component == :component");
        query.deletePersistentAll(component);
    }

    /**
     * Returns a list of all repositories.
     * @return a List of Repositories
     */
    public PaginatedResult getRepositories() {
        final Query<Repository> query = pm.newQuery(Repository.class);
        if (orderBy == null) {
            query.setOrdering("type asc, identifier asc");
        }
        if (filter != null) {
            query.setFilter("identifier.toLowerCase().matches(:identifier)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a list of all repositories
     * This method if designed NOT to provide paginated results.
     * @return a List of Repositories
     */
    public List<Repository> getAllRepositories() {
        final Query<Repository> query = pm.newQuery(Repository.class);
        query.setOrdering("type asc, identifier asc");
        return query.executeResultList(Repository.class);
    }

    /**
     * Returns a list of repositories by it's type.
     * @param type the type of repository (required)
     * @return a List of Repository objects
     */
    public PaginatedResult getRepositories(RepositoryType type) {
        final Query<Repository> query = pm.newQuery(Repository.class, "type == :type");
        if (orderBy == null) {
            query.setOrdering("identifier asc");
        }
        return execute(query, type);
    }

    /**
     * Returns a list of repositories by it's type in the order in which the repository should be used in resolution.
     * This method if designed NOT to provide paginated results.
     * @param type the type of repository (required)
     * @return a List of Repository objects
     */
    @SuppressWarnings("unchecked")
    public List<Repository> getAllRepositoriesOrdered(RepositoryType type) {
        final Query<Repository> query = pm.newQuery(Repository.class, "type == :type");
        query.setOrdering("resolutionOrder asc");
        return (List<Repository>)query.execute(type);
    }

    /**
     * Determines if the repository exists in the database.
     * @param type the type of repository (required)
     * @param identifier the repository identifier
     * @return true if object exists, false if not
     */
    public boolean repositoryExist(RepositoryType type, String identifier) {
        final Query<Repository> query = pm.newQuery(Repository.class, "type == :type && identifier == :identifier");
        return singleResult(query.execute(type, identifier)) != null;
    }

    /**
     * Creates a new Repository.
     * @param type the type of repository
     * @param identifier a unique (to the type) identifier for the repo
     * @param url the URL to the repository
     * @param enabled if the repo is enabled or not
     * @return the created Repository
     */
    public Repository createRepository(RepositoryType type, String identifier, String url, boolean enabled, boolean internal) {
        if (repositoryExist(type, identifier)) {
            return null;
        }
        int order = 0;
        final List<Repository> existingRepos = getAllRepositoriesOrdered(type);
        if (existingRepos != null) {
            for (final Repository existing : existingRepos) {
                if (existing.getResolutionOrder() > order) {
                    order = existing.getResolutionOrder();
                }
            }
        }
        final Repository repo = new Repository();
        repo.setType(type);
        repo.setIdentifier(identifier);
        repo.setUrl(url);
        repo.setResolutionOrder(order + 1);
        repo.setEnabled(enabled);
        repo.setInternal(internal);
        return persist(repo);
    }

    /**
     * Updates an existing Repository.
     * @param uuid the uuid of the repository to update
     * @param identifier the identifier of the repository
     * @param url a url of the repository
     * @param internal specifies if the repository is internal
     * @param enabled specifies if the repository is enabled
     * @return the updated Repository
     */
    public Repository updateRepository(UUID uuid, String identifier, String url, boolean internal, boolean enabled) {
        final Repository repository = getObjectByUuid(Repository.class, uuid);
        repository.setIdentifier(identifier);
        repository.setUrl(url);
        repository.setInternal(internal);
        repository.setEnabled(enabled);
        return persist(repository);
    }

    /**
     * Returns a RepositoryMetaComponent object from the specified type, group, and name.
     * @param repositoryType the type of repository
     * @param namespace the Package URL namespace of the meta component
     * @param name the Package URL name of the meta component
     * @return a RepositoryMetaComponent object, or null if not found
     */
    public RepositoryMetaComponent getRepositoryMetaComponent(RepositoryType repositoryType, String namespace, String name) {
        final Query<RepositoryMetaComponent> query = pm.newQuery(RepositoryMetaComponent.class);
        query.setFilter("repositoryType == :repositoryType && namespace == :namespace && name == :name");
        return singleResult(query.execute(repositoryType, namespace, name));
    }

    /**
     * Synchronizes a RepositoryMetaComponent, updating it if it needs updating, or creating it if it doesn't exist.
     * @param repositoryMetaComponent the RepositoryMetaComponent object to synchronize
     * @return a synchronized RepositoryMetaComponent object
     */
    public RepositoryMetaComponent synchronizeRepositoryMetaComponent(RepositoryMetaComponent repositoryMetaComponent) {
        RepositoryMetaComponent result = updateRepositoryMetaComponent(repositoryMetaComponent);
        if (result == null) {
            result = persist(repositoryMetaComponent);
        }
        return result;
    }

    /**
     * Updates a RepositoryMetaComponent.
     * @param transientRepositoryMetaComponent the RepositoryMetaComponent to update
     * @return a RepositoryMetaComponent object
     */
    private RepositoryMetaComponent updateRepositoryMetaComponent(RepositoryMetaComponent transientRepositoryMetaComponent) {
        final RepositoryMetaComponent metaComponent;
        if (transientRepositoryMetaComponent.getId() > 0) {
            metaComponent = getObjectById(RepositoryMetaComponent.class, transientRepositoryMetaComponent.getId());
        } else {
            metaComponent = getRepositoryMetaComponent(transientRepositoryMetaComponent.getRepositoryType(),
                    transientRepositoryMetaComponent.getNamespace(), transientRepositoryMetaComponent.getName());
        }

        if (metaComponent != null) {
            metaComponent.setRepositoryType(transientRepositoryMetaComponent.getRepositoryType());
            metaComponent.setNamespace(transientRepositoryMetaComponent.getNamespace());
            metaComponent.setLastCheck(transientRepositoryMetaComponent.getLastCheck());
            metaComponent.setLatestVersion(transientRepositoryMetaComponent.getLatestVersion());
            metaComponent.setName(transientRepositoryMetaComponent.getName());
            metaComponent.setPublished(transientRepositoryMetaComponent.getPublished());
            return persist(metaComponent);
        }
        return null;
    }

    /**
     * Creates a new NotificationRule.
     * @param name the name of the rule
     * @param scope the scope
     * @param level the level
     * @param publisher the publisher
     * @return a new NotificationRule
     */
    public NotificationRule createNotificationRule(String name, NotificationScope scope, NotificationLevel level, NotificationPublisher publisher) {
        final NotificationRule rule = new NotificationRule();
        rule.setName(name);
        rule.setScope(scope);
        rule.setNotificationLevel(level);
        rule.setPublisher(publisher);
        rule.setEnabled(true);
        return persist(rule);
    }

    /**
     * Updated an existing NotificationRule.
     * @param transientRule the rule to update
     * @return a NotificationRule
     */
    public NotificationRule updateNotificationRule(NotificationRule transientRule) {
        final NotificationRule rule = getObjectByUuid(NotificationRule.class, transientRule.getUuid());
        rule.setName(transientRule.getName());
        rule.setNotificationLevel(transientRule.getNotificationLevel());
        rule.setPublisherConfig(transientRule.getPublisherConfig());
        rule.setNotifyOn(transientRule.getNotifyOn());
        return persist(rule);
    }

    /**
     * Returns a paginated list of all notification rules.
     * @return a paginated list of NotificationRules
     */
    public PaginatedResult getNotificationRules() {
        final Query<NotificationRule> query = pm.newQuery(NotificationRule.class);
        if (orderBy == null) {
            query.setOrdering("name asc");
        }
        if (filter != null) {
            query.setFilter("name.toLowerCase().matches(:name) || publisher.name.toLowerCase().matches(:name)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Retrieves all NotificationPublishers.
     * This method if designed NOT to provide paginated results.
     * @return list of all NotificationPublisher objects
     */
    @SuppressWarnings("unchecked")
    public List<NotificationPublisher> getAllNotificationPublishers() {
        final Query<NotificationPublisher> query = pm.newQuery(NotificationPublisher.class);
        query.getFetchPlan().addGroup(NotificationPublisher.FetchGroup.ALL.name());
        query.setOrdering("name asc");
        return (List<NotificationPublisher>)query.execute();
    }

    /**
     * Retrieves a NotificationPublisher by its name.
     * @param name The name of the NotificationPublisher
     * @return a NotificationPublisher
     */
    public NotificationPublisher getNotificationPublisher(final String name) {
        final Query<NotificationPublisher> query = pm.newQuery(NotificationPublisher.class, "name == :name");
        return singleResult(query.execute(name));
    }

    /**
     * Retrieves a NotificationPublisher by its class.
     * @param clazz The Class of the NotificationPublisher
     * @return a NotificationPublisher
     */
    NotificationPublisher getDefaultNotificationPublisher(final Class<Publisher> clazz) {
        return getDefaultNotificationPublisher(clazz.getCanonicalName());
    }

    /**
     * Retrieves a NotificationPublisher by its class.
     * @param clazz The Class of the NotificationPublisher
     * @return a NotificationPublisher
     */
    private NotificationPublisher getDefaultNotificationPublisher(final String clazz) {
        final Query<NotificationPublisher> query = pm.newQuery(NotificationPublisher.class, "publisherClass == :publisherClass && defaultPublisher == true");
        return singleResult(query.execute(clazz));
    }

    /**
     * Creates a NotificationPublisher object.
     * @param name The name of the NotificationPublisher
     * @return a NotificationPublisher
     */
    public NotificationPublisher createNotificationPublisher(final String name, final String description,
                                                             final Class<Publisher> publisherClass, final String templateContent,
                                                             final String templateMimeType, final boolean defaultPublisher) {
        pm.currentTransaction().begin();
        final NotificationPublisher publisher = new NotificationPublisher();
        publisher.setName(name);
        publisher.setDescription(description);
        publisher.setPublisherClass(publisherClass.getCanonicalName());
        publisher.setTemplate(templateContent);
        publisher.setTemplateMimeType(templateMimeType);
        publisher.setDefaultPublisher(defaultPublisher);
        pm.makePersistent(publisher);
        pm.currentTransaction().commit();
        return getObjectById(NotificationPublisher.class, publisher.getId());
    }

    /**
     * Updates a NotificationPublisher.
     * @return a NotificationPublisher object
     */
    NotificationPublisher updateNotificationPublisher(NotificationPublisher transientPublisher) {
        NotificationPublisher publisher = null;
        if (transientPublisher.getId() > 0) {
            publisher = getObjectById(NotificationPublisher.class, transientPublisher.getId());
        } else if (transientPublisher.isDefaultPublisher()) {
            publisher = getDefaultNotificationPublisher(transientPublisher.getPublisherClass());
        }
        if (publisher != null) {
            publisher.setName(transientPublisher.getName());
            publisher.setDescription(transientPublisher.getDescription());
            publisher.setPublisherClass(transientPublisher.getPublisherClass());
            publisher.setTemplate(transientPublisher.getTemplate());
            publisher.setTemplateMimeType(transientPublisher.getTemplateMimeType());
            publisher.setDefaultPublisher(transientPublisher.isDefaultPublisher());
            return persist(publisher);
        }
        return null;
    }

    /**
     * Removes projects from NotificationRules
     */
    @SuppressWarnings("unchecked")
    public void removeProjectFromNotificationRules(final Project project) {
        final Query<NotificationRule> query = pm.newQuery(NotificationRule.class, "projects.contains(:project)");
        for (final NotificationRule rule: (List<NotificationRule>) query.execute(project)) {
            rule.getProjects().remove(project);
            persist(rule);
        }
    }

    /**
     * Determines if a config property is enabled or not.
     * @param configPropertyConstants the property to query
     * @return true if enabled, false if not
     */
    public boolean isEnabled(final ConfigPropertyConstants configPropertyConstants) {
        final ConfigProperty property = getConfigProperty(
                configPropertyConstants.getGroupName(), configPropertyConstants.getPropertyName()
        );
        if (property != null && ConfigProperty.PropertyType.BOOLEAN == property.getPropertyType()) {
            return BooleanUtil.valueOf(property.getPropertyValue());
        }
        return false;
    }

    public ComponentAnalysisCache getComponentAnalysisCache(ComponentAnalysisCache.CacheType cacheType, String targetHost, String targetType, String target) {
        final Query<ComponentAnalysisCache> query = pm.newQuery(ComponentAnalysisCache.class,
                "cacheType == :cacheType && targetHost == :targetHost && targetType == :targetType && target == :target");
        query.setOrdering("lastOccurrence desc");
        return singleResult(query.executeWithArray(cacheType, targetHost, targetType, target));
    }

    public void updateComponentAnalysisCache(ComponentAnalysisCache.CacheType cacheType, String targetHost, String targetType, String target, Date lastOccurrence, JsonObject result) {
        ComponentAnalysisCache cac = getComponentAnalysisCache(cacheType, targetHost, targetType, target);
        if (cac == null) {
            cac = new ComponentAnalysisCache();
            cac.setCacheType(cacheType);
            cac.setTargetHost(targetHost);
            cac.setTargetType(targetType);
            cac.setTarget(target);
        }
        cac.setLastOccurrence(lastOccurrence);
        if (result != null) {
            cac.setResult(result);
        }
        persist(cac);
    }

    public void clearComponentAnalysisCache() {
        final Query<ComponentAnalysisCache> query = pm.newQuery(ComponentAnalysisCache.class);
        query.deletePersistentAll();
    }

    /**
     * Binds the two objects together in a corresponding join table.
     * @param project a Project object
     * @param tags a List of Tag objects
     */
    @SuppressWarnings("unchecked")
    public void bind(Project project, List<Tag> tags) {
        final Query<Tag> query = pm.newQuery(Tag.class, "projects.contains(:project)");
        final List<Tag> currentProjectTags = (List<Tag>)query.execute(project);
        pm.currentTransaction().begin();
        for (final Tag tag: currentProjectTags) {
            if (!tags.contains(tag)) {
                tag.getProjects().remove(project);
            }
        }
        project.setTags(tags);
        for (final Tag tag: tags) {
            tag.getProjects().add(project);
        }
        pm.currentTransaction().commit();
    }

    /**
     * Commits the Lucene index.
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @param clazz the indexable class to commit the index of
     */
    public void commitSearchIndex(boolean commitIndex, Class clazz) {
        if (commitIndex) {
            Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, clazz));
        }
    }

    /**
     * Commits the Lucene index.
     * @param clazz the indexable class to commit the index of
     */
    public void commitSearchIndex(Class clazz) {
        commitSearchIndex(true, clazz);
    }
}
