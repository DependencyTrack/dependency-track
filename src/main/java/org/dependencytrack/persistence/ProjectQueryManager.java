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

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.model.ApiKey;
import alpine.model.Permission;
import alpine.model.Team;
import alpine.model.UserPrincipal;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import com.github.packageurl.PackageURL;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.FindingAttribution;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vulnerability;

import javax.jdo.FetchPlan;
import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

final class ProjectQueryManager extends QueryManager implements IQueryManager {

    private static final Logger LOGGER = Logger.getLogger(ProjectQueryManager.class);

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    ProjectQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    ProjectQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
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

        var filterBuilder = new ProjectQueryFilterBuilder()
                .excludeInactive(excludeInactive);

        if (filter != null) {
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            final Tag tag = getTagByName(filter.trim());

            if (tag != null) {
                filterBuilder = filterBuilder.withFuzzyNameOrExactTag(filterString, tag);

            } else {
                filterBuilder = filterBuilder.withFuzzyName(filterString);
            }
        }

        final String queryFilter = filterBuilder.buildFilter();
        final Map<String, Object> params = filterBuilder.getParams();

        preprocessACLs(query, queryFilter, params, false);
        result = execute(query, params);
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
        return getAllProjects(false);
    }

    /**
     * Returns a list of all projects.
     * This method if designed NOT to provide paginated results.
     * @return a List of Projects
     */
    public List<Project> getAllProjects(boolean excludeInactive) {
        final Query<Project> query = pm.newQuery(Project.class);
        if (excludeInactive) {
            query.setFilter("active == true || active == null");
        }
        query.setOrdering("id asc");
        return query.executeList();
    }

    /**
     * Returns a list of projects by their name.
     * @param name the name of the Projects (required)
     * @return a List of Project objects
     */
    public PaginatedResult getProjects(final String name, final boolean excludeInactive) {
        final Query<Project> query = pm.newQuery(Project.class);
        if (orderBy == null) {
            query.setOrdering("version desc");
        }

        final var filterBuilder = new ProjectQueryFilterBuilder()
                .excludeInactive(excludeInactive)
                .withName(name);

        final String queryFilter = filterBuilder.buildFilter();
        final Map<String, Object> params = filterBuilder.getParams();

        preprocessACLs(query, queryFilter, params, false);
        return execute(query, params);
    }

    /**
     * Returns a project by its name and version.
     * @param name the name of the Project (required)
     * @param version the version of the Project (or null)
     * @return a Project object, or null if not found
     */
    public Project getProject(final String name, final String version) {
        final Query<Project> query = pm.newQuery(Project.class);

        final var filterBuilder = new ProjectQueryFilterBuilder()
                .withName(name)
                .withVersion(version);

        final String queryFilter = filterBuilder.buildFilter();
        final Map<String, Object> params = filterBuilder.getParams();

        preprocessACLs(query, queryFilter, params, false);
        query.setFilter(queryFilter);
        query.setRange(0, 1);
        return singleResult(query.executeWithMap(params));
    }

    /**
     * Returns a list of projects that are accessible by the specified team.
     * @param team the team the has access to Projects
     * @return a List of Project objects
     */
    public PaginatedResult getProjects(final Team team, final boolean excludeInactive, final boolean bypass) {
        final Query<Project> query = pm.newQuery(Project.class);
        if (orderBy == null) {
            query.setOrdering("name asc, version desc, id asc");
        }

        final var filterBuilder = new ProjectQueryFilterBuilder()
                .excludeInactive(excludeInactive)
                .withTeam(team);

        final String queryFilter = filterBuilder.buildFilter();
        final Map<String, Object> params = filterBuilder.getParams();

        preprocessACLs(query, queryFilter, params, bypass);
        return execute(query, params);
    }

    /**
     * Returns a paginated result of projects by tag.
     * @param tag the tag associated with the Project
     * @return a List of Projects that contain the tag
     */
    public PaginatedResult getProjects(final Tag tag, final boolean includeMetrics, final boolean excludeInactive) {
        final PaginatedResult result;
        final Query<Project> query = pm.newQuery(Project.class);
        if (orderBy == null) {
            query.setOrdering("name asc");
        }

        var filterBuilder = new ProjectQueryFilterBuilder()
                .excludeInactive(excludeInactive)
                .withTag(tag);

        if (filter != null) {
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            filterBuilder = filterBuilder.withFuzzyName(filterString);
        }

        final String queryFilter = filterBuilder.buildFilter();
        final Map<String, Object> params = filterBuilder.getParams();

        preprocessACLs(query, queryFilter, params, false);
        result = execute(query, params);
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
     * Returns a paginated result of projects by classifier.
     * @param classifier the classifier of the Project
     * @return a List of Projects of the specified classifier
     */
    public PaginatedResult getProjects(final Classifier classifier, final boolean includeMetrics, final boolean excludeInactive) {
        final PaginatedResult result;
        final Query<Project> query = pm.newQuery(Project.class);
        if (orderBy == null) {
            query.setOrdering("name asc");
        }

        final var filterBuilder = new ProjectQueryFilterBuilder()
                .excludeInactive(excludeInactive)
                .withClassifier(classifier);

        final String queryFilter = filterBuilder.buildFilter();
        final Map<String, Object> params = filterBuilder.getParams();

        preprocessACLs(query, queryFilter, params, false);
        result = execute(query, params);
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
        return getProjects(tag, false, false);
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
        query.setRange(0, 1);
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
    public Project createProject(String name, String description, String version, List<Tag> tags, Project parent, PackageURL purl, boolean active, boolean commitIndex) {
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
     * Creates a new Project.
     * @param project the project to create
     * @param tags a List of Tags - these will be resolved if necessary
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return the created Project
     */
    public Project createProject(final Project project, List<Tag> tags, boolean commitIndex) {
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
    public Project updateProject(UUID uuid, String name, String description, String version, List<Tag> tags, PackageURL purl, boolean active, boolean commitIndex) {
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

    /**
     * Updates an existing Project.
     * @param transientProject the project to update
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return the updated Project
     */
    public Project updateProject(Project transientProject, boolean commitIndex) {
        final Project project = getObjectByUuid(Project.class, transientProject.getUuid());
        project.setAuthor(transientProject.getAuthor());
        project.setPublisher(transientProject.getPublisher());
        project.setGroup(transientProject.getGroup());
        project.setName(transientProject.getName());
        project.setDescription(transientProject.getDescription());
        project.setVersion(transientProject.getVersion());
        project.setClassifier(transientProject.getClassifier());
        project.setCpe(transientProject.getCpe());
        project.setPurl(transientProject.getPurl());
        project.setSwidTagId(transientProject.getSwidTagId());
        project.setActive(transientProject.isActive());

        final List<Tag> resolvedTags = resolveTags(transientProject.getTags());
        bind(project, resolvedTags);

        final Project result = persist(project);
        Event.dispatch(new IndexEvent(IndexEvent.Action.UPDATE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, Project.class);
        return result;
    }

    public Project clone(UUID from, String newVersion, boolean includeTags, boolean includeProperties,
                         boolean includeComponents, boolean includeServices, boolean includeAuditHistory) {
        final Project source = getObjectByUuid(Project.class, from, Project.FetchGroup.ALL.name());
        if (source == null) {
            return null;
        }
        Project project = new Project();
        project.setAuthor(source.getAuthor());
        project.setPublisher(source.getPublisher());
        project.setGroup(source.getGroup());
        project.setName(source.getName());
        project.setDescription(source.getDescription());
        project.setVersion(newVersion);
        project.setClassifier(source.getClassifier());
        project.setActive(source.isActive());
        project.setCpe(source.getCpe());
        project.setPurl(source.getPurl());
        project.setSwidTagId(source.getSwidTagId());
        if (includeComponents && includeServices) {
            project.setDirectDependencies(source.getDirectDependencies());
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

        final Map<Long, Component> clonedComponents = new HashMap<>();
        if (includeComponents) {
            final List<Component> sourceComponents = getAllComponents(source);
            if (sourceComponents != null) {
                for (final Component sourceComponent: sourceComponents) {
                    final Component clonedComponent = cloneComponent(sourceComponent, project, false);
                    // Add vulnerabilties and finding attribution from the source component to the cloned component
                    for (Vulnerability vuln: sourceComponent.getVulnerabilities()) {
                        final FindingAttribution sourceAttribution = this.getFindingAttribution(vuln, sourceComponent);
                        this.addVulnerability(vuln, clonedComponent, sourceAttribution.getAnalyzerIdentity(), sourceAttribution.getAlternateIdentifier(), sourceAttribution.getReferenceUrl());
                    }
                    clonedComponents.put(sourceComponent.getId(), clonedComponent);
                }
            }
        }

        if (includeAuditHistory && includeComponents) {
            final List<Analysis> analyses = super.getAnalyses(source);
            if (analyses != null) {
                for (final Analysis sourceAnalysis: analyses) {
                    Analysis analysis = new Analysis();
                    analysis.setAnalysisState(sourceAnalysis.getAnalysisState());
                    final Component clonedComponent = clonedComponents.get(sourceAnalysis.getComponent().getId());
                    if (clonedComponent == null) {
                        break;
                    }
                    analysis.setComponent(clonedComponent);
                    analysis.setVulnerability(sourceAnalysis.getVulnerability());
                    analysis.setSuppressed(sourceAnalysis.isSuppressed());
                    analysis.setAnalysisResponse(sourceAnalysis.getAnalysisResponse());
                    analysis.setAnalysisJustification(sourceAnalysis.getAnalysisJustification());
                    analysis.setAnalysisState(sourceAnalysis.getAnalysisState());
                    analysis.setAnalysisDetails(sourceAnalysis.getAnalysisDetails());
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
     * Deletes a Project and all objects dependant on the project.
     * @param project the Project to delete
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     */
    public void recursivelyDelete(final Project project, final boolean commitIndex) {
        if (project.getChildren() != null) {
            for (final Project child: project.getChildren()) {
                recursivelyDelete(child, false);
            }
        }
        pm.getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
        final Project result = pm.getObjectById(Project.class, project.getId());
        Event.dispatch(new IndexEvent(IndexEvent.Action.DELETE, pm.detachCopy(result)));
        commitSearchIndex(commitIndex, Project.class);

        deleteAnalysisTrail(project);
        deleteViolationAnalysisTrail(project);
        deleteMetrics(project);
        deleteFindingAttributions(project);
        deletePolicyViolations(project);
        deleteComponents(project);

        for (final ServiceComponent s: getAllServiceComponents(project)) {
            recursivelyDelete(s, false);
        }
        deleteBoms(project);
        deleteVexs(project);
        removeProjectFromNotificationRules(project);
        removeProjectFromPolicies(project);
        delete(project.getProperties());
        delete(getAllBoms(project));
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
        query.setRange(0, 1);
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
     * Binds the two objects together in a corresponding join table.
     * @param project a Project object
     * @param tags a List of Tag objects
     */
    @SuppressWarnings("unchecked")
    @Override
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
            final List<Project> projects = tag.getProjects();
            if (!projects.contains(project)) {
                projects.add(project);
            }
        }
        pm.currentTransaction().commit();
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

    public boolean hasAccess(final Principal principal, final Project project) {
        if (isEnabled(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED)) {
            if (principal instanceof UserPrincipal) {
                final UserPrincipal userPrincipal = (UserPrincipal) principal;
                if (super.hasAccessManagementPermission(userPrincipal)) {
                    return true;
                }
                if (userPrincipal.getTeams() != null) {
                    for (final Team userInTeam : userPrincipal.getTeams()) {
                        for (final Team accessTeam : project.getAccessTeams()) {
                            if (userInTeam.getId() == accessTeam.getId()) {
                                return true;
                            }
                        }
                    }
                }
            } else if (principal instanceof ApiKey ){
                final ApiKey apiKey = (ApiKey) principal;
                if (super.hasAccessManagementPermission(apiKey)) {
                    return true;
                }
                if (apiKey.getTeams() != null) {
                    for (final Team userInTeam : apiKey.getTeams()) {
                        for (final Team accessTeam : project.getAccessTeams()) {
                            if (userInTeam.getId() == accessTeam.getId()) {
                                return true;
                            }
                        }
                    }
                }
            } else if (principal == null) {
                // This is a system request being made (e.g. MetricsUpdateTask, etc) where there isn't a principal
                return true;
            }
            return false;
        } else {
            return true;
        }
    }

    /**
     * A similar method exists in ComponentQueryManager
     */
    private void preprocessACLs(final Query<Project> query, final String inputFilter, final Map<String, Object> params, final boolean bypass) {
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
                    sb.append(" accessTeams.contains(:team").append(i).append(") ");
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
        } else if (StringUtils.trimToNull(inputFilter) != null) {
            query.setFilter(inputFilter);
        }
    }

    /**
     * Updates a Project ACL to add the principals Team to the AccessTeams
     * This only happens if Portfolio Access Control is enabled and the @param principal is an ApyKey
     * For a UserPrincipal we don't know which Team(s) to add to the ACL,
     * See https://github.com/DependencyTrack/dependency-track/issues/1435
     * @param project
     * @param principal
     * @return True if ACL was updated
     */
    public boolean updateNewProjectACL(Project project, Principal principal) {
        if (isEnabled(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED) && principal instanceof ApiKey) {
            ApiKey apiKey = (ApiKey) principal;
            final var apiTeam = apiKey.getTeams().stream().findFirst();
            if (apiTeam.isPresent()) {
                LOGGER.debug("adding Team to ACL of newly created project");
                final Team team = getObjectByUuid(Team.class, apiTeam.get().getUuid());
                project.addAccessTeam(team);
                persist(project);
                return true;
            } else {
                LOGGER.warn("API Key without a Team, unable to assign team ACL to project.");
            }
        }
        return false;
    }

    public boolean hasAccessManagementPermission(final UserPrincipal userPrincipal) {
        for (Permission permission: getEffectivePermissions(userPrincipal)) {
            if (Permissions.ACCESS_MANAGEMENT.name().equals(permission.getName())) {
                return true;
            }
        }
        return false;
    }

    public boolean hasAccessManagementPermission(final ApiKey apiKey) {
        return hasPermission(apiKey, Permissions.ACCESS_MANAGEMENT.name());
    }

}
