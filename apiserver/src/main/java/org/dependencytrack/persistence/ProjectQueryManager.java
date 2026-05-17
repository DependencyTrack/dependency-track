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

import alpine.model.ApiKey;
import alpine.model.Team;
import alpine.model.User;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import com.github.packageurl.PackageURL;
import org.datanucleus.api.jdo.JDOQuery;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectCollectionLogic;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.model.ProjectVersion;
import org.dependencytrack.model.Tag;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.metadata.MemberMetadata;
import javax.jdo.metadata.TypeMetadata;
import java.security.Principal;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNullElse;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.util.PersistenceUtil.assertPersistent;
import static org.dependencytrack.util.PersistenceUtil.assertPersistentAll;

final class ProjectQueryManager extends QueryManager implements IQueryManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProjectQueryManager.class);

    /**
     * Constructs a new QueryManager.
     *
     * @param pm a PersistenceManager object
     */
    ProjectQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     *
     * @param pm      a PersistenceManager object
     * @param request an AlpineRequest object
     */
    ProjectQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns a project by its uuid.
     * @param uuid the uuid of the Project (required)
     * @return a Project object, or null if not found
     */
    @Override
    public Project getProject(final String uuid) {
        final Project project = getObjectByUuid(Project.class, uuid, Project.FetchGroup.ALL.name());
        if (project != null) {
            // set Metrics to minimize the number of round trips a client needs to make
            project.setMetrics(withJdbiHandle(handle ->
                    handle.attach(MetricsDao.class).getMostRecentProjectMetrics(project.getId())));
            // set ProjectVersions to minimize the number of round trips a client needs to make
            project.setVersions(getProjectVersions(project));
        }
        return project;
    }

    /**
     * Returns a project by its name and version.
     *
     * @param name    the name of the Project (required)
     * @param version the version of the Project (or null)
     * @return a Project object, or null if not found
     */
    @Override
    public Project getProject(final String name, final String version) {
        final Query<Project> query = pm.newQuery(Project.class);

        final var filterBuilder = new ProjectQueryFilterBuilder()
                .withName(name)
                .withVersion(version);

        final String queryFilter = filterBuilder.buildFilter();
        final Map<String, Object> params = filterBuilder.getParams();

        preprocessACLs(query, queryFilter, params);
        query.setRange(0, 1);
        final Project project = singleResult(query.executeWithMap(params));
        if (project != null) {
            // set Metrics to prevent extra round trip
            project.setMetrics(withJdbiHandle(handle ->
                    handle.attach(MetricsDao.class).getMostRecentProjectMetrics(project.getId())));
            // set ProjectVersions to prevent extra round trip
            project.setVersions(getProjectVersions(project));
        }
        return project;
    }

    /**
     * Returns the latest version of a project by its name.
     *
     * @param name the name of the Project (required)
     * @return a Project object representing the latest version, or null if not found
     */
    @Override
    public Project getLatestProjectVersion(final String name) {
        final Query<Project> query = pm.newQuery(Project.class);

        final var filterBuilder = new ProjectQueryFilterBuilder()
                .withName(name)
                .onlyLatestVersion();

        final String queryFilter = filterBuilder.buildFilter();
        final Map<String, Object> params = filterBuilder.getParams();

        preprocessACLs(query, queryFilter, params);
        query.setRange(0, 1);

        final Project project = singleResult(query.executeWithMap(params));
        if (project != null) {
            // set Metrics to prevent extra round trip
            project.setMetrics(withJdbiHandle(handle ->
                    handle.attach(MetricsDao.class).getMostRecentProjectMetrics(project.getId())));
            // set ProjectVersions to prevent extra round trip
            project.setVersions(getProjectVersions(project));
        }
        return project;
    }

    @Override
    public Project createProject(String name, String description, String version, Collection<Tag> tags, Project parent,
                                 PackageURL purl, Date inactiveSince, boolean commitIndex) {
        return createProject(name, description, version, tags, parent, purl, inactiveSince, false, commitIndex);
    }

    /**
     * Creates a new Project.
     *
     * @param name        the name of the project to create
     * @param description a description of the project
     * @param version     the project version
     * @param tags        a List of Tags - these will be resolved if necessary
     * @param parent      an optional parent Project
     * @param purl        an optional Package URL
     * @param inactiveSince      date when the project is deactivated
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @param isLatest    specified if the project version is latest
     * @return the created Project
     */
    @Override
    public Project createProject(String name, String description, String version, Collection<Tag> tags, Project parent,
                                 PackageURL purl, Date inactiveSince, boolean isLatest, boolean commitIndex) {
        final Project project = new Project();
        project.setName(name);
        project.setDescription(description);
        project.setVersion(version);
        project.setParent(parent);
        project.setPurl(purl);
        project.setInactiveSince(inactiveSince);
        project.setIsLatest(isLatest);
        return createProject(project, tags, commitIndex);
    }

    /**
     * Creates a new Project.
     *
     * @param project     the project to create
     * @param tags        a List of Tags - these will be resolved if necessary
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return the created Project
     */
    @Override
    public Project createProject(final Project project, Collection<Tag> tags, boolean commitIndex) {
        return callInTransaction(() -> {
            if (project.getParent() != null && project.getParent().getInactiveSince() != null) {
                throw new IllegalArgumentException("An inactive Parent cannot be selected as parent");
            }

            if (project.getCollectionLogic() == ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN_WITH_TAG) {
                if (project.getCollectionTag() == null) {
                    throw new IllegalArgumentException(
                            "A collection tag must be specified for AGGREGATE_DIRECT_CHILDREN_WITH_TAG logic.");
                }

                final Set<Tag> resolvedCollectionTags =
                        resolveTags(List.of(project.getCollectionTag()));
                project.setCollectionTag(resolvedCollectionTags.iterator().next());
            } else {
                project.setCollectionTag(null);
            }

            // Remove isLatest flag from current latest project version, if the new project will be the latest
            final Project oldLatestProject = project.isLatest() ? getLatestProjectVersion(project.getName()) : null;
            if (oldLatestProject != null) {
                oldLatestProject.setIsLatest(false);

                // Ensure the change is flushed to the database before the new project
                // record is created. Necessary to prevent unique constraint violation.
                pm.flush();
            }

            // NB: Prevent JDO from implicitly creating any tags already assigned to the project object.
            project.setTags(null);

            final Project newProject = persist(project);
            final Set<Tag> resolvedTags = resolveTags(tags);
            bind(project, resolvedTags);
            return newProject;
        });
    }

    /**
     * Updates an existing Project.
     *
     * @param transientProject the project to update
     * @param commitIndex      specifies if the search index should be committed (an expensive operation)
     * @return the updated Project
     */
    @Override
    public Project updateProject(Project transientProject, boolean commitIndex) {
        return callInTransaction(() -> {
            final Project project = getObjectByUuid(Project.class, transientProject.getUuid());
            project.setAuthors(transientProject.getAuthors());
            project.setPublisher(transientProject.getPublisher());
            project.setManufacturer(transientProject.getManufacturer());
            project.setSupplier(transientProject.getSupplier());
            project.setGroup(transientProject.getGroup());
            project.setName(transientProject.getName());
            project.setDescription(transientProject.getDescription());
            project.setVersion(transientProject.getVersion());
            project.setClassifier(transientProject.getClassifier());
            project.setCpe(transientProject.getCpe());
            project.setPurl(transientProject.getPurl());
            project.setSwidTagId(transientProject.getSwidTagId());
            project.setExternalReferences(transientProject.getExternalReferences());

            if (project.isActive() && !transientProject.isActive() && hasActiveChild(project)) {
                throw new IllegalArgumentException("Project cannot be set to inactive if active children are present.");
            }
            project.setActive(transientProject.isActive());

            // Remove isLatest flag from current latest project version, if this project will be the latest now
            if (transientProject.isLatest() && !project.isLatest()) {
                final Project oldLatestProject = getLatestProjectVersion(project.getName());
                if (oldLatestProject != null) {
                    oldLatestProject.setIsLatest(false);

                    // Ensure the change is flushed to the database before the project
                    // record is updated. Necessary to prevent unique constraint violation.
                    pm.flush();
                }
            }
            project.setIsLatest(transientProject.isLatest());

            if (transientProject.getParent() != null && transientProject.getParent().getUuid() != null) {
                if (project.getUuid().equals(transientProject.getParent().getUuid())) {
                    throw new IllegalArgumentException("A project cannot select itself as a parent");
                }
                Project parent = getObjectByUuid(Project.class, transientProject.getParent().getUuid());
                if (parent.getInactiveSince() != null) {
                    throw new IllegalArgumentException("An inactive project cannot be selected as a parent");
                } else if (isChildOf(parent, transientProject.getUuid())) {
                    throw new IllegalArgumentException("The new parent project cannot be a child of the current project.");
                } else {
                    project.setParent(parent);
                }
                project.setParent(parent);
            } else {
                project.setParent(null);
            }

            // Prevent illegal states of collection projects (must not contain components or services).
            final ProjectCollectionLogic newCollectionLogic = transientProject.getCollectionLogic();
            if (newCollectionLogic != null
                    && !newCollectionLogic.equals(project.getCollectionLogic())
                    && (hasComponents(project) || hasServiceComponents(project))) {
                throw new IllegalArgumentException(
                        "A project with components or services cannot be converted to a collection project.");
            }

            // NB: Resolve the collection tag BEFORE setting collectionLogic on the persistent project,
            // as resolveTags triggers a query that flushes dirty state, which would violate the
            // PROJECT_COLLECTION_TAG_REQUIRED_check constraint if collectionLogic is already set
            // but collectionTag is still null.
            Tag resolvedCollectionTag = null;
            if (newCollectionLogic == ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN_WITH_TAG) {
                if (transientProject.getCollectionTag() == null) {
                    throw new IllegalArgumentException(
                            "A collection tag must be specified for AGGREGATE_DIRECT_CHILDREN_WITH_TAG logic.");
                }

                final Set<Tag> resolvedCollectionTags =
                        resolveTags(List.of(transientProject.getCollectionTag()));
                resolvedCollectionTag = resolvedCollectionTags.iterator().next();
            }

            project.setCollectionLogic(newCollectionLogic);
            project.setCollectionTag(resolvedCollectionTag);
            if (newCollectionLogic != null) {
                project.setClassifier(null);
            }

            final Set<Tag> resolvedTags = resolveTags(transientProject.getTags());
            bind(project, resolvedTags);
            return persist(project);
        });
    }

    /**
     * Creates a key/value pair (ProjectProperty) for the specified Project.
     *
     * @param project       the Project to create the property for
     * @param groupName     the group name of the property
     * @param propertyName  the name of the property
     * @param propertyValue the value of the property
     * @param propertyType  the type of property
     * @param description   a description of the property
     * @return the created ProjectProperty object
     */
    @Override
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
     *
     * @param project      the project the property belongs to
     * @param groupName    the group name of the config property
     * @param propertyName the name of the property
     * @return a ProjectProperty object
     */
    @Override
    public ProjectProperty getProjectProperty(final Project project, final String groupName, final String propertyName) {
        final Query<ProjectProperty> query = this.pm.newQuery(ProjectProperty.class, "project == :project && groupName == :groupName && propertyName == :propertyName");
        query.setRange(0, 1);
        return singleResult(query.execute(project, groupName, propertyName));
    }

    /**
     * Returns a List of ProjectProperty's for the specified project.
     *
     * @param project the project the property belongs to
     * @return a List ProjectProperty objects
     */
    @Override
    @SuppressWarnings("unchecked")
    public List<ProjectProperty> getProjectProperties(final Project project) {
        final Query<ProjectProperty> query = this.pm.newQuery(ProjectProperty.class, "project == :project");
        query.setOrdering("groupName asc, propertyName asc");
        return (List<ProjectProperty>) query.execute(project);
    }

    /**
     * @since 4.12.3
     */
    @Override
    public boolean bind(final Project project, final Collection<Tag> tags, final boolean keepExisting) {
        assertPersistent(project, "project must be persistent");
        assertPersistentAll(tags, "tags must be persistent");

        return callInTransaction(() -> {
            boolean modified = false;

            if (project.getTags() == null) {
                project.setTags(new HashSet<>());
            }

            if (!keepExisting) {
                final Iterator<Tag> existingTagsIterator = project.getTags().iterator();
                while (existingTagsIterator.hasNext()) {
                    final Tag existingTag = existingTagsIterator.next();
                    if (!tags.contains(existingTag)) {
                        existingTagsIterator.remove();
                        if (existingTag.getProjects() != null) {
                            existingTag.getProjects().remove(project);
                        }
                        modified = true;
                    }
                }
            }
            for (final Tag tag : tags) {
                if (!project.getTags().contains(tag)) {
                    project.getTags().add(tag);

                    if (tag.getProjects() == null) {
                        tag.setProjects(new HashSet<>(Set.of(project)));
                    } else {
                        tag.getProjects().add(project);
                    }

                    modified = true;
                }
            }
            return modified;
        });
    }

    /**
     * Binds the two objects together in a corresponding join table.
     * @param project a Project object
     * @param tags a List of Tag objects
     */
    @Override
    public void bind(final Project project, final Collection<Tag> tags) {
        bind(project, tags, /* keepExisting */ false);
    }

    @Override
    public boolean hasAccess(final Principal principal, final Project project) {
        if (!isEnabled(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED)
                || principal == null // System request (e.g. MetricsUpdateTask, etc) where there isn't a principal
                || getEffectivePermissions(principal).contains(Permissions.Constants.PORTFOLIO_ACCESS_CONTROL_BYPASS))
            return true;

        final Query<?> query;
        switch (principal) {
            case User user -> {
                query = pm.newQuery(Query.SQL, /* language=SQL */ """
                                SELECT EXISTS(
                                  SELECT 1
                                    FROM "PROJECT_ACCESS_USERS" AS pau
                                   INNER JOIN "PROJECT_HIERARCHY" AS ph
                                      ON ph."PARENT_PROJECT_ID" = pau."PROJECT_ID"
                                   WHERE ph."CHILD_PROJECT_ID" = ?
                                     AND pau."USER_ID" = ?
                                )
                                """)
                        .setParameters(project.getId(), user.getId());
            }
            case ApiKey apiKey -> {
                query = pm.newQuery(Query.SQL, /* language=SQL */ """
                                SELECT EXISTS(
                                  SELECT 1
                                    FROM "APIKEYS_TEAMS" AS akt
                                   INNER JOIN "PROJECT_ACCESS_TEAMS" AS pat
                                      ON pat."TEAM_ID" = akt."TEAM_ID"
                                   INNER JOIN "PROJECT_HIERARCHY" AS ph
                                      ON ph."PARENT_PROJECT_ID" = pat."PROJECT_ID"
                                   WHERE akt."APIKEY_ID" = ?
                                     AND ph."CHILD_PROJECT_ID" = ?
                                )
                                """)
                        .setParameters(apiKey.getId(), project.getId());
            }
            default -> {
                return false;
            }
        }

        return executeAndCloseResultUnique(query, Boolean.class);
    }

    void preprocessACLs(final Query<?> query, final String inputFilter, final Map<String, Object> params) {
        if (principal == null
            || !isEnabled(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED)
            || getEffectivePermissions(principal).contains(Permissions.Constants.PORTFOLIO_ACCESS_CONTROL_BYPASS)) {
            query.setFilter(inputFilter);
            return;
        }

        String projectMemberFieldName = null;
        final org.datanucleus.store.query.Query<?> internalQuery = ((JDOQuery<?>)query).getInternalQuery();
        if (!Project.class.equals(internalQuery.getCandidateClass())) {
            // NB: The query does not directly target Project, but if it has a relationship
            // with Project we can still make the ACL check work. If the query candidate
            // has EXACTLY one persistent field of type Project, we'll use that.
            // If there are more than one, or none at all, we fail to avoid unintentional behavior.
            final TypeMetadata candidateTypeMetadata = pm.getPersistenceManagerFactory().getMetadata(internalQuery.getCandidateClassName());

            for (final MemberMetadata memberMetadata : candidateTypeMetadata.getMembers()) {
                if (!Project.class.getName().equals(memberMetadata.getFieldType())) {
                    continue;
                }

                if (projectMemberFieldName != null) {
                    throw new IllegalArgumentException("Query candidate class %s has multiple members of type %s"
                            .formatted(internalQuery.getCandidateClassName(), Project.class.getName()));
                }

                projectMemberFieldName = memberMetadata.getName();
            }

            if (projectMemberFieldName == null) {
                throw new IllegalArgumentException("Query candidate class %s has no member of type %s"
                        .formatted(internalQuery.getCandidateClassName(), Project.class.getName()));
            }
        }

        final String aclCondition = switch (principal) {
            case ApiKey apiKey -> {
                final Set<Long> teamIds = getTeamIds(apiKey);
                if (teamIds.isEmpty()) {
                    yield "false";
                }

                params.put("projectAclTeamIds", teamIds.toArray(new Long[0]));
                yield "%s.isAccessibleBy(:projectAclTeamIds)".formatted(
                        requireNonNullElse(projectMemberFieldName, "this"));
            }
            case User user -> {
                params.put("projectAclUserId", user.getId());
                yield "%s.isAccessibleBy(:projectAclUserId)".formatted(
                        requireNonNullElse(projectMemberFieldName, "this"));
            }
            default -> "false";
        };

        if (inputFilter != null && !inputFilter.isBlank()) {
            query.setFilter("%s && (%s)".formatted(inputFilter, aclCondition));
        } else {
            query.setFilter("(%s)".formatted(aclCondition));
        }
    }

    /**
     * Updates a Project ACL to add the principals Team to the AccessTeams
     * This only happens if Portfolio Access Control is enabled and the @param principal is an ApyKey
     * For a User we don't know which Team(s) to add to the ACL,
     * See https://github.com/DependencyTrack/dependency-track/issues/1435
     *
     * @param project
     * @param principal
     * @return True if ACL was updated
     */
    @Override
    public boolean updateNewProjectACL(Project project, Principal principal) {
        if (isEnabled(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED) && principal instanceof ApiKey apiKey) {
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

    @Override
    public boolean hasAccessManagementPermission(final User user) {
        return hasPermission(user, Permissions.Constants.ACCESS_MANAGEMENT, true);
    }

    @Override
    public boolean hasAccessManagementPermission(final ApiKey apiKey) {
        return hasPermission(apiKey, Permissions.ACCESS_MANAGEMENT.name());
    }

    @Override
    public PaginatedResult getChildrenProjects(final UUID uuid, final boolean includeMetrics, final boolean excludeInactive) {
        final PaginatedResult result;
        final Query<Project> query = pm.newQuery(Project.class);
        if (orderBy == null) {
            query.setOrdering("name asc, version desc, id asc");
        }

        var filterBuilder = new ProjectQueryFilterBuilder()
                .excludeInactive(excludeInactive)
                .withParent(uuid);

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

        preprocessACLs(query, queryFilter, params);
        query.getFetchPlan().addGroup(Project.FetchGroup.ALL.name());
        result = execute(query, params);
        if (!result.getObjects().isEmpty() && includeMetrics) {
            populateMetrics(result.getList(Project.class));
        }
        return result;
    }

    @Override
    public PaginatedResult getChildrenProjects(final Classifier classifier, final UUID uuid, final boolean includeMetrics, final boolean excludeInactive) {
        final PaginatedResult result;
        final Query<Project> query = pm.newQuery(Project.class);
        if (orderBy == null) {
            query.setOrdering("name asc, id asc");
        }

        final var filterBuilder = new ProjectQueryFilterBuilder()
                .excludeInactive(excludeInactive)
                .withParent(uuid)
                .withClassifier(classifier);

        final String queryFilter = filterBuilder.buildFilter();
        final Map<String, Object> params = filterBuilder.getParams();

        preprocessACLs(query, queryFilter, params);
        query.getFetchPlan().addGroup(Project.FetchGroup.ALL.name());
        result = execute(query, params);

        if (!result.getObjects().isEmpty() && includeMetrics) {
            populateMetrics(result.getList(Project.class));
        }

        return result;
    }

    @Override
    public PaginatedResult getChildrenProjects(final Tag tag, final UUID uuid, final boolean includeMetrics, final boolean excludeInactive) {
        final PaginatedResult result;
        final Query<Project> query = pm.newQuery(Project.class);
        if (orderBy == null) {
            query.setOrdering("name asc, id asc");
        }

        var filterBuilder = new ProjectQueryFilterBuilder()
                .excludeInactive(excludeInactive)
                .withParent(uuid)
                .withTag(tag);

        if (filter != null) {
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            filterBuilder = filterBuilder.withFuzzyName(filterString);
        }

        final String queryFilter = filterBuilder.buildFilter();
        final Map<String, Object> params = filterBuilder.getParams();

        preprocessACLs(query, queryFilter, params);
        result = execute(query, params);

        if (!result.getObjects().isEmpty() && includeMetrics) {
            populateMetrics(result.getList(Project.class));
        }

        return result;
    }

    @Override
    public PaginatedResult getProjectsWithoutDescendantsOf(final boolean exludeInactive, final Project project) {
        final PaginatedResult result;
        final Query<Project> query = pm.newQuery(Project.class);
        if (orderBy == null) {
            query.setOrdering("name asc, version desc, id asc");
        }

        var filterBuilder = new ProjectQueryFilterBuilder()
                .excludeInactive(exludeInactive);

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

        preprocessACLs(query, queryFilter, params);
        result = execute(query, params);

        result.setObjects(result.getList(Project.class).stream().filter(p -> !isChildOf(p, project.getUuid()) && !p.getUuid().equals(project.getUuid())).toList());
        result.setTotal(result.getObjects().size());

        return result;
    }

    @Override
    public PaginatedResult getProjectsWithoutDescendantsOf(final String name, final boolean excludeInactive, Project project) {
        final PaginatedResult result;
        final Query<Project> query = pm.newQuery(Project.class);
        if (orderBy == null) {
            query.setOrdering("name asc, version desc, id asc");
        }

        var filterBuilder = new ProjectQueryFilterBuilder()
                .excludeInactive(excludeInactive)
                .withName(name);

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

        preprocessACLs(query, queryFilter, params);
        result = execute(query, params);

        result.setObjects(result.getList(Project.class).stream().filter(p -> !isChildOf(p, project.getUuid()) && !p.getUuid().equals(project.getUuid())).toList());
        result.setTotal(result.getObjects().size());

        return result;
    }

    /**
     * Check whether a {@link Project} with a given {@code name} and {@code version} exists.
     *
     * @param name    Name of the {@link Project} to check for
     * @param version Version of the {@link Project} to check for
     * @return {@code true} when a matching {@link Project} exists, otherwise {@code false}
     * @since 4.9.0
     */
    @Override
    public boolean doesProjectExist(final String name, final String version) {
        final Query<Project> query = pm.newQuery(Project.class);
        if (version != null) {
            query.setFilter("name == :name && version == :version");
            query.setNamedParameters(Map.of(
                    "name", name,
                    "version", version
            ));
        } else {
            // Version is optional for projects, but using null
            // for parameter values bypasses the query compilation cache.
            // https://github.com/DependencyTrack/dependency-track/issues/2540
            query.setFilter("name == :name && version == null");
            query.setNamedParameters(Map.of(
                    "name", name
            ));
        }
        query.setRange(0, 1);
        query.setResult("id");
        return !executeAndCloseResultList(query, Long.class).isEmpty();
    }

    private boolean isChildOf(Project project, UUID uuid) {
        final Query<?> query = pm.newQuery(Query.SQL, /* language=SQL */ """
                SELECT EXISTS (
                  SELECT 1
                    FROM "PROJECT_HIERARCHY"
                   WHERE "PARENT_PROJECT_ID" = (SELECT "ID" FROM "PROJECT" WHERE "UUID" = ?)
                     AND "CHILD_PROJECT_ID" = ?
                )
                """);
        query.setParameters(uuid, project.getId());
        try {
            return (boolean) query.executeUnique();
        } finally {
            query.closeAll();
        }
    }

    private boolean hasActiveChild(Project project) {
        final Query<?> query = pm.newQuery(Query.SQL, /* language=SQL */ """
                SELECT EXISTS (
                  SELECT 1
                    FROM "PROJECT_HIERARCHY" AS hierarchy
                   INNER JOIN "PROJECT" AS child_project
                      ON child_project."ID" = hierarchy."CHILD_PROJECT_ID"
                   WHERE hierarchy."PARENT_PROJECT_ID" = ?
                     AND hierarchy."DEPTH" > 0
                     AND child_project."INACTIVE_SINCE" IS NULL
                )
                """);
        query.setParameters(project.getId());
        try {
            return (boolean) query.executeUnique();
        } finally {
            query.closeAll();
        }
    }

    private List<ProjectVersion> getProjectVersions(Project project) {
        final Query<Project> query = pm.newQuery(Project.class);
        query.setResult("uuid, version, inactiveSince");
        query.setOrdering("id asc"); // Ensure consistent ordering
        final var params = new HashMap<String, Object>();
        params.put("name", project.getName());
        preprocessACLs(query, "name == :name", params);
        query.setNamedParameters(params);
        return executeAndCloseResultList(query, ProjectVersion.class);
    }

    private void populateMetrics(final Collection<Project> projects) {
        final Map<Long, Project> projectById = projects.stream()
                .collect(Collectors.toMap(Project::getId, Function.identity()));
        final List<ProjectMetrics> metricsList = withJdbiHandle(
                handle -> handle.attach(MetricsDao.class).getMostRecentProjectMetrics(projectById.keySet()));
        for (final ProjectMetrics metrics : metricsList) {
            final Project project = projectById.get(metrics.getProjectId());
            if (project != null) {
                project.setMetrics(metrics);
            }
        }
    }

}
