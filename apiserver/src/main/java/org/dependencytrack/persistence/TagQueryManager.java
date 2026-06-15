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

import alpine.persistence.OrderDirection;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.exception.InvalidSortFieldException;
import org.dependencytrack.exception.TagOperationFailedException;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class TagQueryManager extends QueryManager {

    private static final Comparator<Tag> TAG_COMPARATOR = Comparator.comparingInt(
            (Tag tag) -> tag.getProjects().size()).reversed();

    private static final Logger LOGGER = LoggerFactory.getLogger(ProjectQueryManager.class);

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    TagQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    TagQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * @since 4.12.0
     */
    public record TagListRow(
            String name,
            long projectCount,
            long collectionProjectCount,
            long policyCount,
            long notificationRuleCount,
            long vulnerabilityCount,
            long totalCount
    ) {
    }

    /**
     * @since 4.12.0
     */
    @Override
    public List<TagListRow> getTags() {
        final Map.Entry<String, Map<String, Object>> projectAclConditionAndParams = getProjectAclSqlCondition();
        final String projectAclCondition = projectAclConditionAndParams.getKey();
        final Map<String, Object> projectAclConditionParams = projectAclConditionAndParams.getValue();

        // language=SQL
        var sqlQuery = """
                SELECT "NAME" AS "name"
                     , (SELECT COUNT(*)
                          FROM "PROJECTS_TAGS"
                         INNER JOIN "PROJECT"
                            ON "PROJECT"."ID" = "PROJECTS_TAGS"."PROJECT_ID"
                         WHERE "PROJECTS_TAGS"."TAG_ID" = "TAG"."ID"
                           AND %1$s) AS "projectCount"
                     , (SELECT COUNT(*)
                          FROM "PROJECT"
                         WHERE "COLLECTION_TAG_ID" = "TAG"."ID"
                           AND %1$s) AS "collectionProjectCount"
                     , (SELECT COUNT(*)
                          FROM "POLICY_TAGS"
                         WHERE "POLICY_TAGS"."TAG_ID" = "TAG"."ID") AS "policyCount"
                     , (SELECT COUNT(*)
                            FROM "NOTIFICATIONRULE_TAGS"
                         WHERE "NOTIFICATIONRULE_TAGS"."TAG_ID" = "TAG"."ID") AS "notificationRuleCount"
                     , (SELECT COUNT(*)
                            FROM "VULNERABILITIES_TAGS"
                         WHERE "VULNERABILITIES_TAGS"."TAG_ID" = "TAG"."ID") AS "vulnerabilityCount"
                     , COUNT(*) OVER() AS "totalCount"
                  FROM "TAG"
                """.formatted(projectAclCondition);

        final var params = new HashMap<>(projectAclConditionParams);

        if (filter != null) {
            sqlQuery += " WHERE \"NAME\" LIKE :nameFilter";
            params.put("nameFilter", "%" + filter.toLowerCase() + "%");
        }

        if (orderBy == null) {
            sqlQuery += " ORDER BY \"name\" ASC";
        } else if ("name".equals(orderBy)
                || "projectCount".equals(orderBy)
                || "collectionProjectCount".equals(orderBy)
                || "policyCount".equals(orderBy)
                || "notificationRuleCount".equals(orderBy)
                || "vulnerabilityCount".equals(orderBy)) {
            sqlQuery += " ORDER BY \"%s\" %s, \"ID\" ASC".formatted(orderBy,
                    orderDirection == OrderDirection.DESCENDING ? "DESC" : "ASC");
        } else {
            throw new InvalidSortFieldException(orderBy, List.of(
                    "name", "projectCount", "collectionProjectCount",
                    "policyCount", "notificationRuleCount", "vulnerabilityCount"));
        }

        sqlQuery += " " + getOffsetLimitSqlClause();

        final Query<?> query = pm.newQuery(Query.SQL, sqlQuery);
        query.setNamedParameters(params);
        return executeAndCloseResultList(query, TagListRow.class);
    }

    /**
     * @since 4.12.0
     */
    public record TaggedProjectRow(UUID uuid, String name, String version, long totalCount) {
    }

    /**
     * @since 4.12.0
     */
    public record TagDeletionCandidateRow(
            long id,
            String name,
            long projectCount,
            long accessibleProjectCount,
            long collectionProjectCount,
            long policyCount,
            long notificationRuleCount,
            long vulnerabilityCount
    ) {
    }

    /**
     * @since 4.12.0
     */
    @Override
    public void deleteTags(final Collection<String> tagNames) {
        runInTransaction(() -> {
            final Map.Entry<String, Map<String, Object>> projectAclConditionAndParams = getProjectAclSqlCondition();
            final String projectAclCondition = projectAclConditionAndParams.getKey();
            final Map<String, Object> projectAclConditionParams = projectAclConditionAndParams.getValue();

            final var tagNameFilters = new ArrayList<String>(tagNames.size());
            final var params = new HashMap<>(projectAclConditionParams);

            int paramIndex = 0;
            for (final String tagName : tagNames) {
                final var paramName = "tagName" + (++paramIndex);
                tagNameFilters.add("\"NAME\" = :" + paramName);
                params.put(paramName, tagName);
            }

            final Query<?> candidateQuery = pm.newQuery(Query.SQL, /* language=SQL */ """
                    SELECT "ID"
                         , "NAME"
                         , (SELECT COUNT(*)
                              FROM "PROJECTS_TAGS"
                             INNER JOIN "PROJECT"
                                ON "PROJECT"."ID" = "PROJECTS_TAGS"."PROJECT_ID"
                             WHERE "PROJECTS_TAGS"."TAG_ID" = "TAG"."ID") AS "projectCount"
                         , (SELECT COUNT(*)
                              FROM "PROJECTS_TAGS"
                             INNER JOIN "PROJECT"
                                ON "PROJECT"."ID" = "PROJECTS_TAGS"."PROJECT_ID"
                             WHERE "PROJECTS_TAGS"."TAG_ID" = "TAG"."ID"
                               AND %1$s) AS "accessibleProjectCount"
                         , (SELECT COUNT(*)
                              FROM "PROJECT"
                             WHERE "COLLECTION_TAG_ID" = "TAG"."ID") AS "collectionProjectCount"
                         , (SELECT COUNT(*)
                              FROM "POLICY_TAGS"
                             INNER JOIN "POLICY"
                                ON "POLICY"."ID" = "POLICY_TAGS"."POLICY_ID"
                             WHERE "POLICY_TAGS"."TAG_ID" = "TAG"."ID") AS "policyCount"
                         , (SELECT COUNT(*)
                              FROM "NOTIFICATIONRULE_TAGS"
                             INNER JOIN "NOTIFICATIONRULE"
                                ON "NOTIFICATIONRULE"."ID" = "NOTIFICATIONRULE_TAGS"."NOTIFICATIONRULE_ID"
                             WHERE "NOTIFICATIONRULE_TAGS"."TAG_ID" = "TAG"."ID") AS "notificationRuleCount"
                         , (SELECT COUNT(*)
                              FROM "VULNERABILITIES_TAGS"
                             INNER JOIN "VULNERABILITY"
                                ON "VULNERABILITY"."ID" = "VULNERABILITIES_TAGS"."VULNERABILITY_ID"
                             WHERE "VULNERABILITIES_TAGS"."TAG_ID" = "TAG"."ID") AS "vulnerabilityCount"
                      FROM "TAG"
                     WHERE %2$s
                    """.formatted(projectAclCondition, String.join(" OR ", tagNameFilters)));
            candidateQuery.setNamedParameters(params);
            final List<TagDeletionCandidateRow> candidateRows =
                    executeAndCloseResultList(candidateQuery, TagDeletionCandidateRow.class);

            final var errorByTagName = new HashMap<String, String>();

            if (tagNames.size() > candidateRows.size()) {
                final Set<String> candidateRowNames = candidateRows.stream()
                        .map(TagDeletionCandidateRow::name)
                        .collect(Collectors.toSet());
                for (final String tagName : tagNames) {
                    if (!candidateRowNames.contains(tagName)) {
                        errorByTagName.put(tagName, "Tag does not exist");
                    }
                }

                throw TagOperationFailedException.forDeletion(errorByTagName);
            }

            final boolean hasPortfolioManagementUpdatePermission;
            final boolean hasPolicyManagementUpdatePermission;
            final boolean hasVulnerabilityManagementUpdatePermission;
            final boolean hasSystemConfigurationUpdatePermission;
            if (request == null) {
                hasPortfolioManagementUpdatePermission = true;
                hasPolicyManagementUpdatePermission = true;
                hasVulnerabilityManagementUpdatePermission = true;
                hasSystemConfigurationUpdatePermission = true;
            } else {
                final Set<String> effectivePermissions = request.getEffectivePermissions();
                hasPortfolioManagementUpdatePermission =
                        effectivePermissions.contains(Permissions.Constants.PORTFOLIO_MANAGEMENT)
                                || effectivePermissions.contains(Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE);
                hasPolicyManagementUpdatePermission =
                        effectivePermissions.contains(Permissions.Constants.POLICY_MANAGEMENT)
                                || effectivePermissions.contains(Permissions.Constants.POLICY_MANAGEMENT_UPDATE);
                hasSystemConfigurationUpdatePermission =
                        effectivePermissions.contains(Permissions.Constants.SYSTEM_CONFIGURATION)
                                || effectivePermissions.contains(Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE);
                hasVulnerabilityManagementUpdatePermission =
                        effectivePermissions.contains(Permissions.Constants.VULNERABILITY_MANAGEMENT)
                                || effectivePermissions.contains(Permissions.Constants.VULNERABILITY_MANAGEMENT_UPDATE);
            }

            for (final TagDeletionCandidateRow row : candidateRows) {
                if (row.projectCount() > 0 && !hasPortfolioManagementUpdatePermission) {
                    errorByTagName.put(row.name(), """
                            The tag is assigned to %d project(s), but the authenticated principal \
                            is missing the %s or %s permission.""".formatted(row.projectCount(),
                            Permissions.PORTFOLIO_MANAGEMENT, Permissions.PORTFOLIO_MANAGEMENT_UPDATE));
                    continue;
                }

                final long inaccessibleProjectAssignmentCount =
                        row.projectCount() - row.accessibleProjectCount();
                if (inaccessibleProjectAssignmentCount > 0) {
                    errorByTagName.put(row.name(), """
                            The tag is assigned to %d project(s) that are not accessible \
                            by the authenticated principal.""".formatted(inaccessibleProjectAssignmentCount));
                    continue;
                }

                if (row.collectionProjectCount() > 0) {
                    errorByTagName.put(row.name(), "The tag is used by %d collection project(s)".formatted(row.collectionProjectCount()));
                    continue;
                }

                if (row.policyCount() > 0 && !hasPolicyManagementUpdatePermission) {
                    errorByTagName.put(row.name(), """
                            The tag is assigned to %d policies, but the authenticated principal \
                            is missing the %s or %s permission.""".formatted(row.policyCount(),
                            Permissions.POLICY_MANAGEMENT, Permissions.POLICY_MANAGEMENT_UPDATE));
                }

                if (row.notificationRuleCount() > 0 && !hasSystemConfigurationUpdatePermission) {
                    errorByTagName.put(row.name(), """
                            The tag is assigned to %d notification rules, but the authenticated principal \
                            is missing the %s or %s permission.""".formatted(row.notificationRuleCount(),
                            Permissions.SYSTEM_CONFIGURATION, Permissions.SYSTEM_CONFIGURATION_UPDATE));
                }

                if (row.vulnerabilityCount() > 0 && !hasVulnerabilityManagementUpdatePermission) {
                    errorByTagName.put(row.name(), """
                            The tag is assigned to %d vulnerabilities, but the authenticated principal \
                            is missing the %s or %s permission.""".formatted(row.vulnerabilityCount(),
                            Permissions.VULNERABILITY_MANAGEMENT, Permissions.VULNERABILITY_MANAGEMENT_UPDATE));
                }
            }

            if (!errorByTagName.isEmpty()) {
                throw TagOperationFailedException.forDeletion(errorByTagName);
            }

            final Query<Tag> deletionQuery = pm.newQuery(Tag.class);
            deletionQuery.setFilter(":ids.contains(id)");
            try {
                deletionQuery.deletePersistentAll(
                        candidateRows.stream()
                                .map(TagDeletionCandidateRow::id)
                                .toList());
            } finally {
                deletionQuery.closeAll();
            }
        });
    }

    /**
     * @since 4.12.0
     */
    @Override
    public List<TaggedProjectRow> getTaggedProjects(final String tagName) {
        final Map.Entry<String, Map<String, Object>> projectAclConditionAndParams = getProjectAclSqlCondition();
        final String projectAclCondition = projectAclConditionAndParams.getKey();
        final Map<String, Object> projectAclConditionParams = projectAclConditionAndParams.getValue();

        // language=SQL
        var sqlQuery = """
            SELECT "PROJECT"."UUID" AS "uuid"
                 , "PROJECT"."NAME" AS "name"
                 , "PROJECT"."VERSION" AS "version"
                 , COUNT(*) OVER() AS "totalCount"
              FROM "PROJECT"
             INNER JOIN "PROJECTS_TAGS"
                ON "PROJECTS_TAGS"."PROJECT_ID" = "PROJECT"."ID"
             INNER JOIN "TAG"
                ON "TAG"."ID" = "PROJECTS_TAGS"."TAG_ID"
             WHERE "TAG"."NAME" = :tag
               AND %s
            """.formatted(projectAclCondition);

        final var params = new HashMap<>(projectAclConditionParams);
        params.put("tag", tagName);

        if (filter != null) {
            sqlQuery += " AND \"PROJECT\".\"NAME\" LIKE :nameFilter";
            params.put("nameFilter", "%" + filter + "%");
        }

        if (orderBy == null) {
            sqlQuery += " ORDER BY \"name\" ASC, \"version\" DESC";
        } else if ("name".equals(orderBy) || "version".equals(orderBy)) {
            sqlQuery += " ORDER BY \"%s\" %s, \"ID\" ASC".formatted(orderBy,
                    orderDirection == OrderDirection.DESCENDING ? "DESC" : "ASC");
        } else {
            throw new InvalidSortFieldException(orderBy, List.of("name", "version"));
        }

        sqlQuery += " " + getOffsetLimitSqlClause();

        final Query<?> query = pm.newQuery(Query.SQL, sqlQuery);
        query.setNamedParameters(params);
        return executeAndCloseResultList(query, TaggedProjectRow.class);
    }

    /**
     * @since 4.12.0
     */
    @Override
    public void tagProjects(final String tagName, final Collection<String> projectUuids) {
        runInTransaction(() -> {
            final Tag tag = getTagByName(tagName);
            if (tag == null) {
                throw new NoSuchElementException("A tag with name %s does not exist".formatted(tagName));
            }

            final Query<Project> projectsQuery = pm.newQuery(Project.class);
            final var params = new HashMap<String, Object>(Map.of("uuids", projectUuids));
            preprocessACLs(projectsQuery, ":uuids.contains(uuid)", params);
            projectsQuery.setNamedParameters(params);
            final List<Project> projects = executeAndCloseList(projectsQuery);

            for (final Project project : projects) {
                bind(project, List.of(tag), /* keepExisting */ true);
            }
        });
    }

    /**
     * @since 4.12.0
     */
    @Override
    public void untagProjects(final String tagName, final Collection<String> projectUuids) {
        runInTransaction(() -> {
            final Tag tag = getTagByName(tagName);
            if (tag == null) {
                throw new NoSuchElementException("A tag with name %s does not exist".formatted(tagName));
            }

            final Query<Project> projectsQuery = pm.newQuery(Project.class);
            final var params = new HashMap<String, Object>(Map.of("uuids", projectUuids));
            preprocessACLs(projectsQuery, ":uuids.contains(uuid)", params);
            projectsQuery.setNamedParameters(params);
            final List<Project> projects = executeAndCloseList(projectsQuery);

            for (final Project project : projects) {
                if (project.getTags() == null || project.getTags().isEmpty()) {
                    continue;
                }

                project.getTags().remove(tag);
            }
        });
    }

    /**
     * @since 4.13.1
     */
    public record TaggedCollectionProjectRow(UUID uuid, String name, String version, long totalCount) {
    }

    /**
     * @since 4.13.1
     */
    @Override
    public List<TaggedCollectionProjectRow> getTaggedCollectionProjects(final String tagName) {
        final Map.Entry<String, Map<String, Object>> projectAclConditionAndParams = getProjectAclSqlCondition();
        final String projectAclCondition = projectAclConditionAndParams.getKey();
        final Map<String, Object> projectAclConditionParams = projectAclConditionAndParams.getValue();

        // language=SQL
        var sqlQuery = """
                SELECT "PROJECT"."UUID" AS "uuid"
                     , "PROJECT"."NAME" AS "name"
                     , "PROJECT"."VERSION" AS "version"
                     , COUNT(*) OVER() AS "totalCount"
                  FROM "PROJECT"
                 INNER JOIN "TAG"
                    ON "TAG"."ID" = "PROJECT"."COLLECTION_TAG_ID"
                 WHERE "TAG"."NAME" = :tag
                   AND %s
                """.formatted(projectAclCondition);

        final var params = new HashMap<>(projectAclConditionParams);
        params.put("tag", tagName);

        if (filter != null) {
            sqlQuery += " AND \"PROJECT\".\"NAME\" LIKE :nameFilter";
            params.put("nameFilter", "%" + filter + "%");
        }

        if (orderBy == null) {
            sqlQuery += " ORDER BY \"name\" ASC, \"version\" DESC";
        } else if ("name".equals(orderBy) || "version".equals(orderBy)) {
            sqlQuery += " ORDER BY \"%s\" %s, \"ID\" ASC".formatted(orderBy,
                    orderDirection == OrderDirection.DESCENDING ? "DESC" : "ASC");
        } else {
            throw new InvalidSortFieldException(orderBy, List.of("name", "version"));
        }

        sqlQuery += " " + getOffsetLimitSqlClause();

        final Query<?> query = pm.newQuery(Query.SQL, sqlQuery);
        query.setNamedParameters(params);
        return executeAndCloseResultList(query, TaggedCollectionProjectRow.class);
    }

    /**
     * @since 4.12.0
     */
    public record TaggedPolicyRow(UUID uuid, String name, long totalCount) {
    }

    /**
     * @since 4.12.0
     */
    @Override
    public List<TaggedPolicyRow> getTaggedPolicies(final String tagName) {
        // language=SQL
        var sqlQuery = """
                SELECT "POLICY"."UUID" AS "uuid"
                     , "POLICY"."NAME" AS "name"
                     , COUNT(*) OVER() AS "totalCount"
                  FROM "POLICY"
                 INNER JOIN "POLICY_TAGS"
                    ON "POLICY_TAGS"."POLICY_ID" = "POLICY"."ID"
                 INNER JOIN "TAG"
                    ON "TAG"."ID" = "POLICY_TAGS"."TAG_ID"
                 WHERE "TAG"."NAME" = :tag
                """;

        final var params = new HashMap<String, Object>();
        params.put("tag", tagName);

        if (filter != null) {
            sqlQuery += " AND \"POLICY\".\"NAME\" LIKE :nameFilter";
            params.put("nameFilter", "%" + filter + "%");
        }

        if (orderBy == null) {
            sqlQuery += " ORDER BY \"name\" ASC";
        } else if ("name".equals(orderBy)) {
            sqlQuery += " ORDER BY \"%s\" %s".formatted(orderBy,
                    orderDirection == OrderDirection.DESCENDING ? "DESC" : "ASC");
        } else {
            throw new InvalidSortFieldException(orderBy, List.of("name"));
        }

        sqlQuery += " " + getOffsetLimitSqlClause();

        final Query<?> query = pm.newQuery(Query.SQL, sqlQuery);
        query.setNamedParameters(params);
        return executeAndCloseResultList(query, TaggedPolicyRow.class);
    }

    /**
     * @since 4.12.0
     */
    @Override
    public void tagPolicies(final String tagName, final Collection<String> policyUuids) {
        runInTransaction(() -> {
            final Tag tag = getTagByName(tagName);
            if (tag == null) {
                throw new NoSuchElementException("A tag with name %s does not exist".formatted(tagName));
            }

            final Query<Policy> policiesQuery = pm.newQuery(Policy.class);
            policiesQuery.setFilter(":uuids.contains(uuid)");
            policiesQuery.setParameters(policyUuids);
            final List<Policy> policies = executeAndCloseList(policiesQuery);

            for (final Policy policy : policies) {
                bind(policy, List.of(tag), /* keepExisting */ true);
            }
        });
    }

    /**
     * @since 4.12.0
     */
    @Override
    public void untagPolicies(final String tagName, final Collection<String> policyUuids) {
        runInTransaction(() -> {
            final Tag tag = getTagByName(tagName);
            if (tag == null) {
                throw new NoSuchElementException("A tag with name %s does not exist".formatted(tagName));
            }

            final Query<Policy> policiesQuery = pm.newQuery(Policy.class);
            policiesQuery.setFilter(":uuids.contains(uuid)");
            policiesQuery.setParameters(policyUuids);
            final List<Policy> policies = executeAndCloseList(policiesQuery);

            for (final Policy policy : policies) {
                if (policy.getTags() == null || policy.getTags().isEmpty()) {
                    continue;
                }

                policy.getTags().remove(tag);
            }
        });
    }

    @Override
    public PaginatedResult getTagsForPolicy(String policyUuid) {
        LOGGER.debug("Retrieving tags under policy {}", policyUuid);
        final var policy = getObjectByUuid(Policy.class, policyUuid);
        final var tags = Optional.ofNullable(policy.getTags())
                .orElse(Collections.emptySet()).stream().sorted(TAG_COMPARATOR).toList();
        return (new PaginatedResult()).objects(tags).total(tags.size());
    }

    /**
     * Returns a list of Tag objects what have been resolved. It resolved
     * tags by querying the database to retrieve the tag. If the tag does
     * not exist, the tag will be created and returned with other resolved
     * tags.
     *
     * @param tags a List of Tags to resolve
     * @return List of resolved Tags
     */
    public synchronized Set<Tag> resolveTags(final Collection<Tag> tags) {
        if (tags == null) {
            return new HashSet<>();
        }
         List<String> tagNames = tags.stream().map(Tag::getName).toList();
         return resolveTagsByName(tagNames);
    }

    public synchronized Set<Tag> resolveTagsByName(final Collection<String> tags) {
        if (tags == null) {
            return new HashSet<>();
        }
        final Set<Tag> resolvedTags = new HashSet<>();
        final Set<String> unresolvedTags = new HashSet<>();
        for (final String tag : tags) {
            final String trimmedTag = StringUtils.trimToNull(tag);
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
     *
     * @param name the name of the Tag
     * @return a Tag object
     */
    @Override
    public Tag getTagByName(final String name) {
        final String loweredTrimmedTag = StringUtils.lowerCase(StringUtils.trimToNull(name));
        final Query<Tag> query = pm.newQuery(Tag.class, "name == :name");
        query.setRange(0, 1);
        return singleResult(query.execute(loweredTrimmedTag));
    }

    /**
     * Creates a new Tag object with the specified name.
     *
     * @param name the name of the Tag to create
     * @return the created Tag object
     */
    @Override
    public Tag createTag(final String name) {
        final String loweredTrimmedTag = StringUtils.lowerCase(StringUtils.trimToNull(name));
        final Tag resolvedTag = getTagByName(loweredTrimmedTag);
        if (resolvedTag != null) {
            return resolvedTag;
        }
        final Tag tag = new Tag();
        tag.setName(loweredTrimmedTag);
        return persist(tag);
    }

    /**
     * Creates one or more Tag objects from the specified name(s).
     *
     * @param names the name(s) of the Tag(s) to create
     * @return the created Tag object(s)
     */
    @Override
    public Set<Tag> createTags(final Collection<String> names) {
        final Set<Tag> newTags = new HashSet<>();
        for (final String name : names) {
            final String loweredTrimmedTag = StringUtils.lowerCase(StringUtils.trimToNull(name));
            if (getTagByName(loweredTrimmedTag) == null) {
                final Tag tag = new Tag();
                tag.setName(loweredTrimmedTag);
                newTags.add(tag);
            }
        }
        return new HashSet<>(persist(newTags));
    }

    /**
     * @since 4.12.0
     */
    public record TaggedNotificationRuleRow(UUID uuid, String name, long totalCount) {
    }

    /**
     * @since 4.12.0
     */
    @Override
    public List<TaggedNotificationRuleRow> getTaggedNotificationRules(final String tagName) {
        // language=SQL
        var sqlQuery = """
                SELECT "NOTIFICATIONRULE"."UUID" AS "uuid"
                     , "NOTIFICATIONRULE"."NAME" AS "name"
                     , COUNT(*) OVER() AS "totalCount"
                  FROM "NOTIFICATIONRULE"
                 INNER JOIN "NOTIFICATIONRULE_TAGS"
                    ON "NOTIFICATIONRULE_TAGS"."NOTIFICATIONRULE_ID" = "NOTIFICATIONRULE"."ID"
                 INNER JOIN "TAG"
                    ON "TAG"."ID" = "NOTIFICATIONRULE_TAGS"."TAG_ID"
                 WHERE "TAG"."NAME" = :tag
                """;

        final var params = new HashMap<String, Object>();
        params.put("tag", tagName);

        if (filter != null) {
            sqlQuery += " AND \"NOTIFICATIONRULE\".\"NAME\" LIKE :nameFilter";
            params.put("nameFilter", "%" + filter + "%");
        }

        if (orderBy == null) {
            sqlQuery += " ORDER BY \"name\" ASC";
        } else if ("name".equals(orderBy)) {
            sqlQuery += " ORDER BY \"%s\" %s".formatted(orderBy,
                    orderDirection == OrderDirection.DESCENDING ? "DESC" : "ASC");
        } else {
            throw new InvalidSortFieldException(orderBy, List.of("name"));
        }

        sqlQuery += " " + getOffsetLimitSqlClause();

        final Query<?> query = pm.newQuery(Query.SQL, sqlQuery);
        query.setNamedParameters(params);
        return executeAndCloseResultList(query, TaggedNotificationRuleRow.class);
    }

    /**
     * @since 4.12.0
     */
    @Override
    public void tagNotificationRules(final String tagName, final Collection<String> notificationRuleUuids) {
        runInTransaction(() -> {
            final Tag tag = getTagByName(tagName);
            if (tag == null) {
                throw new NoSuchElementException("A tag with name %s does not exist".formatted(tagName));
            }

            final Query<NotificationRule> notificationRulesQuery = pm.newQuery(NotificationRule.class);
            notificationRulesQuery.setFilter(":uuids.contains(uuid)");
            notificationRulesQuery.setParameters(notificationRuleUuids);
            final List<NotificationRule> notificationRules = executeAndCloseList(notificationRulesQuery);

            for (final NotificationRule notificationRule : notificationRules) {
                bind(notificationRule, List.of(tag), /* keepExisting */ true);
            }
        });
    }

    /**
     * @since 4.12.0
     */
    @Override
    public void untagNotificationRules(final String tagName, final Collection<String> notificationRuleUuids) {
        runInTransaction(() -> {
            final Tag tag = getTagByName(tagName);
            if (tag == null) {
                throw new NoSuchElementException("A tag with name %s does not exist".formatted(tagName));
            }

            final Query<NotificationRule> notificationRulesQuery = pm.newQuery(NotificationRule.class);
            notificationRulesQuery.setFilter(":uuids.contains(uuid)");
            notificationRulesQuery.setParameters(notificationRuleUuids);
            final List<NotificationRule> notificationRules = executeAndCloseList(notificationRulesQuery);

            for (final NotificationRule notificationRule : notificationRules) {
                if (notificationRule.getTags() == null || notificationRule.getTags().isEmpty()) {
                    continue;
                }

                notificationRule.getTags().remove(tag);
            }
        });
    }

    public record TaggedVulnerabilityRow(UUID uuid, String vulnId, String source, long totalCount) {
    }

    @Override
    public List<TaggedVulnerabilityRow> getTaggedVulnerabilities(final String tagName) {
        // language=SQL
        var sqlQuery = """
                SELECT "VULNERABILITY"."UUID" AS "uuid"
                     , "VULNERABILITY"."VULNID" AS "vulnId"
                     , "VULNERABILITY"."SOURCE" AS "source"
                     , COUNT(*) OVER() AS "totalCount"
                  FROM "VULNERABILITY"
                 INNER JOIN "VULNERABILITIES_TAGS"
                    ON "VULNERABILITIES_TAGS"."VULNERABILITY_ID" = "VULNERABILITY"."ID"
                 INNER JOIN "TAG"
                    ON "TAG"."ID" = "VULNERABILITIES_TAGS"."TAG_ID"
                 WHERE "TAG"."NAME" = :tag
                """;

        final var params = new HashMap<String, Object>();
        params.put("tag", tagName);

        if (filter != null) {
            sqlQuery += " AND \"VULNERABILITY\".\"VULNID\" LIKE :vulnIdFilter";
            params.put("vulnIdFilter", "%" + filter + "%");
        }

        if (orderBy == null) {
            sqlQuery += " ORDER BY \"vulnId\" ASC";
        } else if ("vulnId".equals(orderBy)) {
            sqlQuery += " ORDER BY \"%s\" %s".formatted(orderBy,
                    orderDirection == OrderDirection.DESCENDING ? "DESC" : "ASC");
        } else {
            throw new InvalidSortFieldException(orderBy, List.of("vulnId"));
        }

        sqlQuery += " " + getOffsetLimitSqlClause();

        final Query<?> query = pm.newQuery(Query.SQL, sqlQuery);
        query.setNamedParameters(params);
        return executeAndCloseResultList(query, TaggedVulnerabilityRow.class);
    }

    @Override
    public void untagVulnerabilities(final String tagName, final Collection<String> vulnerabilityUuids) {
        runInTransaction(() -> {
            final Tag tag = getTagByName(tagName);
            if (tag == null) {
                throw new NoSuchElementException("A tag with name %s does not exist".formatted(tagName));
            }
            final Query<Vulnerability> vulnerabilityQuery = pm.newQuery(Vulnerability.class);
            vulnerabilityQuery.setFilter(":uuids.contains(uuid)");
            vulnerabilityQuery.setParameters(vulnerabilityUuids);
            final List<Vulnerability> vulnerabilities = executeAndCloseList(vulnerabilityQuery);

            for (final Vulnerability vulnerability : vulnerabilities) {
                if (vulnerability.getTags() == null || vulnerability.getTags().isEmpty()) {
                    continue;
                }
                vulnerability.getTags().remove(tag);
            }
        });
    }
}
