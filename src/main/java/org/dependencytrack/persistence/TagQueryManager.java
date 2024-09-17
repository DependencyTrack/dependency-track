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
import alpine.model.ApiKey;
import alpine.model.UserPrincipal;
import alpine.persistence.NotSortableException;
import alpine.persistence.OrderDirection;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.exception.TagOperationFailedException;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class TagQueryManager extends QueryManager implements IQueryManager {

    private static final Comparator<Tag> TAG_COMPARATOR = Comparator.comparingInt(
            (Tag tag) -> tag.getProjects().size()).reversed();

    private static final Logger LOGGER = Logger.getLogger(ProjectQueryManager.class);

    /**
     * Constructs a new QueryManager.
     *
     * @param pm a PersistenceManager object
     */
    TagQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     *
     * @param pm      a PersistenceManager object
     * @param request an AlpineRequest object
     */
    TagQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns a list of Tag objects by name.
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
     * @param names the name(s) of the Tag(s) to create
     * @return the created Tag object(s)
     */
    @Override
    public List<Tag> createTags(final List<String> names) {
        final List<Tag> newTags = new ArrayList<>();
        for (final String name: names) {
            final String loweredTrimmedTag = StringUtils.lowerCase(StringUtils.trimToNull(name));
            if (getTagByName(loweredTrimmedTag) == null) {
                final Tag tag = new Tag();
                tag.setName(loweredTrimmedTag);
                newTags.add(tag);
            }
        }
        return new ArrayList<>(persist(newTags));
    }

    /**
     * Returns a list of Tag objects what have been resolved. It resolved
     * tags by querying the database to retrieve the tag. If the tag does
     * not exist, the tag will be created and returned with other resolved
     * tags.
     * @param tags a List of Tags to resolve
     * @return List of resolved Tags
     */
    @Override
    public synchronized List<Tag> resolveTags(final List<Tag> tags) {
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
     * @since 4.12.0
     */
    public record TagListRow(
            String name,
            long projectCount,
            long policyCount,
            long notificationRuleCount,
            long totalCount
    ) {

        @SuppressWarnings("unused") // DataNucleus will use this for MSSQL.
        public TagListRow(
                final String name,
                final int projectCount,
                final int policyCount,
                final int notificationRuleCount,
                final int totalCount
        ) {
            this(name, (long) projectCount, (long) policyCount, (long) notificationRuleCount, (long) totalCount);
        }

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
                           AND %s) AS "projectCount"
                     , (SELECT COUNT(*)
                          FROM "POLICY_TAGS"
                         WHERE "POLICY_TAGS"."TAG_ID" = "TAG"."ID") AS "policyCount"
                     , (SELECT COUNT(*)
                          FROM "NOTIFICATIONRULE_TAGS"
                         WHERE "NOTIFICATIONRULE_TAGS"."TAG_ID" = "TAG"."ID") AS "notificationRuleCount"
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
                || "policyCount".equals(orderBy)
                || "notificationRuleCount".equals(orderBy)) {
            sqlQuery += " ORDER BY \"%s\" %s, \"ID\" ASC".formatted(orderBy,
                    orderDirection == OrderDirection.DESCENDING ? "DESC" : "ASC");
        } else {
            throw new NotSortableException("Tag", orderBy, "Field does not exist or is not sortable");
        }

        sqlQuery += " " + getOffsetLimitSqlClause();

        final Query<?> query = pm.newQuery(Query.SQL, sqlQuery);
        query.setNamedParameters(params);
        return executeAndCloseResultList(query, TagListRow.class);
    }

    /**
     * @since 4.12.0
     */
    public record TagDeletionCandidateRow(
            String name,
            long projectCount,
            long accessibleProjectCount,
            long policyCount,
            long notificationRuleCount
    ) {

        @SuppressWarnings("unused") // DataNucleus will use this for MSSQL.
        public TagDeletionCandidateRow(
                final String name,
                final int projectCount,
                final int accessibleProjectCount,
                final int policyCount,
                final int notificationRuleCount
        ) {
            this(name, (long) projectCount, (long) accessibleProjectCount, (long) policyCount, (long) notificationRuleCount);
        }

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
                    SELECT "NAME"
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
                               AND %s) AS "accessibleProjectCount"
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
                      FROM "TAG"
                     WHERE %s
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

            boolean hasPortfolioManagementPermission = false;
            boolean hasPolicyManagementPermission = false;
            boolean hasSystemConfigurationPermission = false;
            if (principal == null) {
                hasPortfolioManagementPermission = true;
                hasPolicyManagementPermission = true;
                hasSystemConfigurationPermission = true;
            } else {
                if (principal instanceof final ApiKey apiKey) {
                    hasPortfolioManagementPermission = hasPermission(apiKey, Permissions.Constants.PORTFOLIO_MANAGEMENT);
                    hasPolicyManagementPermission = hasPermission(apiKey, Permissions.Constants.POLICY_MANAGEMENT);
                    hasSystemConfigurationPermission = hasPermission(apiKey, Permissions.Constants.SYSTEM_CONFIGURATION);
                } else if (principal instanceof final UserPrincipal user) {
                    hasPortfolioManagementPermission = hasPermission(user, Permissions.Constants.PORTFOLIO_MANAGEMENT, /* includeTeams */ true);
                    hasPolicyManagementPermission = hasPermission(user, Permissions.Constants.POLICY_MANAGEMENT, /* includeTeams */ true);
                    hasSystemConfigurationPermission = hasPermission(user, Permissions.Constants.SYSTEM_CONFIGURATION, /* includeTeams */ true);
                }
            }

            for (final TagDeletionCandidateRow row : candidateRows) {
                if (row.projectCount() > 0 && !hasPortfolioManagementPermission) {
                    errorByTagName.put(row.name(), """
                            The tag is assigned to %d project(s), but the authenticated principal \
                            is missing the %s permission.""".formatted(row.projectCount(), Permissions.PORTFOLIO_MANAGEMENT));
                    continue;
                }

                final long inaccessibleProjectAssignmentCount =
                        row.projectCount - row.accessibleProjectCount();
                if (inaccessibleProjectAssignmentCount > 0) {
                    errorByTagName.put(row.name(), """
                            The tag is assigned to %d project(s) that are not accessible \
                            by the authenticated principal.""".formatted(inaccessibleProjectAssignmentCount));
                    continue;
                }

                if (row.policyCount() > 0 && !hasPolicyManagementPermission) {
                    errorByTagName.put(row.name(), """
                            The tag is assigned to %d policies, but the authenticated principal \
                            is missing the %s permission.""".formatted(row.policyCount(), Permissions.POLICY_MANAGEMENT));
                }

                if (row.notificationRuleCount() > 0 && !hasSystemConfigurationPermission) {
                    errorByTagName.put(row.name(), """
                            The tag is assigned to %d notification rules, but the authenticated principal \
                            is missing the %s permission.""".formatted(row.notificationRuleCount(), Permissions.SYSTEM_CONFIGURATION));
                }
            }

            if (!errorByTagName.isEmpty()) {
                throw TagOperationFailedException.forDeletion(errorByTagName);
            }

            final Query<Tag> deletionQuery = pm.newQuery(Tag.class);
            deletionQuery.setFilter(":names.contains(name)");
            try {
                deletionQuery.deletePersistentAll(candidateRows.stream().map(TagDeletionCandidateRow::name).toList());
            } finally {
                deletionQuery.closeAll();
            }
        });
    }

    /**
     * @since 4.12.0
     */
    public record TaggedProjectRow(String uuid, String name, String version, long totalCount) {

        @SuppressWarnings("unused") // DataNucleus will use this for MSSQL.
        public TaggedProjectRow(String uuid, String name, String version, int totalCount) {
            this(uuid, name, version, (long) totalCount);
        }

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
            throw new NotSortableException("TaggedProject", orderBy, "Field does not exist or is not sortable");
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
            preprocessACLs(projectsQuery, ":uuids.contains(uuid)", params, /* bypass */ false);
            projectsQuery.setNamedParameters(params);
            final List<Project> projects = executeAndCloseList(projectsQuery);

            for (final Project project : projects) {
                if (project.getTags() == null || project.getTags().isEmpty()) {
                    project.setTags(List.of(tag));
                    continue;
                }

                if (!project.getTags().contains(tag)) {
                    project.getTags().add(tag);
                }
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
            preprocessACLs(projectsQuery, ":uuids.contains(uuid)", params, /* bypass */ false);
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
     * @since 4.12.0
     */
    public record TaggedPolicyRow(String uuid, String name, long totalCount) {

        @SuppressWarnings("unused") // DataNucleus will use this for MSSQL.
        public TaggedPolicyRow(String uuid, String name, int totalCount) {
            this(uuid, name, (long) totalCount);
        }

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
            throw new NotSortableException("TaggedPolicy", orderBy, "Field does not exist or is not sortable");
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
                bind(policy, List.of(tag));
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

        LOGGER.debug("Retrieving tags under policy " + policyUuid);

        Policy policy = getObjectByUuid(Policy.class, policyUuid);
        List<Project> projects = policy.getProjects();

        final Stream<Tag> tags;
        if (projects != null && !projects.isEmpty()) {
            tags = projects.stream()
                    .map(Project::getTags)
                    .flatMap(List::stream)
                    .distinct();
        } else {
            tags = pm.newQuery(Tag.class).executeList().stream();
        }

        List<Tag> tagsToShow = tags.sorted(TAG_COMPARATOR).toList();

        return (new PaginatedResult()).objects(tagsToShow).total(tagsToShow.size());
    }

    /**
     * @since 4.12.0
     */
    public record TaggedNotificationRuleRow(String uuid, String name, long totalCount) {

        @SuppressWarnings("unused") // DataNucleus will use this for MSSQL.
        public TaggedNotificationRuleRow(final String uuid, final String name, final int totalCount) {
            this(uuid, name, (long) totalCount);
        }

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
            throw new NotSortableException("TaggedNotificationRule", orderBy, "Field does not exist or is not sortable");
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
                bind(notificationRule, List.of(tag));
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

}
