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
import alpine.persistence.OrderDirection;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class TagQueryManager extends QueryManager implements IQueryManager {

    private static final Comparator<Tag> TAG_COMPARATOR = Comparator.comparingInt(
            (Tag tag) -> tag.getProjects().size()).reversed();

    private static final Logger LOGGER = Logger.getLogger(ProjectQueryManager.class);

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
    public record TagListRow(String name, long projectCount, long policyCount, long totalCount) {

        @SuppressWarnings("unused") // DataNucleus will use this for MSSQL.
        public TagListRow(String name, int projectCount, int policyCount, int totalCount) {
            this(name, (long) projectCount, (long) policyCount, (long) totalCount);
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
                           AND %s
                       ) AS "projectCount"
                     , (SELECT COUNT(*)
                          FROM "POLICY_TAGS"
                         WHERE "POLICY_TAGS"."TAG_ID" = "TAG"."ID"
                       ) AS "policyCount"
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
        } else if ("name".equals(orderBy) || "projectCount".equals(orderBy) || "policyCount".equals(orderBy)) {
            sqlQuery += " ORDER BY \"%s\" %s, \"ID\" ASC".formatted(orderBy,
                    orderDirection == OrderDirection.DESCENDING ? "DESC" : "ASC");
        } else {
            // TODO: Throw NotSortableException once Alpine opens up its constructor.
            throw new IllegalArgumentException("Cannot sort by " + orderBy);
        }

        sqlQuery += " " + getOffsetLimitSqlClause();

        final Query<?> query = pm.newQuery(Query.SQL, sqlQuery);
        query.setNamedParameters(params);
        try {
            return new ArrayList<>(query.executeResultList(TagListRow.class));
        } finally {
            query.closeAll();
        }
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
            // TODO: Throw NotSortableException once Alpine opens up its constructor.
            throw new IllegalArgumentException("Cannot sort by " + orderBy);
        }

        sqlQuery += " " + getOffsetLimitSqlClause();

        final Query<?> query = pm.newQuery(Query.SQL, sqlQuery);
        query.setNamedParameters(params);
        try {
            return new ArrayList<>(query.executeResultList(TaggedProjectRow.class));
        } finally {
            query.closeAll();
        }
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
            // TODO: Throw NotSortableException once Alpine opens up its constructor.
            throw new IllegalArgumentException("Cannot sort by " + orderBy);
        }

        sqlQuery += " " + getOffsetLimitSqlClause();

        final Query<?> query = pm.newQuery(Query.SQL, sqlQuery);
        query.setNamedParameters(params);
        try {
            return new ArrayList<>(query.executeResultList(TaggedPolicyRow.class));
        } finally {
            query.closeAll();
        }
    }

    @Override
    public PaginatedResult getTags(String policyUuid) {

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

}
