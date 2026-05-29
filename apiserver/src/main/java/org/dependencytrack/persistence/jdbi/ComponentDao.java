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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.Page.TotalCount;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.dependencytrack.common.pagination.SortDirection;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentOccurrence;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.jdbi.query.ListComponentsQuery;
import org.dependencytrack.persistence.jdbi.query.ListProjectComponentsQuery;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.mapper.reflect.BeanMapper;
import org.jdbi.v3.core.statement.StatementContext;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterBeanMapper;
import org.jdbi.v3.sqlobject.config.RegisterRowMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.BindMap;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.customizer.DefineNamedBindings;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.hasColumn;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;
import static org.dependencytrack.util.PersistenceUtil.escapeLikePattern;

public interface ComponentDao extends SqlObject, PaginationSupport {

    @SqlUpdate("""
            DELETE
              FROM "COMPONENT"
             WHERE "UUID" = :componentUuid
            """)
    int deleteComponent(@Bind final UUID componentUuid);

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            SELECT ${apiProjectAclCondition}
              FROM "COMPONENT"
             WHERE "UUID" = :componentUuid
            """)
    @DefineApiProjectAclCondition(projectIdColumn = "\"PROJECT_ID\"")
    Boolean isAccessible(@Bind UUID componentUuid);

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiFilterParameter" type="String" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            SELECT "COMPONENT_OCCURRENCE"."ID"
                 , "LOCATION"
                 , "LINE"
                 , "OFFSET"
                 , "SYMBOL"
                 , "CREATED_AT"
                 , COUNT(*) OVER() AS "TOTAL_COUNT"
              FROM "COMPONENT"
             INNER JOIN "COMPONENT_OCCURRENCE"
                ON "COMPONENT_OCCURRENCE"."COMPONENT_ID" = "COMPONENT"."ID"
             WHERE "COMPONENT"."UUID" = :componentUuid
            <#if apiFilterParameter??>
               AND LOWER("LOCATION") LIKE ('%' || LOWER(${apiFilterParameter}) || '%')
            </#if>
            ORDER BY "LOCATION", "COMPONENT_OCCURRENCE"."ID"
            ${apiOffsetLimitClause!}
            """)
    @RegisterBeanMapper(ComponentOccurrence.class)
    List<ComponentOccurrence> getOccurrences(@Bind UUID componentUuid);

    @SqlQuery("""
            SELECT "ID" FROM "COMPONENT" WHERE "UUID" = :componentUuid
            """)
    Long getComponentId(@Bind UUID componentUuid);

    default Page<Component> listProjectComponents(ListProjectComponentsQuery query) {
        final PageTokenEncoder pageTokenEncoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decodedPageToken = pageTokenEncoder.decode(
                query.pageToken(), ListProjectComponentsQuery.PageToken.class);

        final var whereConditions = new ArrayList<>(List.of("\"C\".\"PROJECT_ID\" = :projectId"));
        final var queryParams = new HashMap<String, Object>(Map.of("projectId", query.projectId()));

        if (Boolean.TRUE.equals(query.onlyOutdated())) {
            whereConditions.add(/* language=SQL */ """
                    EXISTS (
                     SELECT 1
                       FROM "PACKAGE_ARTIFACT_METADATA" "PAM"
                       JOIN "PACKAGE_METADATA" "PM" ON "PM"."PURL" = "PAM"."PACKAGE_PURL"
                      WHERE "PAM"."PURL" = "C"."PURL"
                        AND "PM"."LATEST_VERSION" != "C"."VERSION"
                    )""");
        }
        if (Boolean.TRUE.equals(query.onlyDirect())) {
            whereConditions.add(/* language=SQL */ """
                    AND "C"."DIRECT" IS TRUE
                    """);
        }
        if (query.searchText() != null && !query.searchText().isBlank()) {
            whereConditions.add(/* language=SQL */ """
                    (LOWER("C"."NAME") LIKE ('%' || LOWER(:searchText) || '%') ESCAPE '!' \
                    OR LOWER("C"."GROUP") LIKE ('%' || LOWER(:searchText) || '%') ESCAPE '!')""");
            queryParams.put("searchText", escapeLikePattern(query.searchText()));
        }

        final TotalCount totalCount;
        final ListProjectComponentsQuery.SortBy effectiveSortBy;
        final SortDirection effectiveSortDirection;

        if (decodedPageToken != null) {
            totalCount = decodedPageToken.totalCount();
            effectiveSortBy = decodedPageToken.sortBy() != null
                    ? decodedPageToken.sortBy()
                    : ListProjectComponentsQuery.SortBy.NAME;
            effectiveSortDirection = decodedPageToken.sortDirection();
            queryParams.put("lastSortValue", switch (effectiveSortBy) {
                case NAME -> decodedPageToken.lastName();
                case GROUP -> decodedPageToken.lastGroup();
                case LAST_RISKSCORE -> decodedPageToken.lastRiskScore();
                case PUBLISHED_AT -> decodedPageToken.lastPublishedAtMicros() != null
                        ? Instant.EPOCH.plus(decodedPageToken.lastPublishedAtMicros(), ChronoUnit.MICROS)
                        : null;
            });
        } else {
            totalCount = getBoundedTotalCountWithProjectAcl(
                    "FROM \"COMPONENT\" \"C\" WHERE " + String.join(" AND ", whereConditions),
                    queryParams,
                    null,
                    "\"C\".\"PROJECT_ID\"");
            effectiveSortBy = query.sortBy() != null
                    ? query.sortBy()
                    : ListProjectComponentsQuery.SortBy.NAME;
            effectiveSortDirection = query.sortDirection() != null
                    ? query.sortDirection()
                    : SortDirection.ASC;
        }

        final List<ListedComponent> rows = listProjectComponents(
                whereConditions,
                queryParams,
                query.limit() + 1,
                query.includeOccurrenceCount(),
                decodedPageToken != null
                        ? decodedPageToken.lastId()
                        : null,
                effectiveSortBy,
                effectiveSortDirection,
                decodedPageToken != null);

        final List<ListedComponent> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), query.limit()))
                : rows;

        final ListProjectComponentsQuery.PageToken nextPageToken;
        if (rows.size() > query.limit()) {
            final ListedComponent lastRow = resultRows.getLast();
            final Component lastComponent = lastRow.component();

            nextPageToken = new ListProjectComponentsQuery.PageToken(
                    lastComponent.getId(),
                    effectiveSortBy == ListProjectComponentsQuery.SortBy.NAME
                            ? lastComponent.getName()
                            : null,
                    effectiveSortBy == ListProjectComponentsQuery.SortBy.GROUP
                            ? lastComponent.getGroup()
                            : null,
                    effectiveSortBy == ListProjectComponentsQuery.SortBy.LAST_RISKSCORE
                            ? lastComponent.getLastInheritedRiskScore()
                            : null,
                    effectiveSortBy == ListProjectComponentsQuery.SortBy.PUBLISHED_AT
                            ? lastRow.publishedAtMicros()
                            : null,
                    effectiveSortBy,
                    effectiveSortDirection,
                    totalCount);
        } else {
            nextPageToken = null;
        }

        final List<Component> components = resultRows.stream()
                .map(ListedComponent::component)
                .toList();
        return new Page<>(components, pageTokenEncoder.encode(nextPageToken), totalCount);
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="includeOccurrenceCount" type="boolean" -->
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            <#-- @ftlvariable name="sortByColumn" type="org.dependencytrack.persistence.jdbi.query.ListProjectComponentsQuery.SortBy" -->
            <#-- @ftlvariable name="sortDirection" type="String" -->
            <#-- @ftlvariable name="hasCursor" type="boolean" -->
            <#-- @ftlvariable name="whereConditions" type="java.util.Collection<String>" -->
            SELECT "C"."ID"
                 , "C"."NAME"
                 , "C"."BLAKE2B_256"
                 , "C"."BLAKE2B_384"
                 , "C"."BLAKE2B_512"
                 , "C"."BLAKE3"
                 , "C"."CLASSIFIER"
                 , "C"."COPYRIGHT"
                 , "C"."CPE"
                 , "C"."PURL"
                 , "C"."GROUP"
                 , "C"."INTERNAL"
                 , "C"."DIRECT"
                 , "C"."LAST_RISKSCORE"
                 , "C"."LICENSE" AS "componentLicenseName"
                 , "C"."LICENSE_EXPRESSION" AS "licenseExpression"
                 , "C"."LICENSE_URL" AS "licenseUrl"
                 , "C"."TEXT"
                 , "C"."SCOPE"
                 , "C"."MD5"
                 , "C"."SHA1"
                 , "C"."SHA_256" AS "sha256"
                 , "C"."SHA_384" AS "sha384"
                 , "C"."SHA_512" AS "sha512"
                 , "C"."SHA3_256"
                 , "C"."SHA3_384"
                 , "C"."SHA3_512"
                 , "C"."SWIDTAGID"
                 , "C"."UUID"
                 , "C"."VERSION"
                 , "L"."ISCUSTOMLICENSE"
                 , "L"."FSFLIBRE" AS "isFsfLibre"
                 , "L"."LICENSEID"
                 , "L"."ISOSIAPPROVED"
                 , "L"."UUID" AS "licenseUuid"
                 , "L"."NAME" AS "licenseName"
            <#if includeOccurrenceCount>
                 , (SELECT COUNT(*) FROM "COMPONENT_OCCURRENCE" WHERE "COMPONENT_ID" = "C"."ID") AS "occurrenceCount"
            </#if>
            <#if sortByColumn?has_content && sortByColumn == "PUBLISHED_AT">
                 , (EXTRACT(EPOCH FROM "PAM"."PUBLISHED_AT") * 1000000)::bigint AS "artifactPublishedAtMicros"
            </#if>
              FROM "COMPONENT" "C"
              LEFT JOIN "LICENSE" "L"
                ON "C"."LICENSE_ID" = "L"."ID"
            <#if sortByColumn?has_content && sortByColumn == "PUBLISHED_AT">
              LEFT JOIN "PACKAGE_ARTIFACT_METADATA" "PAM"
                ON "PAM"."PURL" = "C"."PURL"
            </#if>
             WHERE ${apiProjectAclCondition}
               AND ${whereConditions?join(" AND ")}
            <#assign castedLastSortValue>
                <#-- Ensure Postgres can determine the type of lastSortValue even when it's null. -->
                <#if sortByColumn?has_content && sortByColumn == "PUBLISHED_AT">CAST(:lastSortValue AS TIMESTAMPTZ)
                <#elseif sortByColumn?has_content && sortByColumn == "LAST_RISKSCORE">CAST(:lastSortValue AS DOUBLE PRECISION)
                <#else>CAST(:lastSortValue AS TEXT)
                </#if>
            </#assign>
            <#if hasCursor && sortByColumn?has_content && sortByColumn == "PUBLISHED_AT">
               <#-- NB: Handle sort with NULLS LAST in *both* directions. -->
               <#if sortDirection == "DESC">
                   AND ((${castedLastSortValue} IS NULL AND "PAM"."PUBLISHED_AT" IS NULL AND "C"."ID" > :lastId)
                        OR (${castedLastSortValue} IS NOT NULL AND "PAM"."PUBLISHED_AT" IS NOT NULL
                            AND ("PAM"."PUBLISHED_AT" < ${castedLastSortValue}
                                 OR ("PAM"."PUBLISHED_AT" = ${castedLastSortValue} AND "C"."ID" > :lastId)))
                        OR (${castedLastSortValue} IS NOT NULL AND "PAM"."PUBLISHED_AT" IS NULL))
               <#else>
                   AND ((${castedLastSortValue} IS NULL AND "PAM"."PUBLISHED_AT" IS NULL AND "C"."ID" > :lastId)
                        OR (${castedLastSortValue} IS NOT NULL AND "PAM"."PUBLISHED_AT" IS NOT NULL
                            AND ("PAM"."PUBLISHED_AT" > ${castedLastSortValue}
                                 OR ("PAM"."PUBLISHED_AT" = ${castedLastSortValue} AND "C"."ID" > :lastId)))
                        OR (${castedLastSortValue} IS NOT NULL AND "PAM"."PUBLISHED_AT" IS NULL))
               </#if>
            <#elseif hasCursor && sortByColumn?has_content>
               <#if sortDirection == "DESC">
                   AND ((${castedLastSortValue} IS NULL AND "C"."${sortByColumn}" IS NULL AND "C"."ID" > :lastId)
                        OR (${castedLastSortValue} IS NULL AND "C"."${sortByColumn}" IS NOT NULL)
                        OR (${castedLastSortValue} IS NOT NULL AND "C"."${sortByColumn}" IS NOT NULL
                            AND ("C"."${sortByColumn}" < ${castedLastSortValue}
                                 OR ("C"."${sortByColumn}" = ${castedLastSortValue} AND "C"."ID" > :lastId))))
               <#else>
                   AND ((${castedLastSortValue} IS NULL AND "C"."${sortByColumn}" IS NULL AND "C"."ID" > :lastId)
                        OR (${castedLastSortValue} IS NOT NULL AND "C"."${sortByColumn}" IS NOT NULL
                            AND ("C"."${sortByColumn}" > ${castedLastSortValue}
                                 OR ("C"."${sortByColumn}" = ${castedLastSortValue} AND "C"."ID" > :lastId)))
                        OR (${castedLastSortValue} IS NOT NULL AND "C"."${sortByColumn}" IS NULL))
               </#if>
            <#elseif hasCursor>
               AND "C"."ID" > :lastId
            </#if>
            <#if sortByColumn?has_content && sortByColumn == "PUBLISHED_AT">
             ORDER BY "PAM"."PUBLISHED_AT" ${sortDirection} NULLS LAST, "C"."ID" ASC
            <#elseif sortByColumn?has_content>
             ORDER BY "C"."${sortByColumn}" ${sortDirection}, "C"."ID" ASC
            <#else>
             ORDER BY "C"."ID" ASC
            </#if>
             LIMIT :limit
            """)
    @DefineNamedBindings
    @DefineApiProjectAclCondition(projectIdColumn = "\"PROJECT_ID\"")
    @RegisterRowMapper(ComponentListRowMapper.class)
    List<ListedComponent> listProjectComponents(
            @Define ArrayList<String> whereConditions,
            @BindMap Map<String, Object> queryParams,
            @Bind int limit,
            @Define boolean includeOccurrenceCount,
            @Bind Long lastId,
            @Define ListProjectComponentsQuery.SortBy sortByColumn,
            @Define SortDirection sortDirection,
            @Define boolean hasCursor);

    default Page<Component> listComponents(ListComponentsQuery query) {
        final PageTokenEncoder pageTokenEncoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decodedPageToken = pageTokenEncoder.decode(
                query.pageToken(), ListComponentsQuery.PageToken.class);

        final var whereConditions = new ArrayList<String>();
        final var queryParams = new HashMap<String, Object>();
        whereConditions.add("TRUE");
        if (query.projectId() != null) {
            whereConditions.add("\"C\".\"PROJECT_ID\" = :projectId");
            queryParams.put("projectId", query.projectId());
        }
        if (query.groupContains() != null) {
            whereConditions.add("LOWER(\"C\".\"GROUP\") LIKE ('%' || LOWER(:componentGroup) || '%') ESCAPE '!'");
            queryParams.put("componentGroup", escapeLikePattern(query.groupContains()));
        }
        if (query.nameContains() != null) {
            whereConditions.add("LOWER(\"C\".\"NAME\") LIKE ('%' || LOWER(:componentName) || '%') ESCAPE '!'");
            queryParams.put("componentName", escapeLikePattern(query.nameContains()));
        }
        if (query.versionContains() != null) {
            whereConditions.add("LOWER(\"C\".\"VERSION\") LIKE ('%' || LOWER(:componentVersion) || '%') ESCAPE '!'");
            queryParams.put("componentVersion", escapeLikePattern(query.versionContains()));
        }
        if (query.purlStartsWith() != null) {
            whereConditions.add("LOWER(\"C\".\"PURL\") LIKE LOWER(:componentPurl) || '%' ESCAPE '!'");
            queryParams.put("componentPurl", escapeLikePattern(query.purlStartsWith()));
        }
        if (query.cpe() != null) {
            whereConditions.add("LOWER(\"C\".\"CPE\") = LOWER(:componentCpe)");
            queryParams.put("componentCpe", query.cpe());
        }
        if (query.swidTagIdContains() != null) {
            whereConditions.add("LOWER(\"C\".\"SWIDTAGID\") LIKE ('%' || LOWER(:componentSwidTagId) || '%') ESCAPE '!'");
            queryParams.put("componentSwidTagId", escapeLikePattern(query.swidTagIdContains()));
        }
        if (query.packageArtifactPublishedSince() != null || query.packageArtifactPublishedBefore() != null) {
            final var pamConditions = new ArrayList<String>(3);
            pamConditions.add("pam.\"PURL\" = \"C\".\"PURL\"");
            if (query.packageArtifactPublishedSince() != null) {
                pamConditions.add("pam.\"PUBLISHED_AT\" >= :packageArtifactPublishedSince");
                queryParams.put("packageArtifactPublishedSince", query.packageArtifactPublishedSince());
            }
            if (query.packageArtifactPublishedBefore() != null) {
                pamConditions.add("pam.\"PUBLISHED_AT\" < :packageArtifactPublishedBefore");
                queryParams.put("packageArtifactPublishedBefore", query.packageArtifactPublishedBefore());
            }
            whereConditions.add(
                    "EXISTS (SELECT 1 FROM \"PACKAGE_ARTIFACT_METADATA\" AS pam WHERE %s)".formatted(
                            String.join(" AND ", pamConditions)));
        }
        if (query.projectActive() != null) {
            whereConditions.add(query.projectActive()
                    ? "\"PROJECT\".\"INACTIVE_SINCE\" IS NULL"
                    : "\"PROJECT\".\"INACTIVE_SINCE\" IS NOT NULL");
        }
        if (query.projectIsLatest() != null) {
            whereConditions.add(query.projectIsLatest()
                    ? "\"PROJECT\".\"IS_LATEST\""
                    : "NOT \"PROJECT\".\"IS_LATEST\"");
        }
        if (query.hashType() != null && query.hashValue() != null) {
            final String hashColumn = switch (query.hashType()) {
                case MD5 -> "\"C\".\"MD5\"";
                case SHA1 -> "\"C\".\"SHA1\"";
                case SHA_256 -> "\"C\".\"SHA_256\"";
                case SHA_384 -> "\"C\".\"SHA_384\"";
                case SHA_512 -> "\"C\".\"SHA_512\"";
                case SHA3_256 -> "\"C\".\"SHA3_256\"";
                case SHA3_384 -> "\"C\".\"SHA3_384\"";
                case SHA3_512 -> "\"C\".\"SHA3_512\"";
                case BLAKE2B_256 -> "\"C\".\"BLAKE2B_256\"";
                case BLAKE2B_384 -> "\"C\".\"BLAKE2B_384\"";
                case BLAKE2B_512 -> "\"C\".\"BLAKE2B_512\"";
                case BLAKE3 -> "\"C\".\"BLAKE3\"";
            };
            whereConditions.add("%s = :componentHash".formatted(hashColumn));
            queryParams.put("componentHash", query.hashValue());
        }

        final TotalCount totalCount;
        final ListComponentsQuery.SortBy effectiveSortBy;
        final SortDirection effectiveSortDirection;

        if (decodedPageToken != null) {
            totalCount = decodedPageToken.totalCount();
            effectiveSortBy = decodedPageToken.sortBy() != null
                    ? decodedPageToken.sortBy()
                    : ListComponentsQuery.SortBy.NAME;
            effectiveSortDirection = decodedPageToken.sortDirection();
            queryParams.put("lastSortValue", switch (effectiveSortBy) {
                case NAME -> decodedPageToken.lastName();
                case GROUP -> decodedPageToken.lastGroup();
                case LAST_RISKSCORE -> decodedPageToken.lastRiskScore();
            });
        } else {
            final String projectJoin = (query.projectActive() != null || query.projectIsLatest() != null)
                    ? "INNER JOIN \"PROJECT\" ON \"C\".\"PROJECT_ID\" = \"PROJECT\".\"ID\""
                    : "";
            totalCount = getBoundedTotalCountWithProjectAcl("""
                            FROM "COMPONENT" "C"
                            %s
                            WHERE %s
                            """.formatted(projectJoin, String.join(" AND ", whereConditions)),
                    queryParams,
                    10000,
                    "\"C\".\"PROJECT_ID\"");
            effectiveSortBy = query.sortBy() != null
                    ? query.sortBy()
                    : ListComponentsQuery.SortBy.NAME;
            effectiveSortDirection = query.sortDirection() != null
                    ? query.sortDirection()
                    : SortDirection.ASC;
        }

        final List<ListedComponent> rows = listComponents(
                whereConditions,
                queryParams,
                query.limit() + 1,
                decodedPageToken != null
                        ? decodedPageToken.lastId()
                        : null,
                effectiveSortBy,
                effectiveSortDirection,
                decodedPageToken != null);

        final List<ListedComponent> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), query.limit()))
                : rows;

        final ListComponentsQuery.PageToken nextPageToken;
        if (rows.size() > query.limit()) {
            final ListedComponent lastRow = resultRows.getLast();
            final Component lastComponent = lastRow.component();

            nextPageToken = new ListComponentsQuery.PageToken(
                    lastComponent.getId(),
                    effectiveSortBy == ListComponentsQuery.SortBy.NAME
                            ? lastComponent.getName()
                            : null,
                    effectiveSortBy == ListComponentsQuery.SortBy.GROUP
                            ? lastComponent.getGroup()
                            : null,
                    effectiveSortBy == ListComponentsQuery.SortBy.LAST_RISKSCORE
                            ? lastComponent.getLastInheritedRiskScore()
                            : null,
                    effectiveSortBy,
                    effectiveSortDirection,
                    totalCount);
        } else {
            nextPageToken = null;
        }

        final List<Component> components = resultRows.stream()
                .map(ListedComponent::component)
                .toList();
        return new Page<>(components, pageTokenEncoder.encode(nextPageToken), totalCount);
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            <#-- @ftlvariable name="sortByColumn" type="org.dependencytrack.persistence.jdbi.query.ListComponentsQuery.SortBy" -->
            <#-- @ftlvariable name="sortDirection" type="org.dependencytrack.common.pagination.SortDirection" -->
            <#-- @ftlvariable name="hasCursor" type="boolean" -->
            <#-- @ftlvariable name="whereConditions" type="java.util.Collection<String>" -->
            SELECT "C"."ID",
                        "C"."NAME",
                        "C"."BLAKE2B_256",
                        "C"."BLAKE2B_384",
                        "C"."BLAKE2B_512",
                        "C"."BLAKE3",
                        "C"."CLASSIFIER",
                        "C"."COPYRIGHT",
                        "C"."CPE",
                        "C"."PURL",
                        "C"."GROUP",
                        "C"."INTERNAL",
                        "C"."LAST_RISKSCORE",
                        "C"."LICENSE" AS "componentLicenseName",
                        "C"."LICENSE_EXPRESSION" AS "licenseExpression",
                        "C"."LICENSE_URL" AS "licenseUrl",
                        "C"."TEXT",
                        "C"."SCOPE",
                        "C"."MD5",
                        "C"."SHA1",
                        "C"."SHA_256" AS "sha256",
                        "C"."SHA_384" AS "sha384",
                        "C"."SHA_512" AS "sha512",
                        "C"."SHA3_256",
                        "C"."SHA3_384",
                        "C"."SHA3_512",
                        "C"."SWIDTAGID",
                        "C"."UUID",
                        "C"."VERSION",
                        "L"."LICENSEID",
                        "L"."UUID" AS "licenseUuid",
                        "L"."NAME" AS "licenseName",
                        "PROJECT"."NAME" AS "projectName",
                        "PROJECT"."UUID" AS "projectUuid",
                        "PROJECT"."VERSION" AS "projectVersion"
                FROM "COMPONENT" "C"
                INNER JOIN "PROJECT" ON "C"."PROJECT_ID" = "PROJECT"."ID"
                LEFT OUTER JOIN "LICENSE" "L" ON "C"."LICENSE_ID" = "L"."ID"
                WHERE ${apiProjectAclCondition}
                AND ${whereConditions?join(" AND ")}
                <#assign castedLastSortValue>
                    <#-- Ensure Postgres can determine the type of lastSortValue even when it's null. -->
                    <#if sortByColumn?has_content && sortByColumn == "LAST_RISKSCORE">CAST(:lastSortValue AS DOUBLE PRECISION)
                    <#else>CAST(:lastSortValue AS TEXT)
                    </#if>
                </#assign>
                <#if hasCursor && sortByColumn?has_content>
                    <#if sortDirection == "DESC">
                        AND ((${castedLastSortValue} IS NULL AND "C"."${sortByColumn}" IS NULL AND "C"."ID" > :lastId)
                             OR (${castedLastSortValue} IS NULL AND "C"."${sortByColumn}" IS NOT NULL)
                             OR (${castedLastSortValue} IS NOT NULL AND "C"."${sortByColumn}" IS NOT NULL
                                 AND ("C"."${sortByColumn}" < ${castedLastSortValue}
                                      OR ("C"."${sortByColumn}" = ${castedLastSortValue} AND "C"."ID" > :lastId))))
                    <#else>
                        AND ((${castedLastSortValue} IS NULL AND "C"."${sortByColumn}" IS NULL AND "C"."ID" > :lastId)
                             OR (${castedLastSortValue} IS NOT NULL AND "C"."${sortByColumn}" IS NOT NULL
                                 AND ("C"."${sortByColumn}" > ${castedLastSortValue}
                                      OR ("C"."${sortByColumn}" = ${castedLastSortValue} AND "C"."ID" > :lastId)))
                             OR (${castedLastSortValue} IS NOT NULL AND "C"."${sortByColumn}" IS NULL))
                    </#if>
                <#elseif hasCursor>
                    AND ("C"."NAME" > ${castedLastSortValue}
                            OR ("C"."NAME" = ${castedLastSortValue} AND "C"."ID" > :lastId))
                </#if>
                <#if sortByColumn?has_content>
                    ORDER BY "C"."${sortByColumn}" ${sortDirection!"ASC"}, "C"."ID" ASC
                <#else>
                    <#-- Default sorting to ensure consistent pagination -->
                    ORDER BY "C"."NAME" ASC, "C"."ID" ASC
                </#if>
                LIMIT :limit
            """)
    @DefineNamedBindings
    @RegisterRowMapper(ComponentListRowMapper.class)
    @DefineApiProjectAclCondition(projectIdColumn = "\"C\".\"PROJECT_ID\"")
    List<ListedComponent> listComponents(
            @Define ArrayList<String> whereConditions,
            @BindMap Map<String, Object> queryParams,
            @Bind int limit,
            @Bind Long lastId,
            @Define ListComponentsQuery.SortBy sortByColumn,
            @Define SortDirection sortDirection,
            @Define boolean hasCursor
    );

    record ListedComponent(Component component, Long publishedAtMicros) {
    }

    class ComponentListRowMapper implements RowMapper<ListedComponent> {

        private final RowMapper<Component> componentRowMapper = BeanMapper.of(Component.class);

        @Override
        public ListedComponent map(final ResultSet rs, final StatementContext ctx) throws SQLException {
            final Component component = componentRowMapper.map(rs, ctx);
            if (hasColumn(rs, "projectUuid") && rs.getString("projectUuid") != null) {
                final var project = new Project();
                project.setUuid(UUID.fromString(rs.getString("projectUuid")));
                maybeSet(rs, "projectName", ResultSet::getString, project::setName);
                maybeSet(rs, "projectVersion", ResultSet::getString, project::setVersion);
                component.setProject(project);
            }
            maybeSet(rs, "PURL", ResultSet::getString, component::setPurl);
            if (rs.getString("LAST_RISKSCORE") != null) {
                maybeSet(rs, "LAST_RISKSCORE", ResultSet::getDouble, component::setLastInheritedRiskScore);
            }
            if (hasColumn(rs, "licenseUuid") && rs.getString("licenseUuid") != null) {
                final var license = new License();
                license.setUuid(UUID.fromString(rs.getString("licenseUuid")));
                maybeSet(rs, "licenseId", ResultSet::getString, license::setLicenseId);
                maybeSet(rs, "licenseName", ResultSet::getString, license::setName);
                maybeSet(rs, "isCustomLicense", ResultSet::getBoolean, license::setCustomLicense);
                maybeSet(rs, "isFsfLibre", ResultSet::getBoolean, license::setFsfLibre);
                maybeSet(rs, "isOsiApproved", ResultSet::getBoolean, license::setOsiApproved);
                component.setResolvedLicense(license);
            }
            if (hasColumn(rs, "occurrenceCount")) {
                maybeSet(rs, "occurrenceCount", ResultSet::getLong, component::setOccurrenceCount);
            }
            Long publishedAtMicros = null;
            if (hasColumn(rs, "artifactPublishedAtMicros")) {
                final long value = rs.getLong("artifactPublishedAtMicros");
                if (!rs.wasNull()) {
                    publishedAtMicros = value;
                }
            }
            return new ListedComponent(component, publishedAtMicros);
        }
    }

    @SqlUpdate("""
            UPDATE "COMPONENT"
             SET "DIRECT" = ("UUID"::TEXT IN (
                SELECT JSONB_ARRAY_ELEMENTS(
                     COALESCE("DIRECT_DEPENDENCIES", '[]'::jsonb)) ->> 'uuid'
                FROM "PROJECT" WHERE "ID" = :projectId
             ))
            WHERE "PROJECT_ID" = :projectId
            """)
    void setDirect(@Bind Long projectId);
}
