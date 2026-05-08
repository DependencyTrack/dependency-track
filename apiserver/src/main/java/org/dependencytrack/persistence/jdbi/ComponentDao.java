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
import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.dependencytrack.common.pagination.SortDirection;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentOccurrence;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.hasColumn;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

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

    default Page<Component> listProjectComponents(
            final long projectId,
            final Boolean onlyOutdated,
            final Boolean onlyDirect,
            final int limit,
            final String pageToken) {
        final PageTokenEncoder pageTokenEncoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decodedPageToken = pageTokenEncoder.decode(pageToken, ListComponentPageToken.class);

        final TotalCount totalCount;
        if (decodedPageToken != null) {
            totalCount = decodedPageToken.totalCount();
        } else {
            final var countWhere = new StringBuilder("\"C\".\"PROJECT_ID\" = :projectId");
            final var countParams = new HashMap<String, Object>();
            countParams.put("projectId", projectId);
            if (Boolean.TRUE.equals(onlyOutdated)) {
                countWhere.append("""
                        AND EXISTS (
                         SELECT 1
                           FROM "PACKAGE_ARTIFACT_METADATA" "PAM"
                           JOIN "PACKAGE_METADATA" "PM" ON "PM"."PURL" = "PAM"."PACKAGE_PURL"
                          WHERE "PAM"."PURL" = "C"."PURL"
                            AND "PM"."LATEST_VERSION" != "C"."VERSION"
                        )""");
            }
            if (Boolean.TRUE.equals(onlyDirect)) {
                countWhere.append("""
                        AND EXISTS (
                         SELECT 1
                           FROM "PROJECT"
                          WHERE "PROJECT"."ID" = "C"."PROJECT_ID"
                            AND "PROJECT"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', "C"."UUID"))
                        )""");
            }
            totalCount = getBoundedTotalCountWithProjectAcl(
                    "FROM \"COMPONENT\" \"C\" WHERE " + countWhere,
                    countParams,
                    10000,
                    "\"C\".\"PROJECT_ID\"");
        }

        final List<Component> rows = listProjectComponents(projectId, limit + 1, onlyOutdated, onlyDirect,
                decodedPageToken != null ? decodedPageToken.lastName() : null,
                decodedPageToken != null ? decodedPageToken.lastVersion() : null,
                decodedPageToken != null ? decodedPageToken.lastId() : null);

        final List<Component> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), limit))
                : rows;

        final ListComponentPageToken nextPageToken = rows.size() > limit
                ? new ListComponentPageToken(resultRows.getLast().getName(), resultRows.getLast().getVersion(), resultRows.getLast().getId(), totalCount)
                : null;

        return new Page<>(resultRows, pageTokenEncoder.encode(nextPageToken), totalCount);
    }

    record ListComponentPageToken(
            String lastName,
            String lastVersion,
            Long lastId,
            TotalCount totalCount) implements PageToken {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="onlyOutdated" type="Boolean" -->
            <#-- @ftlvariable name="onlyDirect" type="Boolean" -->
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
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
                        "L"."ISCUSTOMLICENSE",
                        "L"."FSFLIBRE" AS "isFsfLibre",
                        "L"."LICENSEID",
                        "L"."ISOSIAPPROVED",
                        "L"."UUID" AS "licenseUuid",
                        "L"."NAME" AS "licenseName",
                        (SELECT COUNT(*) FROM "COMPONENT_OCCURRENCE" WHERE "COMPONENT_ID" = "C"."ID") AS "occurrenceCount"
                FROM "COMPONENT" "C"
                INNER JOIN "PROJECT" ON "C"."PROJECT_ID" = "PROJECT"."ID"
                LEFT OUTER JOIN "LICENSE" "L" ON "C"."LICENSE_ID" = "L"."ID"
                WHERE ${apiProjectAclCondition}
                AND "C"."PROJECT_ID" = :projectId
                <#if lastName && lastVersion && lastId>
                    AND ("C"."NAME" > :lastName
                            OR ("C"."NAME" = :lastName AND "C"."VERSION" < :lastVersion)
                            OR ("C"."NAME" = :lastName AND "C"."VERSION" = :lastVersion AND "C"."ID" > :lastId))
                </#if>
                <#if onlyOutdated && onlyOutdated == true>
                    AND EXISTS (
                        SELECT 1
                          FROM "PACKAGE_ARTIFACT_METADATA" "PAM"
                          JOIN "PACKAGE_METADATA" "PM" ON "PM"."PURL" = "PAM"."PACKAGE_PURL"
                         WHERE "PAM"."PURL" = "C"."PURL"
                           AND "PM"."LATEST_VERSION" <> "C"."VERSION")
                </#if>
                <#if onlyDirect && onlyDirect == true>
                    AND "PROJECT"."DIRECT_DEPENDENCIES" @> JSONB_BUILD_ARRAY(JSONB_BUILD_OBJECT('uuid', "C"."UUID"))
                </#if>
                ORDER BY "NAME" ASC, "VERSION" DESC, "ID" ASC
                LIMIT :limit
            """)
    @DefineNamedBindings
    @DefineApiProjectAclCondition(projectIdColumn = "\"PROJECT_ID\"")
    @RegisterRowMapper(ComponentListRowMapper.class)
    List<Component> listProjectComponents(
            @Bind long projectId,
            @Bind int limit,
            @Bind Boolean onlyOutdated,
            @Bind Boolean onlyDirect,
            @Bind String lastName,
            @Bind String lastVersion,
            @Bind Long lastId
    );

    default Page<Component> listComponents(
            final Long projectId,
            final Boolean includeMetrics,
            final String componentPurl,
            final String componentCpe,
            final String componentSwidTagId,
            final String componentGroup,
            final String componentName,
            final String componentVersion,
            final HashType componentHashType,
            final String componentHash,
            final Boolean projectActive,
            final Boolean projectIsLatest,
            final int limit,
            final String pageToken,
            final String sortBy,
            final SortDirection sortDirection) {
        final PageTokenEncoder pageTokenEncoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decodedPageToken = pageTokenEncoder.decode(pageToken, ListComponentPageToken.class);

        TotalCount totalCount;
        final var whereConditions = new ArrayList<String>();
        final var queryParams = new HashMap<String, Object>();
        whereConditions.add("TRUE");
        if (projectId != null) {
            whereConditions.add("\"C\".\"PROJECT_ID\" = :projectId");
            queryParams.put("projectId", projectId);
        }
        if (componentGroup != null) {
            whereConditions.add("LOWER(\"C\".\"GROUP\") LIKE ('%' || LOWER(:componentGroup) || '%')");
            queryParams.put("componentGroup", componentGroup);
        }
        if (componentName != null) {
            whereConditions.add("LOWER(\"C\".\"NAME\") LIKE ('%' || LOWER(:componentName) || '%')");
            queryParams.put("componentName", componentName);
        }
        if (componentVersion != null) {
            whereConditions.add("LOWER(\"C\".\"VERSION\") LIKE ('%' || LOWER(:componentVersion) || '%')");
            queryParams.put("componentVersion", componentVersion);
        }
        if (componentPurl != null) {
            whereConditions.add("LOWER(\"C\".\"PURL\") LIKE LOWER(:componentPurl) || '%'");
            queryParams.put("componentPurl", componentPurl);
        }
        if (componentCpe != null) {
            whereConditions.add("LOWER(\"C\".\"CPE\") = LOWER(:componentCpe)");
            queryParams.put("componentCpe", componentCpe);
        }
        if (componentSwidTagId != null) {
            whereConditions.add("LOWER(\"C\".\"SWIDTAGID\") LIKE ('%' || LOWER(:componentSwidTagId) || '%')");
            queryParams.put("componentSwidTagId", componentSwidTagId);
        }
        if (projectActive != null) {
            whereConditions.add(projectActive
                    ? "\"PROJECT\".\"INACTIVE_SINCE\" IS NULL"
                    : "\"PROJECT\".\"INACTIVE_SINCE\" IS NOT NULL");
        }
        if (projectIsLatest != null) {
            whereConditions.add(projectIsLatest
                    ? "\"PROJECT\".\"IS_LATEST\""
                    : "NOT \"PROJECT\".\"IS_LATEST\"");
        }
        if (componentHashType != null && componentHash != null) {
            final String hashColumn = switch (componentHashType) {
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
            queryParams.put("componentHash", componentHash);
        }

        if (decodedPageToken != null) {
            totalCount = decodedPageToken.totalCount();
        } else {
            final String projectJoin = (projectActive != null || projectIsLatest != null)
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
        }

        final String cursorPrimary = decodedPageToken != null ? decodedPageToken.lastName() : null;
        final Long cursorId = decodedPageToken != null ? decodedPageToken.lastId() : null;
        final boolean hasCursor = decodedPageToken != null;
        final String sortDirectionSql = sortDirection != null ? sortDirection.name() : "ASC";

        var sortByColumn = switch (sortBy) {
            case "name" -> SortBy.NAME;
            case "version" -> SortBy.VERSION;
            case "group" -> SortBy.GROUP;
            case "purl" -> SortBy.PURL;
            case "cpe" -> SortBy.CPE;
            case "last_inherited_risk_score" -> SortBy.LAST_RISKSCORE;
            case null, default -> null;
        };

        final List<Component> rows = listComponents(whereConditions, queryParams, limit + 1,
                cursorPrimary,
                cursorId,
                sortByColumn, sortDirectionSql, hasCursor);

        final List<Component> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), limit))
                : rows;

        final ListComponentPageToken nextPageToken;
        if (rows.size() > limit) {
            final Component lastRow = resultRows.getLast();
            final Object lastPrimary = switch (sortByColumn) {
                case SortBy.NAME -> lastRow.getName();
                case SortBy.VERSION -> lastRow.getVersion();
                case SortBy.GROUP -> lastRow.getGroup();
                case SortBy.PURL -> lastRow.getPurl();
                case SortBy.CPE -> lastRow.getCpe();
                case SortBy.LAST_RISKSCORE -> lastRow.getLastInheritedRiskScore();
                case null -> lastRow.getName();
            };
            final String lastSecondary = sortByColumn == null ? lastRow.getVersion() : null;
            nextPageToken = new ListComponentPageToken(
                    lastPrimary != null ? lastPrimary.toString() : null,
                    lastSecondary,
                    lastRow.getId(),
                    totalCount);
        } else {
            nextPageToken = null;
        }

        if (includeMetrics) {
            final Map<Long, Component> componentById = resultRows.stream()
                    .collect(Collectors.toMap(Component::getId, Function.identity()));
            final List<DependencyMetrics> metricsList = getHandle().attach(MetricsDao.class)
                    .getMostRecentDependencyMetrics(componentById.keySet());
            for (final DependencyMetrics metrics : metricsList) {
                final var component = componentById.get(metrics.getComponentId());
                if (component != null) {
                    component.setMetrics(metrics);
                }
            }
        }

        return new Page<>(resultRows, pageTokenEncoder.encode(nextPageToken), totalCount);
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            <#-- @ftlvariable name="sortBy" type="org.dependencytrack.persistence.jdbi.SortBy" -->
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
                <#if hasCursor && sortByColumn?has_content>
                    AND (
                        <#if sortDirection == "DESC">
                            ("C"."${sortByColumn}" <
                                <#if sortByColumn == "LAST_RISKSCORE" > CAST(:lastPrimaryValue AS DOUBLE PRECISION)
                                <#else> :lastPrimaryValue
                                </#if>
                             OR ("C"."${sortByColumn}" =
                                <#if sortByColumn == "LAST_RISKSCORE" > CAST(:lastPrimaryValue AS DOUBLE PRECISION)
                                <#else> :lastPrimaryValue
                                </#if>
                             AND "C"."ID" > :lastId))
                        <#else>
                            ("C"."${sortByColumn}" >
                                <#if sortByColumn == "LAST_RISKSCORE" > CAST(:lastPrimaryValue AS DOUBLE PRECISION)
                                <#else> :lastPrimaryValue
                                </#if>
                             OR ("C"."${sortByColumn}" =
                                <#if sortByColumn == "LAST_RISKSCORE" > CAST(:lastPrimaryValue AS DOUBLE PRECISION)
                                <#else>:lastPrimaryValue
                                </#if>
                             AND "C"."ID" > :lastId))
                        </#if>
                    )
                <#elseif hasCursor && lastPrimaryValue?has_content && lastId?has_content>
                    AND ("C"."NAME" > :lastPrimaryValue
                            OR ("C"."NAME" = :lastPrimaryValue AND "C"."ID" > :lastId))
                </#if>
                <#if sortByColumn?has_content>
                    ORDER BY "${sortByColumn}" ${sortDirection!"ASC"}, "ID" ASC
                <#else>
                    <#-- Default sorting to ensure consistent pagination -->
                    ORDER BY "NAME" ASC, "ID" ASC
                </#if>
                LIMIT :limit
            """)
    @DefineNamedBindings
    @RegisterRowMapper(ComponentListRowMapper.class)
    @DefineApiProjectAclCondition(projectIdColumn = "\"C\".\"PROJECT_ID\"")
    List<Component> listComponents(
            @Define ArrayList<String> whereConditions,
            @BindMap Map<String, Object> queryParams,
            @Bind int limit,
            @Bind String lastPrimaryValue,
            @Bind Long lastId,
            @Define SortBy sortByColumn,
            @Define String sortDirection,
            @Define boolean hasCursor
    );

    enum SortBy {
        NAME,
        VERSION,
        GROUP,
        PURL,
        CPE,
        LAST_RISKSCORE
    }

    enum HashType {
        MD5,
        SHA1,
        SHA_256,
        SHA_384,
        SHA_512,
        SHA3_256,
        SHA3_384,
        SHA3_512,
        BLAKE2B_256,
        BLAKE2B_384,
        BLAKE2B_512,
        BLAKE3
    }

    class ComponentListRowMapper implements RowMapper<Component> {

        private final RowMapper<Component> componentRowMapper = BeanMapper.of(Component.class);

        @Override
        public Component map(final ResultSet rs, final StatementContext ctx) throws SQLException {
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
            return component;
        }
    }
}
