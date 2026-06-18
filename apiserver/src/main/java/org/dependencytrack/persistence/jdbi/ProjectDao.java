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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.github.packageurl.PackageURL;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.Page.TotalCount;
import org.dependencytrack.exception.AlreadyExistsException;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.ExternalReference;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.OrganizationalEntity;
import org.dependencytrack.model.ProjectCollectionLogic;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.persistence.jdbi.command.CloneProjectCommand;
import org.dependencytrack.persistence.jdbi.query.ListProjectsConciseQuery;
import org.dependencytrack.persistence.jdbi.query.ListProjectsQuery;
import org.jdbi.v3.core.mapper.reflect.ColumnName;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.UnableToExecuteStatementException;
import org.jdbi.v3.json.Json;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.AllowUnusedBindings;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.BindMap;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;
import org.jspecify.annotations.Nullable;
import org.postgresql.util.PSQLException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;

import static org.dependencytrack.util.PersistenceUtil.escapeLikePattern;

/**
 * @since 5.0.0
 */
@RegisterConstructorMapper(ProjectDao.ConciseProjectListRow.class)
public interface ProjectDao extends SqlObject, PaginationSupport {

    /// Aggregates `PROJECTMETRICS` rows of a single collection project's
    /// descendants into one row. Intended to be embedded as the body of a
    /// correlated LATERAL subquery.
    ///
    /// The outer query must alias the source project as `"PROJECT"` and is
    /// responsible for the `LEFT JOIN LATERAL (...)` wrapper, as well as
    /// enforcing portfolio ACL on `"PROJECT"`. Because ACLs are inherited,
    /// this query does not perform additional ACL checks.
    ///
    /// When the outer row is not a collection (`COLLECTION_LOGIC IS NULL`),
    /// the recursive seed short-circuits, making the impact negligible.
    ///
    /// Conceptually similar to [MetricsDao#getMostRecentCollectionProjectMetrics].
    /// Keep them in sync when the recursion rules change.
    String COLLECTION_METRICS_SUBQUERY = /* language=SQL */ """
            WITH RECURSIVE collection_descendants AS (
              SELECT "PROJECT"."ID" AS root_id
                   , child."ID" AS project_id
                   , child."COLLECTION_LOGIC"
                   , child."COLLECTION_TAG_ID"
                FROM "PROJECT_HIERARCHY" AS ph
               INNER JOIN "PROJECT" AS child
                  ON child."ID" = ph."CHILD_PROJECT_ID"
                 AND child."INACTIVE_SINCE" IS NULL
                 AND (
                   "PROJECT"."COLLECTION_LOGIC" != 'AGGREGATE_DIRECT_CHILDREN_WITH_TAG'
                   OR EXISTS (
                     SELECT 1
                       FROM "PROJECTS_TAGS" AS pt
                      WHERE pt."PROJECT_ID" = child."ID"
                        AND pt."TAG_ID" = "PROJECT"."COLLECTION_TAG_ID"
                   )
                 )
                 AND (
                   "PROJECT"."COLLECTION_LOGIC" != 'AGGREGATE_LATEST_VERSION_CHILDREN'
                   OR child."IS_LATEST"
                 )
               WHERE "PROJECT"."COLLECTION_LOGIC" IS NOT NULL
                 AND ph."PARENT_PROJECT_ID" = "PROJECT"."ID"
                 AND ph."DEPTH" = 1
               UNION ALL
              SELECT cd.root_id
                   , child."ID"
                   , child."COLLECTION_LOGIC"
                   , child."COLLECTION_TAG_ID"
                FROM collection_descendants cd
               INNER JOIN "PROJECT_HIERARCHY" AS ph
                  ON ph."PARENT_PROJECT_ID" = cd.project_id
                 AND ph."DEPTH" = 1
               INNER JOIN "PROJECT" AS child
                  ON child."ID" = ph."CHILD_PROJECT_ID"
               WHERE cd."COLLECTION_LOGIC" IS NOT NULL
                 AND child."INACTIVE_SINCE" IS NULL
                 AND (
                   cd."COLLECTION_LOGIC" != 'AGGREGATE_DIRECT_CHILDREN_WITH_TAG'
                   OR EXISTS (
                     SELECT 1
                       FROM "PROJECTS_TAGS" AS pt
                      WHERE pt."PROJECT_ID" = child."ID"
                        AND pt."TAG_ID" = cd."COLLECTION_TAG_ID"
                   )
                 )
                 AND (
                   cd."COLLECTION_LOGIC" != 'AGGREGATE_LATEST_VERSION_CHILDREN'
                   OR child."IS_LATEST"
                 )
            ) CYCLE project_id SET is_cycle USING path
            SELECT COALESCE(SUM(pm."COMPONENTS"), 0) AS components
                 , COALESCE(SUM(pm."VULNERABLECOMPONENTS"), 0) AS "vulnerableComponents"
                 , COALESCE(SUM(pm."VULNERABILITIES"), 0) AS vulnerabilities
                 , COALESCE(SUM(pm."CRITICAL"), 0) AS critical
                 , COALESCE(SUM(pm."HIGH"), 0) AS high
                 , COALESCE(SUM(pm."MEDIUM"), 0) AS medium
                 , COALESCE(SUM(pm."LOW"), 0) AS low
                 , COALESCE(SUM(pm."UNASSIGNED_SEVERITY"), 0) AS unassigned
                 , COALESCE(SUM(pm."RISKSCORE"), 0) AS "inheritedRiskScore"
                 , COALESCE(SUM(pm."FINDINGS_TOTAL"), 0) AS "findingsTotal"
                 , COALESCE(SUM(pm."FINDINGS_AUDITED"), 0) AS "findingsAudited"
                 , COALESCE(SUM(pm."FINDINGS_UNAUDITED"), 0) AS "findingsUnaudited"
                 , COALESCE(SUM(pm."SUPPRESSED"), 0) AS suppressed
                 , COALESCE(SUM(pm."POLICYVIOLATIONS_TOTAL"), 0) AS "policyViolationsTotal"
                 , COALESCE(SUM(pm."POLICYVIOLATIONS_FAIL"), 0) AS "policyViolationsFail"
                 , COALESCE(SUM(pm."POLICYVIOLATIONS_WARN"), 0) AS "policyViolationsWarn"
                 , COALESCE(SUM(pm."POLICYVIOLATIONS_INFO"), 0) AS "policyViolationsInfo"
                 , COALESCE(SUM(pm."POLICYVIOLATIONS_AUDITED"), 0) AS "policyViolationsAudited"
                 , COALESCE(SUM(pm."POLICYVIOLATIONS_UNAUDITED"), 0) AS "policyViolationsUnaudited"
                 , COALESCE(SUM(pm."POLICYVIOLATIONS_SECURITY_TOTAL"), 0) AS "policyViolationsSecurityTotal"
                 , COALESCE(SUM(pm."POLICYVIOLATIONS_SECURITY_AUDITED"), 0) AS "policyViolationsSecurityAudited"
                 , COALESCE(SUM(pm."POLICYVIOLATIONS_SECURITY_UNAUDITED"), 0) AS "policyViolationsSecurityUnaudited"
                 , COALESCE(SUM(pm."POLICYVIOLATIONS_LICENSE_TOTAL"), 0) AS "policyViolationsLicenseTotal"
                 , COALESCE(SUM(pm."POLICYVIOLATIONS_LICENSE_AUDITED"), 0) AS "policyViolationsLicenseAudited"
                 , COALESCE(SUM(pm."POLICYVIOLATIONS_LICENSE_UNAUDITED"), 0) AS "policyViolationsLicenseUnaudited"
                 , COALESCE(SUM(pm."POLICYVIOLATIONS_OPERATIONAL_TOTAL"), 0) AS "policyViolationsOperationalTotal"
                 , COALESCE(SUM(pm."POLICYVIOLATIONS_OPERATIONAL_AUDITED"), 0) AS "policyViolationsOperationalAudited"
                 , COALESCE(SUM(pm."POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"), 0) AS "policyViolationsOperationalUnaudited"
                 , MIN(pm."FIRST_OCCURRENCE") AS "firstOccurrence"
                 , MAX(pm."LAST_OCCURRENCE") AS "lastOccurrence"
              FROM collection_descendants cd
              LEFT JOIN LATERAL (
                SELECT *
                  FROM "PROJECTMETRICS"
                 WHERE "PROJECT_ID" = cd.project_id
                 ORDER BY "LAST_OCCURRENCE" DESC
                 LIMIT 1
              ) pm ON TRUE
             WHERE cd."COLLECTION_LOGIC" IS NULL
            """;

    /// Selects the most recent `PROJECTMETRICS` row for a single non-collection project.
    /// Columns are aliased to match the [ProjectMetrics] property names.
    ///
    /// The outer query must alias the source project as `"PROJECT"`.
    String LEAF_METRICS_SUBQUERY = /* language=SQL */ """
            SELECT "COMPONENTS" AS components
                 , "VULNERABLECOMPONENTS" AS "vulnerableComponents"
                 , "VULNERABILITIES" AS vulnerabilities
                 , "CRITICAL" AS critical
                 , "HIGH" AS high
                 , "MEDIUM" AS medium
                 , "LOW" AS low
                 , "UNASSIGNED_SEVERITY" AS unassigned
                 , "RISKSCORE" AS "inheritedRiskScore"
                 , "FINDINGS_TOTAL" AS "findingsTotal"
                 , "FINDINGS_AUDITED" AS "findingsAudited"
                 , "FINDINGS_UNAUDITED" AS "findingsUnaudited"
                 , "SUPPRESSED" AS suppressed
                 , "POLICYVIOLATIONS_TOTAL" AS "policyViolationsTotal"
                 , "POLICYVIOLATIONS_FAIL" AS "policyViolationsFail"
                 , "POLICYVIOLATIONS_WARN" AS "policyViolationsWarn"
                 , "POLICYVIOLATIONS_INFO" AS "policyViolationsInfo"
                 , "POLICYVIOLATIONS_AUDITED" AS "policyViolationsAudited"
                 , "POLICYVIOLATIONS_UNAUDITED" AS "policyViolationsUnaudited"
                 , "POLICYVIOLATIONS_SECURITY_TOTAL" AS "policyViolationsSecurityTotal"
                 , "POLICYVIOLATIONS_SECURITY_AUDITED" AS "policyViolationsSecurityAudited"
                 , "POLICYVIOLATIONS_SECURITY_UNAUDITED" AS "policyViolationsSecurityUnaudited"
                 , "POLICYVIOLATIONS_LICENSE_TOTAL" AS "policyViolationsLicenseTotal"
                 , "POLICYVIOLATIONS_LICENSE_AUDITED" AS "policyViolationsLicenseAudited"
                 , "POLICYVIOLATIONS_LICENSE_UNAUDITED" AS "policyViolationsLicenseUnaudited"
                 , "POLICYVIOLATIONS_OPERATIONAL_TOTAL" AS "policyViolationsOperationalTotal"
                 , "POLICYVIOLATIONS_OPERATIONAL_AUDITED" AS "policyViolationsOperationalAudited"
                 , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED" AS "policyViolationsOperationalUnaudited"
                 , "FIRST_OCCURRENCE" AS "firstOccurrence"
                 , "LAST_OCCURRENCE" AS "lastOccurrence"
              FROM "PROJECTMETRICS"
             WHERE "PROJECTMETRICS"."PROJECT_ID" = "PROJECT"."ID"
             ORDER BY "PROJECTMETRICS"."LAST_OCCURRENCE" DESC
             LIMIT 1
            """;

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="includeMetrics" type="boolean" -->
            <#-- @ftlvariable name="whereConditions" type="java.util.Collection<String>" -->
            <#-- @ftlvariable name="collectionMetricsSubquery" type="String" -->
            <#-- @ftlvariable name="leafMetricsSubquery" type="String" -->
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            SELECT "PROJECT"."ID"
                 , "PROJECT"."UUID" AS "uuid"
                 , "GROUP" AS "group"
                 , "NAME" AS "name"
                 , "VERSION" AS "version"
                 , "PROJECT"."CLASSIFIER" AS "classifier"
                 , "PROJECT"."INACTIVE_SINCE" AS "inactiveSince"
                 , "PROJECT"."IS_LATEST" AS "isLatest"
                 , "PROJECT"."COLLECTION_LOGIC" AS "collectionLogic"
                 , "PROJECT"."COLLECTION_TAG_ID" AS "collectionTagId"
                 , (
                     SELECT ARRAY_AGG("TAG"."NAME")
                       FROM "TAG"
                      INNER JOIN "PROJECTS_TAGS"
                         ON "PROJECTS_TAGS"."TAG_ID" = "TAG"."ID"
                      WHERE "PROJECTS_TAGS"."PROJECT_ID" = "PROJECT"."ID"
                   ) AS "tags"
                 , (
                     SELECT ARRAY_AGG("TEAM"."NAME")
                       FROM "TEAM"
                      INNER JOIN "PROJECT_ACCESS_TEAMS"
                         ON "PROJECT_ACCESS_TEAMS"."TEAM_ID" = "TEAM"."ID"
                      WHERE "PROJECT_ACCESS_TEAMS"."PROJECT_ID" = "PROJECT"."ID"
                   ) AS "teams"
                 , "PROJECT"."LAST_BOM_IMPORTED" AS "lastBomImport"
                 , "PROJECT"."LAST_BOM_IMPORTED_FORMAT" AS "lastBomImportFormat"
                 , CASE
                     WHEN "PROJECT"."COLLECTION_LOGIC" IS NOT NULL
                     THEN cm."inheritedRiskScore"
                     ELSE "PROJECT"."LAST_RISKSCORE"
                   END AS "lastRiskScore"
                 , (
                     SELECT EXISTS(
                       SELECT 1
                         FROM "PROJECT" AS "CHILD_PROJECT"
                        WHERE "CHILD_PROJECT"."PARENT_PROJECT_ID" = "PROJECT"."ID")
                   ) AS "hasChildren"
            <#if includeMetrics>
                 , CASE
                     WHEN "PROJECT"."COLLECTION_LOGIC" IS NOT NULL
                     THEN TO_JSONB(cm.*)
                     ELSE (SELECT TO_JSONB(m) FROM (${leafMetricsSubquery}) AS m)
                   END AS "metrics"
            </#if>
              FROM "PROJECT"
            <#--
                NB: We are forced to do this lateral join unconditionally, because callers expect
                lastRiskScore to be returned, but collection projects have no precomputed
                LAST_RISKSCORE column. In a future query backing a hypothetical API v2 endpoint,
                lastRiskScore should be an expandable field to work around this.
            -->
              LEFT JOIN LATERAL (${collectionMetricsSubquery}) AS cm
                ON "PROJECT"."COLLECTION_LOGIC" IS NOT NULL
             WHERE ${apiProjectAclCondition}
               AND ${whereConditions?join(" AND ")}
            <#if apiOrderByClause??>
              ${apiOrderByClause}
            <#else>
             ORDER BY "name", "PROJECT"."ID"
            </#if>
            ${apiOffsetLimitClause!}
            """)
    @AllowApiOrdering(alwaysBy = @AllowApiOrdering.AlwaysBy(queryName = "\"PROJECT\".\"ID\""), by = {
            @AllowApiOrdering.Column(name = "group"),
            @AllowApiOrdering.Column(name = "name"),
            @AllowApiOrdering.Column(name = "version"),
            @AllowApiOrdering.Column(name = "classifier"),
            @AllowApiOrdering.Column(name = "inactiveSince"),
            @AllowApiOrdering.Column(name = "isLatest"),
            @AllowApiOrdering.Column(name = "lastBomImport"),
            @AllowApiOrdering.Column(name = "lastBomImportFormat"),
            @AllowApiOrdering.Column(name = "lastRiskScore")
    })
    @AllowUnusedBindings
    List<ConciseProjectListRow> queryPageConcise(
            @Define ArrayList<String> whereConditions,
            @BindMap Map<String, Object> queryParams,
            @Define boolean includeMetrics,
            @Define String collectionMetricsSubquery,
            @Define String leafMetricsSubquery);

    default Page<ConciseProjectListRow> getPageConcise(ListProjectsConciseQuery query) {
        if (query.parentUuidFilter() != null
                && !Boolean.TRUE.equals(isAccessible(query.parentUuidFilter()))) {
            return Page.empty();
        }

        final var whereConditions = new ArrayList<String>();
        final var queryParams = new HashMap<String, Object>();
        whereConditions.add("TRUE");
        if (query.nameFilter() != null) {
            whereConditions.add("\"PROJECT\".\"NAME\" = :nameFilter");
            queryParams.put("nameFilter", query.nameFilter());
        }
        if (query.versionFilter() != null) {
            whereConditions.add("\"PROJECT\".\"VERSION\" = :versionFilter");
            queryParams.put("versionFilter", query.versionFilter());
        }
        if (query.classifierFilter() != null) {
            whereConditions.add("\"PROJECT\".\"CLASSIFIER\" = :classifierFilter");
            queryParams.put("classifierFilter", query.classifierFilter());
        }
        if (query.tagFilter() != null) {
            whereConditions.add(/* language=SQL */ """
                    EXISTS (
                      SELECT 1
                        FROM "PROJECTS_TAGS"
                       INNER JOIN "TAG"
                          ON "TAG"."ID" = "PROJECTS_TAGS"."TAG_ID"
                       WHERE "PROJECTS_TAGS"."PROJECT_ID" = "PROJECT"."ID"
                         AND "TAG"."NAME" = :tagFilter
                    )""");
            queryParams.put("tagFilter", query.tagFilter());
        }
        if (query.teamFilter() != null) {
            whereConditions.add(/* language=SQL */ """
                    EXISTS (
                      SELECT 1
                        FROM "PROJECT_ACCESS_TEAMS"
                       INNER JOIN "TEAM"
                          ON "TEAM"."ID" = "PROJECT_ACCESS_TEAMS"."TEAM_ID"
                       WHERE "PROJECT_ACCESS_TEAMS"."PROJECT_ID" = "PROJECT"."ID"
                         AND "TEAM"."NAME" = :teamFilter
                    )""");
            queryParams.put("teamFilter", query.teamFilter());
        }
        if (Boolean.TRUE.equals(query.activeFilter())) {
            whereConditions.add("\"PROJECT\".\"INACTIVE_SINCE\" IS NULL");
        }
        if (query.onlyRootFilter() != null) {
            if (query.onlyRootFilter()) {
                whereConditions.add("\"PROJECT\".\"PARENT_PROJECT_ID\" IS NULL");
            }
        } else if (query.parentUuidFilter() != null) {
            whereConditions.add(/* language=SQL */ """
                    EXISTS (
                      SELECT 1
                        FROM "PROJECT" AS "PARENT_PROJECT"
                       WHERE "PARENT_PROJECT"."ID" = "PROJECT"."PARENT_PROJECT_ID"
                         AND "PARENT_PROJECT"."UUID" = :parentUuidFilter
                    )""");
            queryParams.put("parentUuidFilter", query.parentUuidFilter());
        }
        if (query.searchText() != null) {
            whereConditions.add(/* language=SQL */ """
                    (
                      LOWER("PROJECT"."NAME") LIKE ('%' || LOWER(:searchTextLike) || '%') ESCAPE '!'
                      OR EXISTS (
                        SELECT 1
                          FROM "PROJECTS_TAGS"
                         INNER JOIN "TAG"
                            ON "TAG"."ID" = "PROJECTS_TAGS"."TAG_ID"
                         WHERE "PROJECTS_TAGS"."PROJECT_ID" = "PROJECT"."ID"
                           AND "TAG"."NAME" = :searchText
                      )
                    )""");
            queryParams.put("searchText", query.searchText());
            queryParams.put("searchTextLike", escapeLikePattern(query.searchText()));
        }

        return withJitDisabled(() -> {
            // NB: Count is executed separately from the main query, because including
            // `COUNT(*) OVER()` in the main query forces Postgres to materialize all rows,
            // including LATERAL joins *BEFORE* applying filters and limits.
            //
            // Since calculating metrics for collection projects requires recursive subqueries,
            // this would be extremely expensive. Counting in a separate query bypasses this.
            final TotalCount totalCount = getBoundedTotalCountWithProjectAcl(
                    "FROM \"PROJECT\" WHERE " + String.join(" AND ", whereConditions),
                    queryParams,
                    /* threshold */ null,
                    "\"PROJECT\".\"ID\"");

            final List<ConciseProjectListRow> rows = queryPageConcise(
                    whereConditions,
                    queryParams,
                    query.includeMetrics(),
                    COLLECTION_METRICS_SUBQUERY,
                    LEAF_METRICS_SUBQUERY);

            return new Page<>(rows, /* nextPageToken */ null, totalCount);
        });
    }

    record ConciseProjectListRow(
            long id,
            UUID uuid,
            String group,
            String name,
            String version,
            String classifier,
            @Nullable Instant inactiveSince,
            boolean isLatest,
            @Nullable ProjectCollectionLogic collectionLogic,
            @Nullable Long collectionTagId,
            List<String> tags,
            List<String> teams,
            @Nullable Instant lastBomImport,
            @Nullable String lastBomImportFormat,
            @Nullable Double lastRiskScore,
            boolean hasChildren,
            @Nullable @Json ConciseProjectMetricsRow metrics) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record ConciseProjectMetricsRow(
            int components,
            int critical,
            int high,
            int low,
            int medium,
            int policyViolationsFail,
            int policyViolationsInfo,
            int policyViolationsLicenseTotal,
            int policyViolationsOperationalTotal,
            int policyViolationsSecurityTotal,
            int policyViolationsTotal,
            int policyViolationsWarn,
            double inheritedRiskScore,
            int unassigned,
            int vulnerabilities) {
    }

    record ListProjectsRow(
            UUID uuid,
            @Nullable String group,
            String name,
            @Nullable String version,
            @Nullable Classifier classifier,
            @Nullable String description,
            @Nullable String publisher,
            @Nullable PackageURL purl,
            @Nullable String swidTagId,
            @Nullable String cpe,
            @Nullable String directDependencies,
            boolean isLatest,
            @Nullable Date inactiveSince,
            @Nullable Date lastBomImport,
            @Nullable String lastBomImportFormat,
            @Nullable Date lastVulnerabilityAnalysis,
            @Nullable Double lastInheritedRiskScore,
            @Nullable List<ExternalReference> externalReferences,
            @Nullable OrganizationalEntity supplier,
            @Nullable OrganizationalEntity manufacturer,
            @Nullable List<OrganizationalContact> authors,
            @Nullable List<String> tagNames,
            @Json @ColumnName("metadataJson") @Nullable ProjectMetadata metadata,
            @Json @ColumnName("metricsJson") @Nullable ProjectMetrics metrics,
            @Nullable ProjectCollectionLogic collectionLogic,
            @Nullable String collectionTagName,
            @Nullable UUID parentUuid,
            @Nullable String parentName,
            @Nullable String parentVersion,
            boolean hasChildren) {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="includeMetrics" type="boolean" -->
            <#-- @ftlvariable name="whereConditions" type="java.util.Collection<String>" -->
            <#-- @ftlvariable name="collectionMetricsSubquery" type="String" -->
            <#-- @ftlvariable name="leafMetricsSubquery" type="String" -->
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            SELECT "PROJECT"."ID"
                 , "PROJECT"."CLASSIFIER" AS "classifier"
                 , "PROJECT"."CPE"
                 , "PROJECT"."DESCRIPTION"
                 , "PROJECT"."DIRECT_DEPENDENCIES"
                 , "PROJECT"."EXTERNAL_REFERENCES"
                 , "PROJECT"."GROUP" AS "group"
                 , "PROJECT"."LAST_BOM_IMPORTED" AS "lastBomImport"
                 , "PROJECT"."LAST_BOM_IMPORTED_FORMAT" AS "lastBomImportFormat"
                 , "PROJECT"."LAST_VULNERABILITY_ANALYSIS"
                 , CASE
                     WHEN "PROJECT"."COLLECTION_LOGIC" IS NOT NULL
                     THEN cm."inheritedRiskScore"
                     ELSE "PROJECT"."LAST_RISKSCORE"
                   END AS "lastInheritedRiskScore"
                 , (
                     SELECT EXISTS(
                       SELECT 1
                         FROM "PROJECT" AS "CHILD_PROJECT"
                        WHERE "CHILD_PROJECT"."PARENT_PROJECT_ID" = "PROJECT"."ID")
                   ) AS "hasChildren"
                 , "PROJECT"."NAME" AS "name"
                 , "PROJECT"."PUBLISHER"
                 , "PROJECT"."PURL"
                 , "PROJECT"."SWIDTAGID"
                 , "PROJECT"."UUID"
                 , "PROJECT"."VERSION"
                 , "PROJECT"."SUPPLIER"
                 , "PROJECT"."MANUFACTURER"
                 , "PROJECT"."AUTHORS"
                 , "PROJECT"."IS_LATEST" AS "isLatest"
                 , "PROJECT"."INACTIVE_SINCE" AS "inactiveSince"
                 , "PROJECT"."COLLECTION_LOGIC"
                 , collection_tag."NAME" AS "collectionTagName"
                 , (
                     SELECT ARRAY_AGG("TAG"."NAME")
                       FROM "TAG"
                      INNER JOIN "PROJECTS_TAGS"
                         ON "PROJECTS_TAGS"."PROJECT_ID" = "PROJECT"."ID"
                      WHERE "TAG"."ID" = "PROJECTS_TAGS"."TAG_ID"
                   ) AS "tagNames"
                 , (
                     SELECT JSONB_STRIP_NULLS(JSONB_BUILD_OBJECT(
                              'supplier', "SUPPLIER"::JSONB,
                              'authors', "AUTHORS"::JSONB,
                              'tools', "TOOLS"::JSONB
                            ))
                       FROM "PROJECT_METADATA"
                      WHERE "PROJECT_METADATA"."PROJECT_ID" = "PROJECT"."ID"
                   ) AS "metadataJson"
            <#if includeMetrics>
                 , CASE
                     WHEN "PROJECT"."COLLECTION_LOGIC" IS NOT NULL
                     THEN TO_JSONB(cm.*)
                     ELSE (SELECT TO_JSONB(m) FROM (${leafMetricsSubquery}) AS m)
                   END AS "metricsJson"
            </#if>
                 , parent."UUID" AS "parentUuid"
                 , parent."NAME" AS "parentName"
                 , parent."VERSION" AS "parentVersion"
              FROM "PROJECT"
            <#--
                NB: We are forced to do this lateral join unconditionally, because callers expect
                lastInheritedRiskScore to be returned, but collection projects have no precomputed
                LAST_RISKSCORE column. In a future query backing a hypothetical API v2 endpoint,
                lastInheritedRiskScore should be an expandable field to work around this.
            -->
              LEFT JOIN "PROJECT" AS parent
                ON "PROJECT"."PARENT_PROJECT_ID" IS NOT NULL
               AND parent."ID" = "PROJECT"."PARENT_PROJECT_ID"
              LEFT JOIN LATERAL (${collectionMetricsSubquery}) AS cm
                ON "PROJECT"."COLLECTION_LOGIC" IS NOT NULL
              LEFT JOIN "TAG" AS collection_tag
                ON collection_tag."ID" = "PROJECT"."COLLECTION_TAG_ID"
             WHERE ${apiProjectAclCondition}
               AND ${whereConditions?join(" AND ")}
            <#if apiOrderByClause??>
                ${apiOrderByClause}
            <#else>
                ORDER BY "name", "PROJECT"."ID"
            </#if>
            ${apiOffsetLimitClause!}
            """)
    @AllowApiOrdering(alwaysBy = @AllowApiOrdering.AlwaysBy(queryName = "\"PROJECT\".\"ID\""), by = {
            @AllowApiOrdering.Column(name = "group"),
            @AllowApiOrdering.Column(name = "name"),
            @AllowApiOrdering.Column(name = "version"),
            @AllowApiOrdering.Column(name = "classifier"),
            @AllowApiOrdering.Column(name = "inactiveSince"),
            @AllowApiOrdering.Column(name = "isLatest"),
            @AllowApiOrdering.Column(name = "lastBomImport"),
            @AllowApiOrdering.Column(name = "lastBomImportFormat"),
            @AllowApiOrdering.Column(name = "lastInheritedRiskScore")
    })
    @RegisterConstructorMapper(ListProjectsRow.class)
    @AllowUnusedBindings
    List<ListProjectsRow> getProjects(
            @Define ArrayList<String> whereConditions,
            @BindMap Map<String, Object> queryParams,
            @Define boolean includeMetrics,
            @Define String collectionMetricsSubquery,
            @Define String leafMetricsSubquery);

    default Page<ListProjectsRow> getProjects(ListProjectsQuery query) {
        final var whereConditions = new ArrayList<String>();
        final var queryParams = new HashMap<String, Object>();
        whereConditions.add("TRUE");
        if (query.nameFilter() != null) {
            whereConditions.add("\"PROJECT\".\"NAME\" = :nameFilter");
            queryParams.put("nameFilter", query.nameFilter());
        }
        if (query.classifierFilter() != null) {
            whereConditions.add("\"PROJECT\".\"CLASSIFIER\" = :classifierFilter");
            queryParams.put("classifierFilter", query.classifierFilter());
        }
        if (query.tagFilter() != null) {
            whereConditions.add(/* language=SQL */ """
                    EXISTS (
                      SELECT 1
                        FROM "PROJECTS_TAGS"
                       INNER JOIN "TAG"
                          ON "TAG"."ID" = "PROJECTS_TAGS"."TAG_ID"
                       WHERE "PROJECTS_TAGS"."PROJECT_ID" = "PROJECT"."ID"
                         AND "TAG"."NAME" = :tagFilter
                    )""");
            queryParams.put("tagFilter", query.tagFilter());
        }
        if (query.teamFilter() != null) {
            whereConditions.add(/* language=SQL */ """
                    EXISTS (
                      SELECT 1
                        FROM "PROJECT_ACCESS_TEAMS"
                       INNER JOIN "TEAM"
                          ON "TEAM"."ID" = "PROJECT_ACCESS_TEAMS"."TEAM_ID"
                       WHERE "PROJECT_ACCESS_TEAMS"."PROJECT_ID" = "PROJECT"."ID"
                         AND "TEAM"."NAME" = :teamFilter
                    )""");
            queryParams.put("teamFilter", query.teamFilter());
        }
        if (query.notAssignedToTeamWithUuidFilter() != null) {
            whereConditions.add(/* language=SQL */ """
                    NOT EXISTS (
                      SELECT 1
                        FROM "PROJECT_ACCESS_TEAMS"
                       INNER JOIN "TEAM"
                          ON "TEAM"."ID" = "PROJECT_ACCESS_TEAMS"."TEAM_ID"
                       WHERE "PROJECT_ACCESS_TEAMS"."PROJECT_ID" = "PROJECT"."ID"
                         AND "TEAM"."UUID" = :notAssignedToTeamWithUuidFilter
                    )""");
            queryParams.put("notAssignedToTeamWithUuidFilter", query.notAssignedToTeamWithUuidFilter());
        }
        if (query.parentUuidFilter() != null) {
            whereConditions.add(/* language=SQL */ """
                    EXISTS (
                      SELECT 1
                        FROM "PROJECT" AS "PARENT_PROJECT"
                       WHERE "PARENT_PROJECT"."ID" = "PROJECT"."PARENT_PROJECT_ID"
                         AND "PARENT_PROJECT"."UUID" = :parentUuidFilter
                    )""");
            queryParams.put("parentUuidFilter", query.parentUuidFilter());
        }
        if (query.excludeDescendantsOfUuid() != null) {
            whereConditions.add(/* language=SQL */ """
                    NOT EXISTS (
                      SELECT 1
                        FROM "PROJECT_HIERARCHY"
                       INNER JOIN "PROJECT" AS "ANCESTOR_PROJECT"
                          ON "ANCESTOR_PROJECT"."ID" = "PROJECT_HIERARCHY"."PARENT_PROJECT_ID"
                       WHERE "ANCESTOR_PROJECT"."UUID" = :excludeDescendantsOfUuid
                         AND "PROJECT_HIERARCHY"."CHILD_PROJECT_ID" = "PROJECT"."ID"
                    )""");
            queryParams.put("excludeDescendantsOfUuid", query.excludeDescendantsOfUuid());
        }
        if (query.excludeInactive()) {
            whereConditions.add("\"PROJECT\".\"INACTIVE_SINCE\" IS NULL");
        }
        if (query.onlyRoot()) {
            whereConditions.add("\"PROJECT\".\"PARENT_PROJECT_ID\" IS NULL");
        }
        if (query.searchText() != null) {
            whereConditions.add(/* language=SQL */ """
                    (
                      LOWER("PROJECT"."NAME") LIKE ('%' || LOWER(:searchTextLike) || '%') ESCAPE '!'
                      OR EXISTS (
                        SELECT 1
                          FROM "PROJECTS_TAGS"
                         INNER JOIN "TAG"
                            ON "TAG"."ID" = "PROJECTS_TAGS"."TAG_ID"
                         WHERE "PROJECTS_TAGS"."PROJECT_ID" = "PROJECT"."ID"
                           AND "TAG"."NAME" = :searchText
                      )
                    )""");
            queryParams.put("searchText", query.searchText());
            queryParams.put("searchTextLike", escapeLikePattern(query.searchText()));
        }

        return withJitDisabled(() -> {
            // Count is run separately so the LATERAL fan-out and per-row SubPlans
            // in the page query stay bounded to the page rows. Without this, the
            // `COUNT(*) OVER()` window function would force materialization of
            // every filtered row through the LATERAL.
            final TotalCount totalCount = getBoundedTotalCountWithProjectAcl(
                    "FROM \"PROJECT\" WHERE " + String.join(" AND ", whereConditions),
                    queryParams,
                    /* threshold */ null,
                    "\"PROJECT\".\"ID\"");

            final List<ListProjectsRow> rows = getProjects(
                    whereConditions,
                    queryParams,
                    query.includeMetrics(),
                    COLLECTION_METRICS_SUBQUERY,
                    LEAF_METRICS_SUBQUERY);

            return new Page<>(
                    rows,
                    /* nextPageToken */ null,
                    new TotalCount(totalCount.value(), TotalCount.Type.EXACT));
        });
    }

    @SqlUpdate("""
            DELETE
              FROM "PROJECT"
             WHERE "UUID" = :projectUuid
            """)
    int deleteProject(@Bind final UUID projectUuid);

    @SqlUpdate("""
            WITH cte_locked AS (
              SELECT "ID"
                FROM "PROJECT"
               WHERE ${apiProjectAclCondition}
                 AND "UUID" = ANY(:projectUuids)
               ORDER BY "ID"
                 FOR UPDATE
            )
            DELETE
              FROM "PROJECT"
             WHERE "ID" IN (SELECT "ID" FROM cte_locked)
            RETURNING "UUID"
            """)
    @GetGeneratedKeys
    Set<UUID> deleteProjects(@Bind Collection<UUID> projectUuids);

    @SqlQuery("""
             WITH "CTE" AS (
               SELECT "ID"
                 FROM "PROJECT"
                WHERE "INACTIVE_SINCE" < :retentionCutOff
                ORDER BY "INACTIVE_SINCE"
                LIMIT :batchSize
             )
             DELETE
               FROM "PROJECT"
              WHERE "ID" IN (SELECT "ID" FROM "CTE")
              RETURNING "NAME", "VERSION", "INACTIVE_SINCE", "UUID"
            """)
    @RegisterConstructorMapper(DeletedProject.class)
    List<DeletedProject> deleteInactiveProjectsForRetentionDuration(@Bind final Instant retentionCutOff, @Bind final int batchSize);

    record DeletedProject(@ColumnName("NAME") String name,
                          @ColumnName("VERSION") String version,
                          @ColumnName("INACTIVE_SINCE") Instant inactiveSince,
                          @ColumnName("UUID") UUID uuid) {
    }

    @SqlQuery("""
            WITH cte_candidates AS (
              SELECT "ID"
                FROM (
                  SELECT "ID"
                       , ROW_NUMBER() OVER (PARTITION BY "NAME" ORDER BY "INACTIVE_SINCE" DESC) AS rn
                    FROM "PROJECT"
                   WHERE "INACTIVE_SINCE" IS NOT NULL
                ) AS ranked
               WHERE rn > :versionCountThreshold
               LIMIT :batchSize
            )
            DELETE
              FROM "PROJECT"
             WHERE "ID" IN (SELECT "ID" FROM cte_candidates)
            RETURNING "NAME"
                    , "VERSION"
                    , "INACTIVE_SINCE"
                    , "UUID"
            """)
    @RegisterConstructorMapper(DeletedProject.class)
    List<DeletedProject> deleteExcessProjectVersions(@Bind int versionCountThreshold, @Bind int batchSize);

    record ProjectInfoRow(long id, boolean isCollection) {
    }

    @SqlQuery("""
            SELECT "ID"
                 , "COLLECTION_LOGIC" IS NOT NULL AS is_collection
              FROM "PROJECT"
             WHERE "UUID" = :projectUuid
            """)
    @RegisterConstructorMapper(ProjectInfoRow.class)
    @Nullable
    ProjectInfoRow getProjectInfo(@Bind UUID projectUuid);

    default @Nullable Long getProjectId(UUID projectUuid) {
        final ProjectInfoRow info = getProjectInfo(projectUuid);
        return info != null ? info.id() : null;
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            SELECT ${apiProjectAclCondition}
              FROM "PROJECT"
             WHERE "UUID" = :projectUuid
            """)
    Boolean isAccessible(@Bind UUID projectUuid);

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            SELECT "UUID"
              FROM "PROJECT"
             WHERE "UUID" = ANY(:projectUuids)
               AND ${apiProjectAclCondition}
            """)
    Set<UUID> getAccessibleProjectUuids(@Bind Collection<UUID> projectUuids);

    /**
     * @param command The clone command.
     * @return The {@link UUID} of the cloned project.
     * @throws NoSuchElementException When the source project does not exist.
     * @throws AlreadyExistsException When a project with the target version already exists.
     * @since 5.0.0
     */
    default UUID cloneProject(final CloneProjectCommand command) {
        final Query query = getHandle().createQuery(/* language=SQL */ """
                SELECT clone_project(
                  :sourceProjectUuid
                , :targetProjectVersion
                , :targetProjectVersionIsLatest
                , :includeAcl
                , :includeComponents
                , :includeFindings
                , :includeFindingsAuditHistory
                , :includePolicyViolations
                , :includePolicyViolationsAuditHistory
                , :includeProperties
                , :includeServices
                , :includeTags
                );
                """);

        try {
            return query
                    .bindMethods(command)
                    .mapTo(UUID.class)
                    .one();
        } catch (UnableToExecuteStatementException e) {
            if (e.getCause() instanceof final PSQLException pe
                    && pe.getServerErrorMessage() != null
                    && pe.getServerErrorMessage().getMessage() != null) {
                if (pe.getServerErrorMessage().getMessage().startsWith("Source project does not exist")) {
                    throw new NoSuchElementException(pe.getServerErrorMessage().getMessage(), pe);
                } else if (pe.getServerErrorMessage().getMessage().startsWith("Target project version already exists")) {
                    throw new AlreadyExistsException(pe.getServerErrorMessage().getMessage(), pe);
                }
            }

            throw e;
        }
    }

    /**
     * @since 5.0.0
     */
    @SqlUpdate("""
            UPDATE "PROJECT"
               SET "LAST_VULNERABILITY_ANALYSIS" = NOW()
             WHERE "UUID" = :uuid
            """)
    void updateLastVulnAnalysis(@Bind UUID uuid);

}
