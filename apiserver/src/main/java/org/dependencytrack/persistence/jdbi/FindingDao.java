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
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.jdbi.v3.json.Json;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.AllowUnusedBindings;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.BindMap;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.customizer.DefineNamedBindings;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jspecify.annotations.Nullable;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.LongSupplier;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiAttributes.ATTRIBUTE_API_PAGINATE;
import static org.dependencytrack.resources.v1.FindingResource.mapComponentLatestVersion;

public interface FindingDao extends PaginationSupport {

    record FindingRow(
            UUID projectUuid,
            UUID componentUuid,
            String projectName,
            String projectVersion,
            String componentName,
            String componentGroup,
            String componentVersion,
            String componentPurl,
            String componentCpe,
            String componentScope,
            boolean componentHasOccurrences,
            UUID vulnUuid,
            Vulnerability.Source vulnSource,
            String vulnId,
            String vulnTitle,
            String vulnSubtitle,
            String vulnDescription,
            String vulnRecommendation,
            String vulnReferences,
            Instant vulnPublished,
            Severity vulnSeverity,
            List<Integer> cwes,
            BigDecimal cvssV2BaseScore,
            BigDecimal cvssV3BaseScore,
            BigDecimal cvssV4Score,
            String cvssV2Vector,
            String cvssV3Vector,
            String cvssV4Vector,
            BigDecimal owaspRRLikelihoodScore,
            BigDecimal owaspRRTechnicalImpactScore,
            BigDecimal owaspRRBusinessImpactScore,
            String owaspRRVector,
            @Json List<VulnerabilityAlias> vulnAliasesJson,
            BigDecimal epssScore,
            BigDecimal epssPercentile,
            boolean kev,
            String analyzerIdentity,
            Instant attributed_on,
            String alt_id,
            String reference_url,
            @Nullable Short matching_percentage,
            AnalysisState analysisState,
            boolean suppressed,
            @Nullable String analysisDetail,
            @Nullable Long totalCount) {}

    record GroupedFindingRow(
            Vulnerability.Source vulnSource,
            String vulnId,
            String vulnTitle,
            Severity vulnSeverity,
            BigDecimal cvssV2BaseScore,
            BigDecimal cvssV3BaseScore,
            BigDecimal cvssV4Score,
            BigDecimal epssScore,
            BigDecimal epssPercentile,
            boolean kev,
            Instant vulnPublished,
            List<Integer> cwes,
            String analyzerIdentity,
            int affectedProjectCount,
            @Nullable Long totalCount) {}

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            <#-- @ftlvariable name="emitTotalCount" type="boolean" -->
            <#-- @ftlvariable name="epssFrom" type="boolean" -->
            <#-- @ftlvariable name="epssTo" type="boolean" -->
            <#-- @ftlvariable name="isKev" type="boolean" -->
            <#-- @ftlvariable name="includeInactive" type="boolean" -->
            <#-- @ftlvariable name="includeSuppressed" type="boolean" -->
            <#-- @ftlvariable name="source" type="boolean" -->
            <#-- @ftlvariable name="searchText" type="boolean" -->
            SELECT p."UUID" AS "projectUuid"
                 , p."NAME" AS "projectName"
                 , p."VERSION" AS "projectVersion"
                 , c."UUID" AS "componentUuid"
                 , c."NAME" AS "componentName"
                 , c."GROUP" AS "componentGroup"
                 , c."VERSION" AS "componentVersion"
                 , c."PURL" AS "componentPurl"
                 , c."CPE" AS "componentCpe"
                 , c."SCOPE" AS "componentScope"
                 , EXISTS(SELECT 1 FROM "COMPONENT_OCCURRENCE" WHERE "COMPONENT_ID" = c."ID") AS "componentHasOccurrences"
                 , v."UUID" AS "vulnUuid"
                 , v."SOURCE" AS "vulnSource"
                 , v."VULNID"
                 , v."TITLE" AS "vulnTitle"
                 , v."SUBTITLE" AS "vulnSubtitle"
                 , v."DESCRIPTION" AS "vulnDescription"
                 , v."RECOMMENDATION" AS "vulnRecommendation"
                 , v."REFERENCES" AS "vulnReferences"
                 , v."PUBLISHED" AS "vulnPublished"
                 , CASE
                     WHEN a."CVSSV2SCORE" IS NOT NULL OR a."CVSSV2VECTOR" IS NOT NULL
                     THEN a."CVSSV2SCORE"
                     ELSE v."CVSSV2BASESCORE"
                   END AS "cvssV2BaseScore"
                 , CASE
                     WHEN a."CVSSV3SCORE" IS NOT NULL OR a."CVSSV3VECTOR" IS NOT NULL
                     THEN a."CVSSV3SCORE"
                     ELSE v."CVSSV3BASESCORE"
                   END AS "cvssV3BaseScore"
                 , CASE
                     WHEN a."CVSSV4SCORE" IS NOT NULL OR a."CVSSV4VECTOR" IS NOT NULL
                     THEN a."CVSSV4SCORE"
                     ELSE v."CVSSV4SCORE"
                   END AS "cvssV4Score"
                 , CASE
                     WHEN a."CVSSV2SCORE" IS NOT NULL OR a."CVSSV2VECTOR" IS NOT NULL
                     THEN a."CVSSV2VECTOR"
                     ELSE v."CVSSV2VECTOR"
                   END AS "cvssV2Vector"
                 , CASE
                     WHEN a."CVSSV3SCORE" IS NOT NULL OR a."CVSSV3VECTOR" IS NOT NULL
                     THEN a."CVSSV3VECTOR"
                     ELSE v."CVSSV3VECTOR"
                   END AS "cvssV3Vector"
                 , CASE
                     WHEN a."CVSSV4SCORE" IS NOT NULL OR a."CVSSV4VECTOR" IS NOT NULL
                     THEN a."CVSSV4VECTOR"
                     ELSE v."CVSSV4VECTOR"
                   END AS "cvssV4Vector"
                 -- TODO: Analysis only has a single score, but OWASP RR defines multiple.
                 --  How to handle this?
                 , CASE
                     WHEN a."OWASPSCORE" IS NOT NULL OR a."OWASPVECTOR" IS NOT NULL
                     THEN a."OWASPSCORE"
                     ELSE v."OWASPRRBUSINESSIMPACTSCORE"
                   END AS "owaspRRBusinessImpactScore"
                 , CASE
                     WHEN a."OWASPSCORE" IS NOT NULL OR a."OWASPVECTOR" IS NOT NULL
                     THEN a."OWASPSCORE"
                     ELSE v."OWASPRRLIKELIHOODSCORE"
                   END AS "owaspRRLikelihoodScore"
                 , CASE
                     WHEN a."OWASPSCORE" IS NOT NULL OR a."OWASPVECTOR" IS NOT NULL
                     THEN a."OWASPSCORE"
                     ELSE v."OWASPRRTECHNICALIMPACTSCORE"
                   END AS "owaspRRTechnicalImpactScore"
                 , CASE
                     WHEN a."OWASPSCORE" IS NOT NULL OR a."OWASPVECTOR" IS NOT NULL
                     THEN a."OWASPVECTOR"
                     ELSE v."OWASPRRVECTOR"
                   END AS "owaspRRVector"
                 , COALESCE(a."SEVERITY", v."SEVERITY") AS "vulnSeverity"
                 , CAST(STRING_TO_ARRAY(v."CWES", ',') AS INT[]) AS "CWES"
                 , JSONB_VULN_ALIASES(v."SOURCE", v."VULNID") AS "vulnAliasesJson"
                 , e."SCORE" AS "epssScore"
                 , e."PERCENTILE" AS "epssPercentile"
                 , <@sql.isKevColumn vulnSource='v."SOURCE"' vulnId='v."VULNID"'/> AS "kev"
                 , fa."ANALYZERIDENTITY"
                 , fa."ATTRIBUTED_ON"
                 , fa."ALT_ID"
                 , fa."REFERENCE_URL"
                 , fa."MATCHING_PERCENTAGE"
                 , a."STATE" AS "analysisState"
                 , a."SUPPRESSED"
                 , a."DETAILS" AS "analysisDetail"
                 , <#if emitTotalCount>COUNT(*) OVER()<#else>CAST(NULL AS BIGINT)</#if> AS "totalCount"
              FROM "COMPONENT" AS c
             INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
                ON c."ID" = cv."COMPONENT_ID"
             INNER JOIN "VULNERABILITY" AS v
                ON cv."VULNERABILITY_ID" = v."ID"
              LEFT JOIN LATERAL (
                <@sql.epssBestRow vulnSource='v."SOURCE"' vulnId='v."VULNID"'/>
              ) AS e ON TRUE
             INNER JOIN LATERAL (
               SELECT *
                 FROM "FINDINGATTRIBUTION" AS fa
                WHERE c."ID" = fa."COMPONENT_ID"
                  AND v."ID" = fa."VULNERABILITY_ID"
            <#if !includeInactive>
                  AND fa."DELETED_AT" IS NULL
            </#if>
                ORDER BY fa."DELETED_AT" DESC NULLS FIRST
                       , fa."ID"
                LIMIT 1
              ) AS fa ON TRUE
              LEFT JOIN "ANALYSIS" AS a
                ON c."ID" = a."COMPONENT_ID"
               AND v."ID" = a."VULNERABILITY_ID"
               AND c."PROJECT_ID" = a."PROJECT_ID"
              INNER JOIN "PROJECT" AS p
                ON c."PROJECT_ID" = p."ID"
            WHERE c."PROJECT_ID" = :projectId
            <#if source>
               AND v."SOURCE" = :source
            </#if>
            <#if !includeSuppressed>
               AND a."SUPPRESSED" IS DISTINCT FROM TRUE
            </#if>
               AND (:hasAnalysis IS NULL OR (a."ID" IS NOT NULL) = :hasAnalysis)
            <#if epssFrom>
               AND e."SCORE" >= :epssFrom
            </#if>
            <#if epssTo>
               AND e."SCORE" <= :epssTo
            </#if>
            <#if isKev>
               AND <@sql.isKevFilter vulnIdColumn='cv."VULNERABILITY_ID"'/> = :isKev
            </#if>
            <#if searchText>
               AND (
                 LOWER(c."NAME") LIKE ('%' || LOWER(:searchText) || '%') ESCAPE '!'
                 OR LOWER(c."GROUP") LIKE ('%' || LOWER(:searchText) || '%') ESCAPE '!'
                 OR LOWER(v."VULNID") LIKE ('%' || LOWER(:searchText) || '%') ESCAPE '!'
                 OR CAST(v."UUID" AS TEXT) = LOWER(:searchText)
                 OR CAST(c."UUID" AS TEXT) = LOWER(:searchText)
                 OR LOWER(CAST(c."UUID" AS TEXT) || ':' || CAST(v."UUID" AS TEXT)) = LOWER(:searchText)
               )
            </#if>
            <#if apiOrderByClause??>
              ${apiOrderByClause}
            <#else>
             ORDER BY c."ID", v."ID"
            </#if>
             ${apiOffsetLimitClause!}
            """)
    @AllowApiOrdering(
            alwaysBy = @AllowApiOrdering.AlwaysBy(queryName = "c.\"ID\", v.\"ID\""),
            by = {
                @AllowApiOrdering.Column(name = "vulnerability.vulnId", queryName = "v.\"VULNID\""),
                @AllowApiOrdering.Column(name = "vulnerability.severity", queryName = "\"vulnSeverity\""),
                @AllowApiOrdering.Column(name = "vulnerability.cvssV2BaseScore", queryName = "\"cvssV2BaseScore\""),
                @AllowApiOrdering.Column(name = "vulnerability.cvssV3BaseScore", queryName = "\"cvssV3BaseScore\""),
                @AllowApiOrdering.Column(name = "vulnerability.cvssV4Score", queryName = "\"cvssV4Score\""),
                @AllowApiOrdering.Column(name = "vulnerability.epssScore", queryName = "\"epssScore\""),
                @AllowApiOrdering.Column(name = "vulnerability.epssPercentile", queryName = "\"epssPercentile\""),
                @AllowApiOrdering.Column(name = "attribution.analyzerIdentity", queryName = "fa.\"ANALYZERIDENTITY\""),
                @AllowApiOrdering.Column(name = "component.group", queryName = "c.\"GROUP\""),
                @AllowApiOrdering.Column(name = "component.name", queryName = "c.\"NAME\""),
                @AllowApiOrdering.Column(name = "component.version", queryName = "c.\"VERSION\""),
                @AllowApiOrdering.Column(name = "analysis.state", queryName = "a.\"STATE\""),
                @AllowApiOrdering.Column(name = "analysis.isSuppressed", queryName = "a.\"SUPPRESSED\""),
                @AllowApiOrdering.Column(name = "attribution.attributedOn", queryName = "fa.\"ATTRIBUTED_ON\"")
            })
    @DefineNamedBindings
    @RegisterConstructorMapper(FindingRow.class)
    List<FindingRow> selectFindingsByProject(
            @Bind long projectId,
            @Define boolean includeInactive,
            @Define boolean includeSuppressed,
            @Nullable @Bind String searchText,
            @Bind Boolean hasAnalysis,
            @Bind String source,
            @Bind BigDecimal epssFrom,
            @Bind BigDecimal epssTo,
            @Bind Boolean isKev,
            @Define boolean emitTotalCount,
            @Define(ATTRIBUTE_API_PAGINATE) boolean paginate);

    /// Queries the bounded count of findings for a project.
    ///
    /// NB:
    /// * No ACL condition is applied here, since the REST endpoint calling this method enforces access on
    ///   the project object before querying, and the query is naturally scoped to one project.
    /// * The `FROM` / `WHERE` clauses **must** stay in sync with {@link #selectFindingsByProject},
    ///   or the count will drift from the list.
    ///
    /// @return The total count of findings for the project, capped at `threshold + 1`,
    ///         or exact when `threshold` is `null`.
    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="threshold" type="boolean" -->
            <#-- @ftlvariable name="epssFrom" type="boolean" -->
            <#-- @ftlvariable name="epssTo" type="boolean" -->
            <#-- @ftlvariable name="isKev" type="boolean" -->
            <#-- @ftlvariable name="includeInactive" type="boolean" -->
            <#-- @ftlvariable name="includeSuppressed" type="boolean" -->
            <#-- @ftlvariable name="source" type="boolean" -->
            <#-- @ftlvariable name="searchText" type="boolean" -->
            SELECT COUNT(*)
              FROM (
                SELECT 1
                  FROM "COMPONENT" AS c
                 INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
                    ON c."ID" = cv."COMPONENT_ID"
                 INNER JOIN "VULNERABILITY" AS v
                    ON cv."VULNERABILITY_ID" = v."ID"
            <#if epssFrom || epssTo>
                  LEFT JOIN LATERAL (
                    <@sql.epssBestRow vulnSource='v."SOURCE"' vulnId='v."VULNID"'/>
                  ) AS e ON TRUE
            </#if>
                 INNER JOIN LATERAL (
                   SELECT *
                     FROM "FINDINGATTRIBUTION" AS fa
                    WHERE c."ID" = fa."COMPONENT_ID"
                      AND v."ID" = fa."VULNERABILITY_ID"
            <#if !includeInactive>
                      AND fa."DELETED_AT" IS NULL
            </#if>
                    ORDER BY fa."DELETED_AT" DESC NULLS FIRST
                           , fa."ID"
                    LIMIT 1
                  ) AS fa ON TRUE
                  LEFT JOIN "ANALYSIS" AS a
                    ON c."ID" = a."COMPONENT_ID"
                   AND v."ID" = a."VULNERABILITY_ID"
                   AND c."PROJECT_ID" = a."PROJECT_ID"
                 WHERE c."PROJECT_ID" = :projectId
            <#if source>
                   AND v."SOURCE" = :source
            </#if>
            <#if !includeSuppressed>
                   AND a."SUPPRESSED" IS DISTINCT FROM TRUE
            </#if>
                   AND (:hasAnalysis IS NULL OR (a."ID" IS NOT NULL) = :hasAnalysis)
            <#if epssFrom>
                   AND e."SCORE" >= :epssFrom
            </#if>
            <#if epssTo>
                   AND e."SCORE" <= :epssTo
            </#if>
            <#if isKev>
                   AND <@sql.isKevFilter vulnIdColumn='cv."VULNERABILITY_ID"'/> = :isKev
            </#if>
            <#if searchText>
                   AND (
                     LOWER(c."NAME") LIKE ('%' || LOWER(:searchText) || '%') ESCAPE '!'
                     OR LOWER(c."GROUP") LIKE ('%' || LOWER(:searchText) || '%') ESCAPE '!'
                     OR LOWER(v."VULNID") LIKE ('%' || LOWER(:searchText) || '%') ESCAPE '!'
                     OR CAST(v."UUID" AS TEXT) = LOWER(:searchText)
                     OR CAST(c."UUID" AS TEXT) = LOWER(:searchText)
                     OR LOWER(CAST(c."UUID" AS TEXT) || ':' || CAST(v."UUID" AS TEXT)) = LOWER(:searchText)
                   )
            </#if>
            <#if threshold>
                 LIMIT (:threshold + 1)
            </#if>
              ) AS t
            """)
    @DefineNamedBindings
    @AllowUnusedBindings
    long selectFindingsByProjectBoundedCount(
            @Bind long projectId,
            @Define boolean includeInactive,
            @Define boolean includeSuppressed,
            @Nullable @Bind String searchText,
            @Bind Boolean hasAnalysis,
            @Bind String source,
            @Bind BigDecimal epssFrom,
            @Bind BigDecimal epssTo,
            @Bind Boolean isKev,
            @Nullable @Bind Integer threshold);

    /// Queries a project's findings, unpaginated, for export use cases.
    default List<Finding> getFindings(long projectId, boolean includeSuppressed) {
        final List<FindingRow> findingRows = selectAllProjectFindings(
                projectId,
                includeSuppressed,
                /* searchText */ null,
                /* hasAnalysis */ null,
                /* source */ null,
                /* epssFrom */ null,
                /* epssTo */ null,
                /* isKev */ null);
        return mapComponentLatestVersion(findingRows.stream().map(Finding::new).toList());
    }

    /// Queries a project's findings, unpaginated, and without a total count.
    ///
    /// @since 5.1.0
    default List<FindingRow> selectAllProjectFindings(
            long projectId,
            boolean includeSuppressed,
            @Nullable String searchText,
            Boolean hasAnalysis,
            String source,
            BigDecimal epssFrom,
            BigDecimal epssTo,
            Boolean isKev) {
        return withJitDisabled(() -> selectFindingsByProject(
                projectId,
                /* includeInactive */ false,
                includeSuppressed,
                searchText,
                hasAnalysis,
                source,
                epssFrom,
                epssTo,
                isKev,
                // NB: No caller reads the total, so don't pay for the window count.
                /* emitTotalCount */ false,
                /* paginate */ false));
    }

    /// Queries a project's findings as a page.
    ///
    /// @param totalCountThreshold the total count cap, or `null` for an exact count.
    default Page<FindingRow> getFindingsByProject(
            long projectId,
            boolean includeSuppressed,
            @Nullable String searchText,
            Boolean hasAnalysis,
            String source,
            BigDecimal epssFrom,
            BigDecimal epssTo,
            Boolean isKev,
            @Nullable Integer totalCountThreshold) {
        return withJitDisabled(() -> {
            final List<FindingRow> rows = selectFindingsByProject(
                    projectId,
                    /* includeInactive */ false,
                    includeSuppressed,
                    searchText,
                    hasAnalysis,
                    source,
                    epssFrom,
                    epssTo,
                    isKev,
                    /* emitTotalCount */ totalCountThreshold == null,
                    /* paginate */ true);
            final LongSupplier countQuery = () -> selectFindingsByProjectBoundedCount(
                    projectId,
                    /* includeInactive */ false,
                    includeSuppressed,
                    searchText,
                    hasAnalysis,
                    source,
                    epssFrom,
                    epssTo,
                    isKev,
                    totalCountThreshold);
            if (totalCountThreshold == null) {
                return new Page<>(rows).withTotalCount(exactTotalCount(rows, FindingRow::totalCount, countQuery));
            }

            return new Page<>(rows)
                    .withTotalCount(boundedTotalCountOrAtLeast(
                            countQuery, totalCountThreshold, /* returnedItems */ rows.size()));
        });
    }

    /// Queries all findings across the entire portfolio.
    ///
    /// The query is split into:
    /// * an inner `page` CTE that resolves only the row identity, plus the columns needed
    ///   for filtering and ordering
    /// * an outer `SELECT` that enriches just the paginated rows with the expensive columns (e.g. aliases, EPSS)
    ///
    /// This keeps `COUNT(*) OVER()` and all enrichment off the full, pre-pagination row set.
    ///
    /// EPSS is only resolved before pagination when needed. An EPSS score filter is pushed down as an `EXISTS`,
    /// while EPSS ordering or an EPSS percentile filter joins a per-vulnerability `epss_dedup` CTE.
    /// Otherwise, EPSS is resolved only during enrichment of the paginated rows.
    ///
    /// NB: every `queryName` in [AllowApiOrdering] must resolve in **both** the inner `page` CTE **and**
    /// the outer `SELECT`, because the ordering clause is applied at both levels.
    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="queryFilter" type="String" -->
            <#-- @ftlvariable name="activeFilter" type="Boolean" -->
            <#-- @ftlvariable name="includeInactiveFindings" type="Boolean" -->
            <#-- @ftlvariable name="suppressedFilter" type="Boolean" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            <#-- @ftlvariable name="epssInPage" type="boolean" -->
            <#-- @ftlvariable name="epssScoreFrom" type="boolean" -->
            <#-- @ftlvariable name="epssScoreTo" type="boolean" -->
            <#-- @ftlvariable name="isKev" type="boolean" -->
            <#-- @ftlvariable name="emitTotalCount" type="boolean" -->
            WITH
            <#if epssInPage>
            <@sql.epssDedup/>,
            </#if>
            page AS (
              SELECT c."ID" AS "componentId"
                   , v."ID" AS "vulnerabilityId"
                   , COALESCE(a."SEVERITY", v."SEVERITY") AS "vulnSeverity"
                   , CASE
                       WHEN a."CVSSV2SCORE" IS NOT NULL OR a."CVSSV2VECTOR" IS NOT NULL
                       THEN a."CVSSV2SCORE"
                       ELSE v."CVSSV2BASESCORE"
                     END AS "cvssV2BaseScore"
                   , CASE
                       WHEN a."CVSSV3SCORE" IS NOT NULL OR a."CVSSV3VECTOR" IS NOT NULL
                       THEN a."CVSSV3SCORE"
                       ELSE v."CVSSV3BASESCORE"
                     END AS "cvssV3BaseScore"
                   , CASE
                       WHEN a."CVSSV4SCORE" IS NOT NULL OR a."CVSSV4VECTOR" IS NOT NULL
                       THEN a."CVSSV4SCORE"
                       ELSE v."CVSSV4SCORE"
                     END AS "cvssV4Score"
            <#if epssInPage>
                   , ed."SCORE" AS "epssScore"
                   , ed."PERCENTILE" AS "epssPercentile"
            </#if>
                   , <#if emitTotalCount>COUNT(*) OVER()<#else>CAST(NULL AS BIGINT)</#if> AS "totalCount"
                FROM "COMPONENT" AS c
               INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
                  ON c."ID" = cv."COMPONENT_ID"
               INNER JOIN "VULNERABILITY" AS v
                  ON cv."VULNERABILITY_ID" = v."ID"
               INNER JOIN LATERAL (
                 SELECT *
                   FROM "FINDINGATTRIBUTION" AS fa
                  WHERE c."ID" = fa."COMPONENT_ID"
                    AND v."ID" = fa."VULNERABILITY_ID"
            <#if !includeInactiveFindings>
                    AND fa."DELETED_AT" IS NULL
            </#if>
                  ORDER BY fa."DELETED_AT" DESC NULLS FIRST
                         , fa."ID"
                  LIMIT 1
               ) AS fa ON TRUE
            <#if epssInPage>
                LEFT JOIN epss_dedup AS ed
                  ON ed."vulnerabilityId" = v."ID"
            </#if>
                LEFT JOIN "ANALYSIS" AS a
                  ON c."ID" = a."COMPONENT_ID"
                 AND v."ID" = a."VULNERABILITY_ID"
                 AND c."PROJECT_ID" = a."PROJECT_ID"
               INNER JOIN "PROJECT" AS p
                  ON c."PROJECT_ID" = p."ID"
               WHERE ${apiProjectAclCondition}
            <#if !activeFilter>
                 AND p."INACTIVE_SINCE" IS NULL
            </#if>
            <#if !suppressedFilter>
                 AND a."SUPPRESSED" IS DISTINCT FROM TRUE
            </#if>
            <#if epssScoreFrom || epssScoreTo>
                 AND EXISTS (
                   SELECT 1
                     FROM (
                       <@sql.epssCandidates vulnSource='v."SOURCE"' vulnId='v."VULNID"'/>
                     ) AS candidates
                   HAVING
            <#if epssScoreFrom>
                     MAX(candidates."SCORE") >= :epssScoreFrom
            </#if>
            <#if epssScoreFrom && epssScoreTo>
                     AND
            </#if>
            <#if epssScoreTo>
                     MAX(candidates."SCORE") <= :epssScoreTo
            </#if>
                 )
            </#if>
            <#if queryFilter??>
                 ${queryFilter}
            </#if>
            <#if isKev>
                 AND <@sql.isKevFilter vulnIdColumn='cv."VULNERABILITY_ID"'/> = :isKev
            </#if>
            <#if apiOrderByClause??>
               ${apiOrderByClause}
            <#else>
               ORDER BY c."ID", v."ID"
            </#if>
               ${apiOffsetLimitClause!}
            )
            SELECT p."UUID" AS "projectUuid"
                 , p."NAME" AS "projectName"
                 , p."VERSION" AS "projectVersion"
                 , c."UUID" AS "componentUuid"
                 , c."NAME" AS "componentName"
                 , c."GROUP" AS "componentGroup"
                 , c."VERSION" AS "componentVersion"
                 , c."PURL" AS "componentPurl"
                 , c."CPE" AS "componentCpe"
                 , c."SCOPE" AS "componentScope"
                 , EXISTS(SELECT 1 FROM "COMPONENT_OCCURRENCE" WHERE "COMPONENT_ID" = c."ID") AS "componentHasOccurrences"
                 , v."UUID" AS "vulnUuid"
                 , v."SOURCE" AS "vulnSource"
                 , v."VULNID"
                 , v."TITLE" AS "vulnTitle"
                 , v."SUBTITLE" AS "vulnSubtitle"
                 , v."DESCRIPTION" AS "vulnDescription"
                 , v."RECOMMENDATION" AS "vulnRecommendation"
                 , v."REFERENCES" AS "vulnReferences"
                 , v."PUBLISHED" AS "vulnPublished"
                 , CASE
                     WHEN a."CVSSV2SCORE" IS NOT NULL OR a."CVSSV2VECTOR" IS NOT NULL
                     THEN a."CVSSV2SCORE"
                     ELSE v."CVSSV2BASESCORE"
                   END AS "cvssV2BaseScore"
                 , CASE
                     WHEN a."CVSSV3SCORE" IS NOT NULL OR a."CVSSV3VECTOR" IS NOT NULL
                     THEN a."CVSSV3SCORE"
                     ELSE v."CVSSV3BASESCORE"
                   END AS "cvssV3BaseScore"
                 , CASE
                     WHEN a."CVSSV4SCORE" IS NOT NULL OR a."CVSSV4VECTOR" IS NOT NULL
                     THEN a."CVSSV4SCORE"
                     ELSE v."CVSSV4SCORE"
                   END AS "cvssV4Score"
                 , CASE
                     WHEN a."CVSSV2SCORE" IS NOT NULL OR a."CVSSV2VECTOR" IS NOT NULL
                     THEN a."CVSSV2VECTOR"
                     ELSE v."CVSSV2VECTOR"
                   END AS "cvssV2Vector"
                 , CASE
                     WHEN a."CVSSV3SCORE" IS NOT NULL OR a."CVSSV3VECTOR" IS NOT NULL
                     THEN a."CVSSV3VECTOR"
                     ELSE v."CVSSV3VECTOR"
                   END AS "cvssV3Vector"
                 , CASE
                     WHEN a."CVSSV4SCORE" IS NOT NULL OR a."CVSSV4VECTOR" IS NOT NULL
                     THEN a."CVSSV4VECTOR"
                     ELSE v."CVSSV4VECTOR"
                   END AS "cvssV4Vector"
                 -- TODO: Analysis only has a single score, but OWASP RR defines multiple.
                 --  How to handle this?
                 , CASE
                     WHEN a."OWASPSCORE" IS NOT NULL OR a."OWASPVECTOR" IS NOT NULL
                     THEN a."OWASPSCORE"
                     ELSE v."OWASPRRBUSINESSIMPACTSCORE"
                   END AS "owaspRRBusinessImpactScore"
                 , CASE
                     WHEN a."OWASPSCORE" IS NOT NULL OR a."OWASPVECTOR" IS NOT NULL
                     THEN a."OWASPSCORE"
                     ELSE v."OWASPRRLIKELIHOODSCORE"
                   END AS "owaspRRLikelihoodScore"
                 , CASE
                     WHEN a."OWASPSCORE" IS NOT NULL OR a."OWASPVECTOR" IS NOT NULL
                     THEN a."OWASPSCORE"
                     ELSE v."OWASPRRTECHNICALIMPACTSCORE"
                   END AS "owaspRRTechnicalImpactScore"
                 , CASE
                     WHEN a."OWASPSCORE" IS NOT NULL OR a."OWASPVECTOR" IS NOT NULL
                     THEN a."OWASPVECTOR"
                     ELSE v."OWASPRRVECTOR"
                   END AS "owaspRRVector"
                 , COALESCE(a."SEVERITY", v."SEVERITY") AS "vulnSeverity"
                 , CAST(STRING_TO_ARRAY(v."CWES", ',') AS INT[]) AS "CWES"
                 , JSONB_VULN_ALIASES(v."SOURCE", v."VULNID") AS "vulnAliasesJson"
            <#if epssInPage>
                 , page."epssScore"
                 , page."epssPercentile"
            <#else>
                 , ep."SCORE" AS "epssScore"
                 , ep."PERCENTILE" AS "epssPercentile"
            </#if>
                 , <@sql.isKevColumn vulnSource='v."SOURCE"' vulnId='v."VULNID"'/> AS "kev"
                 , fa."ANALYZERIDENTITY"
                 , fa."ATTRIBUTED_ON"
                 , fa."ALT_ID"
                 , fa."REFERENCE_URL"
                 , fa."MATCHING_PERCENTAGE"
                 , a."STATE" AS "analysisState"
                 , a."SUPPRESSED"
                 , a."DETAILS" AS "analysisDetail"
                 , page."totalCount"
              FROM page
             INNER JOIN "COMPONENT" AS c
                ON c."ID" = page."componentId"
             INNER JOIN "VULNERABILITY" AS v
                ON v."ID" = page."vulnerabilityId"
             INNER JOIN "PROJECT" AS p
                ON c."PROJECT_ID" = p."ID"
              LEFT JOIN "ANALYSIS" AS a
                ON c."ID" = a."COMPONENT_ID"
               AND v."ID" = a."VULNERABILITY_ID"
               AND c."PROJECT_ID" = a."PROJECT_ID"
             INNER JOIN LATERAL (
               SELECT *
                 FROM "FINDINGATTRIBUTION" AS fa
                WHERE c."ID" = fa."COMPONENT_ID"
                  AND v."ID" = fa."VULNERABILITY_ID"
            <#if !includeInactiveFindings>
                  AND fa."DELETED_AT" IS NULL
            </#if>
                ORDER BY fa."DELETED_AT" DESC NULLS FIRST
                       , fa."ID"
                LIMIT 1
             ) AS fa ON TRUE
            <#if !epssInPage>
              LEFT JOIN LATERAL (
                <@sql.epssBestRow vulnSource='v."SOURCE"' vulnId='v."VULNID"'/>
              ) AS ep ON TRUE
            </#if>
            <#if apiOrderByClause??>
              ${apiOrderByClause}
            <#else>
              ORDER BY c."ID", v."ID"
            </#if>
            """)
    @AllowApiOrdering(
            alwaysBy = @AllowApiOrdering.AlwaysBy(queryName = "c.\"ID\", v.\"ID\""),
            by = {
                @AllowApiOrdering.Column(name = "vulnerability.title", queryName = "v.\"TITLE\""),
                @AllowApiOrdering.Column(name = "vulnerability.vulnId", queryName = "v.\"VULNID\""),
                @AllowApiOrdering.Column(name = "vulnerability.severity", queryName = "\"vulnSeverity\""),
                @AllowApiOrdering.Column(name = "vulnerability.cvssV4Score", queryName = "\"cvssV4Score\""),
                @AllowApiOrdering.Column(name = "vulnerability.cvssV3BaseScore", queryName = "\"cvssV3BaseScore\""),
                @AllowApiOrdering.Column(name = "vulnerability.cvssV2BaseScore", queryName = "\"cvssV2BaseScore\""),
                @AllowApiOrdering.Column(name = "vulnerability.epssScore", queryName = "\"epssScore\""),
                @AllowApiOrdering.Column(name = "vulnerability.epssPercentile", queryName = "\"epssPercentile\""),
                @AllowApiOrdering.Column(name = "vulnerability.published", queryName = "v.\"PUBLISHED\""),
                @AllowApiOrdering.Column(name = "attribution.analyzerIdentity", queryName = "fa.\"ANALYZERIDENTITY\""),
                @AllowApiOrdering.Column(
                        name = "component.projectName",
                        queryName = "concat(p.\"NAME\", ' ', p.\"VERSION\")"),
                @AllowApiOrdering.Column(name = "component.name", queryName = "c.\"NAME\""),
                @AllowApiOrdering.Column(name = "component.version", queryName = "c.\"VERSION\""),
                @AllowApiOrdering.Column(name = "analysis.state", queryName = "a.\"STATE\""),
                @AllowApiOrdering.Column(name = "analysis.isSuppressed", queryName = "a.\"SUPPRESSED\""),
                @AllowApiOrdering.Column(name = "attribution.attributedOn", queryName = "fa.\"ATTRIBUTED_ON\"")
            })
    @DefineNamedBindings
    @AllowUnusedBindings
    @DefineApiProjectAclCondition(projectIdColumn = "p.\"ID\"")
    @RegisterConstructorMapper(FindingRow.class)
    List<FindingRow> selectAllFindings(
            @Define String queryFilter,
            @Define boolean activeFilter,
            @Define boolean includeInactiveFindings,
            @Define boolean suppressedFilter,
            @Define boolean epssInPage,
            @Bind BigDecimal epssScoreFrom,
            @Bind BigDecimal epssScoreTo,
            @Nullable @Bind Boolean isKev,
            @BindMap Map<String, Object> params,
            @Define boolean emitTotalCount);

    /// Queries the bounded count of all findings across the entire portfolio.
    ///
    /// NB:
    /// * The `epss_dedup` join is included only when `queryFilter` may reference the `ed` alias,
    ///   i.e. for EPSS percentile filters. The join does not change which rows match.
    ///   Notably, it is *not* included for an EPSS sort, unlike in {@link #selectAllFindings},
    ///   because a count has no `ORDER BY`. Including it makes Postgres drive the count from
    ///   the vulnerability side. The `EPSS` and `VULNERABILITY_ALIAS` pages are the least likely
    ///   to be cached, so a fast count becomes a slow one.
    /// * The `FROM` / `WHERE` clauses **must** stay in sync with {@link #selectAllFindings},
    ///   or the count will drift from the list.
    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            <#-- @ftlvariable name="queryFilter" type="String" -->
            <#-- @ftlvariable name="activeFilter" type="Boolean" -->
            <#-- @ftlvariable name="includeInactiveFindings" type="Boolean" -->
            <#-- @ftlvariable name="suppressedFilter" type="Boolean" -->
            <#-- @ftlvariable name="epssDedupJoin" type="boolean" -->
            <#-- @ftlvariable name="epssScoreFrom" type="boolean" -->
            <#-- @ftlvariable name="epssScoreTo" type="boolean" -->
            <#-- @ftlvariable name="isKev" type="boolean" -->
            <#-- @ftlvariable name="threshold" type="boolean" -->
            <#if epssDedupJoin>
            WITH
            <@sql.epssDedup/>
            </#if>
            SELECT COUNT(*)
              FROM (
                SELECT 1
                  FROM "COMPONENT" AS c
                 INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
                    ON c."ID" = cv."COMPONENT_ID"
                 INNER JOIN "VULNERABILITY" AS v
                    ON cv."VULNERABILITY_ID" = v."ID"
                 INNER JOIN LATERAL (
                   SELECT *
                     FROM "FINDINGATTRIBUTION" AS fa
                    WHERE c."ID" = fa."COMPONENT_ID"
                      AND v."ID" = fa."VULNERABILITY_ID"
            <#if !includeInactiveFindings>
                      AND fa."DELETED_AT" IS NULL
            </#if>
                    ORDER BY fa."DELETED_AT" DESC NULLS FIRST
                           , fa."ID"
                    LIMIT 1
                  ) AS fa ON TRUE
            <#if epssDedupJoin>
                  LEFT JOIN epss_dedup AS ed
                    ON ed."vulnerabilityId" = v."ID"
            </#if>
                  LEFT JOIN "ANALYSIS" AS a
                    ON c."ID" = a."COMPONENT_ID"
                   AND v."ID" = a."VULNERABILITY_ID"
                   AND c."PROJECT_ID" = a."PROJECT_ID"
                 INNER JOIN "PROJECT" AS p
                    ON c."PROJECT_ID" = p."ID"
                 WHERE ${apiProjectAclCondition}
            <#if !activeFilter>
                   AND p."INACTIVE_SINCE" IS NULL
            </#if>
            <#if !suppressedFilter>
                   AND a."SUPPRESSED" IS DISTINCT FROM TRUE
            </#if>
            <#if epssScoreFrom || epssScoreTo>
                   AND EXISTS (
                     SELECT 1
                       FROM (
                         <@sql.epssCandidates vulnSource='v."SOURCE"' vulnId='v."VULNID"'/>
                       ) AS candidates
                     HAVING
            <#if epssScoreFrom>
                       MAX(candidates."SCORE") >= :epssScoreFrom
            </#if>
            <#if epssScoreFrom && epssScoreTo>
                       AND
            </#if>
            <#if epssScoreTo>
                       MAX(candidates."SCORE") <= :epssScoreTo
            </#if>
                   )
            </#if>
            <#if queryFilter??>
                   ${queryFilter}
            </#if>
            <#if isKev>
                   AND <@sql.isKevFilter vulnIdColumn='cv."VULNERABILITY_ID"'/> = :isKev
            </#if>
            <#if threshold>
                 LIMIT (:threshold + 1)
            </#if>
              ) AS t
            """)
    @DefineNamedBindings
    @AllowUnusedBindings
    @DefineApiProjectAclCondition(projectIdColumn = "p.\"ID\"")
    long selectAllFindingsBoundedCount(
            @Define String queryFilter,
            @Define boolean activeFilter,
            @Define boolean includeInactiveFindings,
            @Define boolean suppressedFilter,
            @Define boolean epssDedupJoin,
            @Bind BigDecimal epssScoreFrom,
            @Bind BigDecimal epssScoreTo,
            @Nullable @Bind Boolean isKev,
            @Nullable @Bind Integer threshold,
            @BindMap Map<String, Object> params);

    /**
     * Returns a page of all findings filtered by ACL and other optional filters.
     *
     * @param filters             the filters to apply
     * @param showSuppressed      whether to include suppressed vulnerabilities
     * @param showInactive        whether to include inactive projects
     * @param orderBy             the requested ordering field, or {@code null} for the default ordering
     * @param totalCountThreshold the count cap, or {@code null} for an exact count
     * @return the matching findings and their {@link TotalCount}
     */
    default Page<FindingRow> getAllFindings(
            Map<String, String> filters,
            boolean showSuppressed,
            boolean showInactive,
            @Nullable String orderBy,
            @Nullable Integer totalCountThreshold) {
        final StringBuilder queryFilter = new StringBuilder();
        final Map<String, Object> params = new HashMap<>();

        final boolean isEpssOrdering =
                "vulnerability.epssScore".equals(orderBy) || "vulnerability.epssPercentile".equals(orderBy);
        final boolean isEpssPercentileFiltered =
                hasValue(filters, "epssPercentileFrom") || hasValue(filters, "epssPercentileTo");
        final boolean isEpssInPage = isEpssOrdering || isEpssPercentileFiltered;
        processFilters(filters, queryFilter, params, /* epssScoreViaExists */ true);

        final BigDecimal epssScoreFrom = maybeParseDecimal(filters.get("epssFrom"));
        final BigDecimal epssScoreTo = maybeParseDecimal(filters.get("epssTo"));
        final Boolean isKev = maybeParseBoolean(filters.get("isKev"));
        final String renderedQueryFilter = String.valueOf(queryFilter);

        return withJitDisabled(() -> {
            final List<FindingRow> rows = selectAllFindings(
                    renderedQueryFilter,
                    showInactive,
                    /* includeInactiveFindings */ false,
                    showSuppressed,
                    isEpssInPage,
                    epssScoreFrom,
                    epssScoreTo,
                    isKev,
                    params,
                    /* emitTotalCount */ totalCountThreshold == null);
            final LongSupplier countQuery = () -> selectAllFindingsBoundedCount(
                    renderedQueryFilter,
                    showInactive,
                    /* includeInactiveFindings */ false,
                    showSuppressed,
                    /* epssDedupJoin */ isEpssPercentileFiltered,
                    epssScoreFrom,
                    epssScoreTo,
                    isKev,
                    totalCountThreshold,
                    params);
            if (totalCountThreshold == null) {
                return new Page<>(rows).withTotalCount(exactTotalCount(rows, FindingRow::totalCount, countQuery));
            }

            return new Page<>(rows)
                    .withTotalCount(boundedTotalCountOrAtLeast(
                            countQuery, totalCountThreshold, /* returnedItems */ rows.size()));
        });
    }

    /// Queries all findings in the portfolio, grouped by vulnerability.
    ///
    /// NB: EPSS is resolved once per distinct vulnerability via the `epss_dedup` CTE rather
    /// than per finding, since the result is grouped by vulnerability anyway.
    /// EPSS score and percentile values are functionally dependent on the vulnerability but,
    /// since they're being sourced from a join, **must** remain in the `GROUP BY`.
    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="activeFilter" type="Boolean" -->
            <#-- @ftlvariable name="includeInactiveFindings" type="Boolean" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            <#-- @ftlvariable name="isKev" type="boolean" -->
            <#-- @ftlvariable name="emitTotalCount" type="boolean" -->
            WITH
            <@sql.epssDedup/>
            SELECT v."SOURCE" AS "vulnSource"
                 , v."VULNID"
                 , v."TITLE" AS "vulnTitle"
                 , COALESCE(a."SEVERITY", v."SEVERITY") AS "vulnSeverity"
                 , CASE
                     WHEN a."CVSSV2SCORE" IS NOT NULL OR a."CVSSV2VECTOR" IS NOT NULL
                     THEN a."CVSSV2SCORE"
                     ELSE v."CVSSV2BASESCORE"
                   END AS "cvssV2BaseScore"
                 , CASE
                     WHEN a."CVSSV3SCORE" IS NOT NULL OR a."CVSSV3VECTOR" IS NOT NULL
                     THEN a."CVSSV3SCORE"
                     ELSE v."CVSSV3BASESCORE"
                   END AS "cvssV3BaseScore"
                 , CASE
                     WHEN a."CVSSV4SCORE" IS NOT NULL OR a."CVSSV4VECTOR" IS NOT NULL
                     THEN a."CVSSV4SCORE"
                     ELSE v."CVSSV4SCORE"
                   END AS "cvssV4Score"
                 , ed."SCORE" AS "epssScore"
                 , ed."PERCENTILE" AS "epssPercentile"
                 , <@sql.isKevColumn vulnSource='v."SOURCE"' vulnId='v."VULNID"'/> AS "kev"
                 , v."PUBLISHED" AS "vulnPublished"
                 , CAST(STRING_TO_ARRAY(v."CWES", ',') AS INT[]) AS "CWES"
                 , fa."ANALYZERIDENTITY"
                 , COUNT(DISTINCT p."ID") AS "affectedProjectCount"
                 , <#if emitTotalCount>COUNT(*) OVER()<#else>CAST(NULL AS BIGINT)</#if> AS "totalCount"
              FROM "COMPONENT" AS c
             INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
                ON c."ID" = cv."COMPONENT_ID"
             INNER JOIN "VULNERABILITY" AS v
                ON cv."VULNERABILITY_ID" = v."ID"
             INNER JOIN LATERAL (
               SELECT *
                 FROM "FINDINGATTRIBUTION" AS fa
                WHERE c."ID" = fa."COMPONENT_ID"
                  AND v."ID" = fa."VULNERABILITY_ID"
            <#if !includeInactiveFindings>
                  AND fa."DELETED_AT" IS NULL
            </#if>
                ORDER BY fa."DELETED_AT" DESC NULLS FIRST
                       , fa."ID"
                LIMIT 1
             ) AS fa ON TRUE
              LEFT JOIN epss_dedup AS ed
                ON ed."vulnerabilityId" = v."ID"
              LEFT JOIN "ANALYSIS" AS a
                ON c."ID" = a."COMPONENT_ID"
               AND v."ID" = a."VULNERABILITY_ID"
               AND c."PROJECT_ID" = a."PROJECT_ID"
             INNER JOIN "PROJECT" AS p
                ON c."PROJECT_ID" = p."ID"
            WHERE ${apiProjectAclCondition}
            <#if !activeFilter>
                AND p."INACTIVE_SINCE" IS NULL
            </#if>
            <#if queryFilter??>
                ${queryFilter}
            </#if>
            <#if isKev>
                AND <@sql.isKevFilter vulnIdColumn='cv."VULNERABILITY_ID"'/> = :isKev
            </#if>
            GROUP BY v."ID"
                  , v."SOURCE"
                  , v."VULNID"
                  , v."TITLE"
                  , "vulnSeverity"
                  , "cvssV2BaseScore"
                  , "cvssV3BaseScore"
                  , "cvssV4Score"
                  , ed."SCORE"
                  , ed."PERCENTILE"
                  , fa."ANALYZERIDENTITY"
                  , v."PUBLISHED"
                  , v."CWES"
            <#if aggregateFilter??>
                ${aggregateFilter}
            </#if>
            <#if apiOrderByClause??>
              ${apiOrderByClause}
            <#else>
              ORDER BY v."ID"
            </#if>
            ${apiOffsetLimitClause!}
            """)
    @AllowApiOrdering(
            alwaysBy = @AllowApiOrdering.AlwaysBy(queryName = "v.\"ID\""),
            by = {
                @AllowApiOrdering.Column(name = "vulnerability.vulnId", queryName = "v.\"VULNID\""),
                @AllowApiOrdering.Column(name = "vulnerability.title", queryName = "v.\"TITLE\""),
                @AllowApiOrdering.Column(name = "vulnerability.severity", queryName = "\"vulnSeverity\""),
                @AllowApiOrdering.Column(name = "vulnerability.cvssV4Score", queryName = "\"cvssV4Score\""),
                @AllowApiOrdering.Column(name = "vulnerability.cvssV3BaseScore", queryName = "\"cvssV3BaseScore\""),
                @AllowApiOrdering.Column(name = "vulnerability.cvssV2BaseScore", queryName = "\"cvssV2BaseScore\""),
                @AllowApiOrdering.Column(name = "vulnerability.published", queryName = "v.\"PUBLISHED\""),
                @AllowApiOrdering.Column(name = "attribution.analyzerIdentity", queryName = "fa.\"ANALYZERIDENTITY\""),
                @AllowApiOrdering.Column(
                        name = "vulnerability.affectedProjectCount",
                        queryName = "COUNT(DISTINCT p.\"ID\")")
            })
    @AllowUnusedBindings
    @DefineNamedBindings
    @DefineApiProjectAclCondition(projectIdColumn = "p.\"ID\"")
    @RegisterConstructorMapper(GroupedFindingRow.class)
    List<GroupedFindingRow> selectGroupedFindings(
            @Define String queryFilter,
            @Define boolean activeFilter,
            @Define boolean includeInactiveFindings,
            @Define String aggregateFilter,
            @Nullable @Bind Boolean isKev,
            @BindMap Map<String, Object> params,
            @Define boolean emitTotalCount);

    /**
     * Returns a page of all findings filtered by ACL and other optional filters, grouped by vulnerability.
     *
     * @param filters           the filters to apply
     * @param showInactive      whether to include inactive projects
     * @param boundedTotalCount whether to skip the count and report what the page proves
     * @return the matching grouped findings and their {@link TotalCount}
     */
    default Page<GroupedFindingRow> getGroupedFindings(
            Map<String, String> filters, boolean showInactive, boolean boundedTotalCount) {
        final StringBuilder queryFilter = new StringBuilder();
        final Map<String, Object> params = new HashMap<>();

        processFilters(filters, queryFilter, params, /* epssScoreViaExists */ false);
        final StringBuilder aggregateFilter = new StringBuilder();
        processAggregateFilters(filters, aggregateFilter, params);
        final Boolean isKev = maybeParseBoolean(filters.get("isKev"));
        final String renderedQueryFilter = String.valueOf(queryFilter);
        final String renderedAggregateFilter = String.valueOf(aggregateFilter);

        return withJitDisabled(() -> {
            final List<GroupedFindingRow> rows = selectGroupedFindings(
                    renderedQueryFilter,
                    showInactive,
                    /* includeInactiveFindings */ false,
                    renderedAggregateFilter,
                    isKev,
                    params,
                    /* emitTotalCount */ !boundedTotalCount);
            if (boundedTotalCount || rows.isEmpty()) {
                return new Page<>(rows).withTotalCount(pageDerivedTotalCount(rows.size()));
            }

            return new Page<>(rows)
                    .withTotalCount(
                            requireNonNull(
                                    rows.getFirst().totalCount(),
                                    "totalCount must not be null when the window count was requested"),
                            TotalCount.Type.EXACT);
        });
    }

    private void processFilters(
            Map<String, String> filters,
            StringBuilder queryFilter,
            Map<String, Object> params,
            boolean epssScoreViaExists) {
        for (String filter : filters.keySet()) {
            switch (filter) {
                case "severity" ->
                    processArrayFilter(queryFilter, params, filter, filters.get(filter), "v.\"SEVERITY\"");
                case "analysisStatus" ->
                    processArrayFilter(queryFilter, params, filter, filters.get(filter), "a.\"STATE\"");
                case "vendorResponse" ->
                    processArrayFilter(queryFilter, params, filter, filters.get(filter), "a.\"RESPONSE\"");
                case "publishDateFrom" ->
                    processRangeFilter(
                            queryFilter, params, filter, filters.get(filter), "v.\"PUBLISHED\"", true, true, false);
                case "publishDateTo" ->
                    processRangeFilter(
                            queryFilter, params, filter, filters.get(filter), "v.\"PUBLISHED\"", false, true, false);
                case "attributedOnDateFrom" ->
                    processRangeFilter(
                            queryFilter,
                            params,
                            filter,
                            filters.get(filter),
                            "fa.\"ATTRIBUTED_ON\"",
                            true,
                            true,
                            false);
                case "attributedOnDateTo" ->
                    processRangeFilter(
                            queryFilter,
                            params,
                            filter,
                            filters.get(filter),
                            "fa.\"ATTRIBUTED_ON\"",
                            false,
                            true,
                            false);
                case "textSearchField" ->
                    processInputFilter(
                            queryFilter, params, filter, filters.get(filter), filters.get("textSearchInput"));
                case "cvssv2From" ->
                    processRangeFilter(
                            queryFilter,
                            params,
                            filter,
                            filters.get(filter),
                            "v.\"CVSSV2BASESCORE\"",
                            true,
                            false,
                            false);
                case "cvssv2To" ->
                    processRangeFilter(
                            queryFilter,
                            params,
                            filter,
                            filters.get(filter),
                            "v.\"CVSSV2BASESCORE\"",
                            false,
                            false,
                            false);
                case "cvssv3From" ->
                    processRangeFilter(
                            queryFilter,
                            params,
                            filter,
                            filters.get(filter),
                            "v.\"CVSSV3BASESCORE\"",
                            true,
                            false,
                            false);
                case "cvssv3To" ->
                    processRangeFilter(
                            queryFilter,
                            params,
                            filter,
                            filters.get(filter),
                            "v.\"CVSSV3BASESCORE\"",
                            false,
                            false,
                            false);
                case "cvssv4From" ->
                    processRangeFilter(
                            queryFilter, params, filter, filters.get(filter), "v.\"CVSSV4SCORE\"", true, false, false);
                case "cvssv4To" ->
                    processRangeFilter(
                            queryFilter, params, filter, filters.get(filter), "v.\"CVSSV4SCORE\"", false, false, false);
                case "epssFrom" -> {
                    if (!epssScoreViaExists) {
                        processRangeFilter(
                                queryFilter, params, filter, filters.get(filter), "ed.\"SCORE\"", true, false, false);
                    }
                }
                case "epssTo" -> {
                    if (!epssScoreViaExists) {
                        processRangeFilter(
                                queryFilter, params, filter, filters.get(filter), "ed.\"SCORE\"", false, false, false);
                    }
                }
                case "epssPercentileFrom" ->
                    processRangeFilter(
                            queryFilter, params, filter, filters.get(filter), "ed.\"PERCENTILE\"", true, false, false);
                case "epssPercentileTo" ->
                    processRangeFilter(
                            queryFilter, params, filter, filters.get(filter), "ed.\"PERCENTILE\"", false, false, false);
                // NB: isKev is applied directly in the query templates via the shared
                // <@sql.isKevFilter/> macro, not as a queryFilter fragment.
            }
        }
    }

    private void processAggregateFilters(
            Map<String, String> filters, StringBuilder queryFilter, Map<String, Object> params) {
        for (String filter : filters.keySet()) {
            switch (filter) {
                case "occurrencesFrom" ->
                    processRangeFilter(
                            queryFilter,
                            params,
                            filter,
                            filters.get(filter),
                            "COUNT(DISTINCT p.\"ID\")",
                            true,
                            false,
                            true);
                case "occurrencesTo" ->
                    processRangeFilter(
                            queryFilter,
                            params,
                            filter,
                            filters.get(filter),
                            "COUNT(DISTINCT p.\"ID\")",
                            false,
                            false,
                            true);
            }
        }
    }

    private void processArrayFilter(
            StringBuilder queryFilter, Map<String, Object> params, String paramName, String filter, String column) {
        if (filter != null && !filter.isEmpty()) {
            queryFilter.append(" AND (");
            String[] filters = filter.split(",");
            for (int i = 0, length = filters.length; i < length; i++) {
                queryFilter.append(column).append(" = :").append(paramName).append(i);
                if (paramName.equals("severity")) {
                    queryFilter.append("::SEVERITY");
                }
                params.put(paramName + i, filters[i].toUpperCase());
                if (filters[i].equals("NOT_SET")
                        && (paramName.equals("analysisStatus") || paramName.equals("vendorResponse"))) {
                    queryFilter.append(" OR ").append(column).append(" IS NULL");
                }
                if (i < length - 1) {
                    queryFilter.append(" OR ");
                }
            }
            queryFilter.append(")");
        }
    }

    private void processRangeFilter(
            StringBuilder queryFilter,
            Map<String, Object> params,
            String paramName,
            String filter,
            String column,
            boolean fromValue,
            boolean isDate,
            boolean isAggregateFilter) {
        if (filter != null && !filter.isEmpty()) {
            if (queryFilter.isEmpty()) {
                queryFilter.append(isAggregateFilter ? " HAVING (" : " AND (");
            } else {
                queryFilter.append(" AND (");
            }
            String value = filter;
            queryFilter.append(column).append(fromValue ? " >= " : " <= ");
            if (isDate) {
                queryFilter.append("TO_TIMESTAMP(:").append(paramName).append(", 'YYYY-MM-DD HH24:MI:SS')");
                value += (fromValue ? " 00:00:00" : " 23:59:59");
            } else {
                queryFilter.append("CAST(:").append(paramName).append(" AS NUMERIC)");
            }

            params.put(paramName, value);
            queryFilter.append(")");
        }
    }

    private void processInputFilter(
            StringBuilder queryFilter, Map<String, Object> params, String paramName, String filter, String input) {
        if (filter != null && !filter.isEmpty() && input != null && !input.isEmpty()) {
            queryFilter.append(" AND (");
            String[] filters = filter.split(",");
            for (int i = 0, length = filters.length; i < length; i++) {
                switch (filters[i].toUpperCase()) {
                    case "VULNERABILITY_ID" -> queryFilter.append("v.\"VULNID\"");
                    case "VULNERABILITY_TITLE" -> queryFilter.append("v.\"TITLE\"");
                    case "COMPONENT_NAME" -> queryFilter.append("c.\"NAME\"");
                    case "COMPONENT_VERSION" -> queryFilter.append("c.\"VERSION\"");
                    case "PROJECT_NAME" -> queryFilter.append("concat(p.\"NAME\", ' ', p.\"VERSION\")");
                }
                queryFilter.append(" LIKE :").append(paramName);
                if (i < length - 1) {
                    queryFilter.append(" OR ");
                }
            }
            if (filters.length > 0) {
                params.put(paramName, "%" + input + "%");
            }
            queryFilter.append(")");
        }
    }

    private static boolean hasValue(Map<String, String> filters, String key) {
        final String value = filters.get(key);
        return value != null && !value.isEmpty();
    }

    private static @Nullable BigDecimal maybeParseDecimal(@Nullable String value) {
        return value == null || value.isEmpty() ? null : new BigDecimal(value);
    }

    private static @Nullable Boolean maybeParseBoolean(@Nullable String value) {
        return value == null || value.isEmpty() ? null : Boolean.parseBoolean(value);
    }
}
