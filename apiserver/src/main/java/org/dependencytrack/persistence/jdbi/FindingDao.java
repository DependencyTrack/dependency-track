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

import static org.dependencytrack.resources.v1.FindingResource.mapComponentLatestVersion;

public interface FindingDao {

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
            String analyzerIdentity,
            Instant attributed_on,
            String alt_id,
            String reference_url,
            AnalysisState analysisState,
            boolean suppressed,
            long totalCount
    ) {
    }

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
            Instant vulnPublished,
            List<Integer> cwes,
            String analyzerIdentity,
            int affectedProjectCount,
            long totalCount
    ) {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            <#-- @ftlvariable name="epssFrom" type="boolean" -->
            <#-- @ftlvariable name="epssTo" type="boolean" -->
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
                 , fa."ANALYZERIDENTITY"
                 , fa."ATTRIBUTED_ON"
                 , fa."ALT_ID"
                 , fa."REFERENCE_URL"
                 , a."STATE" AS "analysisState"
                 , a."SUPPRESSED"
                 , COUNT(*) OVER() AS "totalCount"
              FROM "COMPONENT" AS c
             INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
                ON c."ID" = cv."COMPONENT_ID"
             INNER JOIN "VULNERABILITY" AS v
                ON cv."VULNERABILITY_ID" = v."ID"
              LEFT JOIN LATERAL (
                SELECT "CVE"
                     , "SCORE"
                     , "PERCENTILE"
                  FROM (
                    SELECT ee."CVE"
                         , ee."SCORE"
                         , ee."PERCENTILE"
                      FROM "EPSS" AS ee
                     WHERE v."SOURCE" = 'NVD'
                       AND ee."CVE" = v."VULNID"
                    UNION ALL
                    SELECT ee."CVE"
                         , ee."SCORE"
                         , ee."PERCENTILE"
                      FROM "VULNERABILITY_ALIAS" AS va
                     INNER JOIN "VULNERABILITY_ALIAS" AS cve_a
                        ON cve_a."GROUP_ID" = va."GROUP_ID"
                       AND cve_a."SOURCE" = 'NVD'
                     INNER JOIN "EPSS" AS ee
                        ON ee."CVE" = cve_a."VULN_ID"
                     WHERE v."SOURCE" != 'NVD'
                       AND va."SOURCE" = v."SOURCE"
                       AND va."VULN_ID" = v."VULNID"
                  ) candidates
                 ORDER BY "SCORE" DESC NULLS LAST
                        , "PERCENTILE" DESC NULLS LAST
                        , "CVE"
                 LIMIT 1
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
    @AllowApiOrdering(alwaysBy = @AllowApiOrdering.AlwaysBy(queryName = "c.\"ID\", v.\"ID\""), by = {
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
    List<FindingRow> getFindingsByProject(
            @Bind long projectId,
            @Define boolean includeInactive,
            @Define boolean includeSuppressed,
            @Nullable @Bind String searchText,
            @Bind Boolean hasAnalysis,
            @Bind String source,
            @Bind BigDecimal epssFrom,
            @Bind BigDecimal epssTo);

    default List<Finding> getFindings(final long projectId, final boolean includeSuppressed) {
        List<FindingRow> findingRows = getFindingsByProject(
                projectId,
                /* includeInactive */ false,
                includeSuppressed,
                /* searchText */ null,
                /* hasAnalysis */ null,
                /* source */ null,
                /* epssFrom */ null,
                /* epssTo */ null);
        List<Finding> findings = findingRows.stream().map(Finding::new).toList();
        return mapComponentLatestVersion(findings);
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="queryFilter" type="String" -->
            <#-- @ftlvariable name="activeFilter" type="Boolean" -->
            <#-- @ftlvariable name="includeInactiveFindings" type="Boolean" -->
            <#-- @ftlvariable name="suppressedFilter" type="Boolean" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
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
                 , ep."SCORE" AS "epssScore"
                 , ep."PERCENTILE" AS "epssPercentile"
                 , fa."ANALYZERIDENTITY"
                 , fa."ATTRIBUTED_ON"
                 , fa."ALT_ID"
                 , fa."REFERENCE_URL"
                 , a."STATE" AS "analysisState"
                 , a."SUPPRESSED"
                 , COUNT(*) OVER() AS "totalCount"
              FROM "COMPONENT" AS c
             INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
                ON c."ID" = cv."COMPONENT_ID"
             INNER JOIN "VULNERABILITY" AS v
                ON cv."VULNERABILITY_ID" = v."ID"
             LEFT JOIN LATERAL (
                SELECT "CVE"
                     , "SCORE"
                     , "PERCENTILE"
                  FROM (
                    SELECT ee."CVE"
                         , ee."SCORE"
                         , ee."PERCENTILE"
                      FROM "EPSS" AS ee
                     WHERE v."SOURCE" = 'NVD'
                       AND ee."CVE" = v."VULNID"
                    UNION ALL
                    SELECT ee."CVE"
                         , ee."SCORE"
                         , ee."PERCENTILE"
                      FROM "VULNERABILITY_ALIAS" AS va
                     INNER JOIN "VULNERABILITY_ALIAS" AS cve_a
                        ON cve_a."GROUP_ID" = va."GROUP_ID"
                       AND cve_a."SOURCE" = 'NVD'
                     INNER JOIN "EPSS" AS ee
                        ON ee."CVE" = cve_a."VULN_ID"
                     WHERE v."SOURCE" != 'NVD'
                       AND va."SOURCE" = v."SOURCE"
                       AND va."VULN_ID" = v."VULNID"
                  ) candidates
                 ORDER BY "SCORE" DESC NULLS LAST
                        , "PERCENTILE" DESC NULLS LAST
                        , "CVE"
                 LIMIT 1
             ) AS ep ON TRUE
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
             <#if queryFilter??>
                ${queryFilter}
             </#if>
             <#if apiOrderByClause??>
              ${apiOrderByClause}
             <#else>
              ORDER BY c."ID", v."ID"
             </#if>
             ${apiOffsetLimitClause!}
            """)
    @AllowApiOrdering(alwaysBy = @AllowApiOrdering.AlwaysBy(queryName = "c.\"ID\", v.\"ID\""), by = {
            @AllowApiOrdering.Column(name = "vulnerability.title", queryName = "v.\"TITLE\""),
            @AllowApiOrdering.Column(name = "vulnerability.vulnId", queryName = "v.\"VULNID\""),
            @AllowApiOrdering.Column(name = "vulnerability.severity", queryName = "\"vulnSeverity\""),
            @AllowApiOrdering.Column(name = "vulnerability.cvssV4Score", queryName = "\"cvssV4Score\""),
            @AllowApiOrdering.Column(name = "vulnerability.cvssV3BaseScore", queryName = "\"cvssV3BaseScore\""),
            @AllowApiOrdering.Column(name = "vulnerability.cvssV2BaseScore", queryName = "\"cvssV2BaseScore\""),
            @AllowApiOrdering.Column(name = "vulnerability.published", queryName = "v.\"PUBLISHED\""),
            @AllowApiOrdering.Column(name = "attribution.analyzerIdentity", queryName = "fa.\"ANALYZERIDENTITY\""),
            @AllowApiOrdering.Column(name = "component.projectName", queryName = "concat(p.\"NAME\", ' ', p.\"VERSION\")"),
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
    List<FindingRow> getAllFindings(@Define String queryFilter,
                                    @Define boolean activeFilter,
                                    @Define boolean includeInactiveFindings,
                                    @Define boolean suppressedFilter,
                                    @BindMap Map<String, Object> params);

    /**
     * Returns a List of all Finding objects filtered by ACL and other optional filters.
     * @param filters        determines the filters to apply on the list of Finding objects
     * @param showSuppressed determines if suppressed vulnerabilities should be included or not
     * @param showInactive   determines if inactive projects should be included or not
     * @return a List of Finding objects
     */
    default List<FindingRow> getAllFindings(final Map<String, String> filters, final boolean showSuppressed, final boolean showInactive) {
        StringBuilder queryFilter = new StringBuilder();
        Map<String, Object> params = new HashMap<>();
        processFilters(filters, queryFilter, params);
        return getAllFindings(String.valueOf(queryFilter), showInactive, /* includeInactiveFindings */ false, showSuppressed, params);
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="activeFilter" type="Boolean" -->
            <#-- @ftlvariable name="includeInactiveFindings" type="Boolean" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
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
                 , ep."SCORE" AS "epssScore"
                 , ep."PERCENTILE" AS "epssPercentile"
                 , v."PUBLISHED" AS "vulnPublished"
                 , CAST(STRING_TO_ARRAY(v."CWES", ',') AS INT[]) AS "CWES"
                 , fa."ANALYZERIDENTITY"
                 , COUNT(DISTINCT p."ID") AS "affectedProjectCount"
                 , COUNT(*) OVER() AS "totalCount"
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
              LEFT JOIN LATERAL (
                SELECT "CVE"
                     , "SCORE"
                     , "PERCENTILE"
                  FROM (
                    SELECT ee."CVE"
                         , ee."SCORE"
                         , ee."PERCENTILE"
                      FROM "EPSS" AS ee
                     WHERE v."SOURCE" = 'NVD'
                       AND ee."CVE" = v."VULNID"
                    UNION ALL
                    SELECT ee."CVE"
                         , ee."SCORE"
                         , ee."PERCENTILE"
                      FROM "VULNERABILITY_ALIAS" AS va
                     INNER JOIN "VULNERABILITY_ALIAS" AS cve_a
                        ON cve_a."GROUP_ID" = va."GROUP_ID"
                       AND cve_a."SOURCE" = 'NVD'
                     INNER JOIN "EPSS" AS ee
                        ON ee."CVE" = cve_a."VULN_ID"
                     WHERE v."SOURCE" != 'NVD'
                       AND va."SOURCE" = v."SOURCE"
                       AND va."VULN_ID" = v."VULNID"
                  ) candidates
                 ORDER BY "SCORE" DESC NULLS LAST
                        , "PERCENTILE" DESC NULLS LAST
                        , "CVE"
                 LIMIT 1
              ) AS ep ON TRUE
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
            GROUP BY v."ID"
                  , v."SOURCE"
                  , v."VULNID"
                  , v."TITLE"
                  , "vulnSeverity"
                  , "cvssV2BaseScore"
                  , "cvssV3BaseScore"
                  , "cvssV4Score"
                  , ep."SCORE"
                  , ep."PERCENTILE"
                  , fa."ANALYZERIDENTITY"
                  , v."PUBLISHED"
                  , v."CWES"
            <#if aggregateFilter??>
                ${aggregateFilter}
            </#if>
            <#if apiOrderByClause??>
              ${apiOrderByClause}
            </#if>
            ${apiOffsetLimitClause!}
            """)
    @AllowApiOrdering(alwaysBy = @AllowApiOrdering.AlwaysBy(queryName = "v.\"ID\""), by = {
            @AllowApiOrdering.Column(name = "vulnerability.vulnId", queryName = "v.\"VULNID\""),
            @AllowApiOrdering.Column(name = "vulnerability.title", queryName = "v.\"TITLE\""),
            @AllowApiOrdering.Column(name = "vulnerability.severity", queryName = "\"vulnSeverity\""),
            @AllowApiOrdering.Column(name = "vulnerability.cvssV4Score", queryName = "\"cvssV4Score\""),
            @AllowApiOrdering.Column(name = "vulnerability.cvssV3BaseScore", queryName = "\"cvssV3BaseScore\""),
            @AllowApiOrdering.Column(name = "vulnerability.cvssV2BaseScore", queryName = "\"cvssV2BaseScore\""),
            @AllowApiOrdering.Column(name = "vulnerability.published", queryName = "v.\"PUBLISHED\""),
            @AllowApiOrdering.Column(name = "attribution.analyzerIdentity", queryName = "fa.\"ANALYZERIDENTITY\""),
            @AllowApiOrdering.Column(name = "vulnerability.affectedProjectCount", queryName = "COUNT(DISTINCT p.\"ID\")")
    })
    @AllowUnusedBindings
    @DefineNamedBindings
    @DefineApiProjectAclCondition(projectIdColumn = "p.\"ID\"")
    @RegisterConstructorMapper(GroupedFindingRow.class)
    List<GroupedFindingRow> getGroupedFindings(@Define String queryFilter,
                                               @Define boolean activeFilter,
                                               @Define boolean includeInactiveFindings,
                                               @Define String aggregateFilter,
                                               @BindMap Map<String, Object> params);

    /**
     * Returns a List of all Finding objects filtered by ACL and other optional filters. The resulting list is grouped by vulnerability.
     *
     * @param filters       determines the filters to apply on the list of Finding objects
     * @param showInactive  determines if inactive projects should be included or not
     * @return a List of Finding objects
     */
    default List<GroupedFindingRow> getGroupedFindings(final Map<String, String> filters, final boolean showInactive) {
        StringBuilder queryFilter = new StringBuilder();
        Map<String, Object> params = new HashMap<>();
        processFilters(filters, queryFilter, params);
        StringBuilder aggregateFilter = new StringBuilder();
        processAggregateFilters(filters, aggregateFilter, params);
        return getGroupedFindings(String.valueOf(queryFilter), showInactive, /* includeInactiveFindings */ false, String.valueOf(aggregateFilter), params);
    }

    private void processFilters(Map<String, String> filters, StringBuilder queryFilter, Map<String, Object> params) {
        for (String filter : filters.keySet()) {
            switch (filter) {
                case "severity" ->
                        processArrayFilter(queryFilter, params, filter, filters.get(filter), "v.\"SEVERITY\"");
                case "analysisStatus" ->
                        processArrayFilter(queryFilter, params, filter, filters.get(filter), "a.\"STATE\"");
                case "vendorResponse" ->
                        processArrayFilter(queryFilter, params, filter, filters.get(filter), "a.\"RESPONSE\"");
                case "publishDateFrom" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "v.\"PUBLISHED\"", true, true, false);
                case "publishDateTo" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "v.\"PUBLISHED\"", false, true, false);
                case "attributedOnDateFrom" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "fa.\"ATTRIBUTED_ON\"", true, true, false);
                case "attributedOnDateTo" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "fa.\"ATTRIBUTED_ON\"", false, true, false);
                case "textSearchField" ->
                        processInputFilter(queryFilter, params, filter, filters.get(filter), filters.get("textSearchInput"));
                case "cvssv2From" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "v.\"CVSSV2BASESCORE\"", true, false, false);
                case "cvssv2To" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "v.\"CVSSV2BASESCORE\"", false, false, false);
                case "cvssv3From" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "v.\"CVSSV3BASESCORE\"", true, false, false);
                case "cvssv3To" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "v.\"CVSSV3BASESCORE\"", false, false, false);
                case "cvssv4From" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "v.\"CVSSV4SCORE\"", true, false, false);
                case "cvssv4To" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "v.\"CVSSV4SCORE\"", false, false, false);
                case "epssFrom" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "ep.\"SCORE\"", true, false, false);
                case "epssTo" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "ep.\"SCORE\"", false, false, false);
                case "epssPercentileFrom" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "ep.\"PERCENTILE\"", true, false, false);
                case "epssPercentileTo" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "ep.\"PERCENTILE\"", false, false, false);
            }
        }
    }

    private void processAggregateFilters(Map<String, String> filters, StringBuilder queryFilter, Map<String, Object> params) {
        for (String filter : filters.keySet()) {
            switch (filter) {
                case "occurrencesFrom" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "COUNT(DISTINCT p.\"ID\")", true, false, true);
                case "occurrencesTo" ->
                        processRangeFilter(queryFilter, params, filter, filters.get(filter), "COUNT(DISTINCT p.\"ID\")", false, false, true);
            }
        }
    }

    private void processArrayFilter(StringBuilder queryFilter, Map<String, Object> params, String paramName, String filter, String column) {
        if (filter != null && !filter.isEmpty()) {
            queryFilter.append(" AND (");
            String[] filters = filter.split(",");
            for (int i = 0, length = filters.length; i < length; i++) {
                queryFilter.append(column).append(" = :").append(paramName).append(i);
                if (paramName.equals("severity")) {
                    queryFilter.append("::SEVERITY");
                }
                params.put(paramName + i, filters[i].toUpperCase());
                if (filters[i].equals("NOT_SET") && (paramName.equals("analysisStatus") || paramName.equals("vendorResponse"))) {
                    queryFilter.append(" OR ").append(column).append(" IS NULL");
                }
                if (i < length - 1) {
                    queryFilter.append(" OR ");
                }
            }
            queryFilter.append(")");
        }
    }

    private void processRangeFilter(StringBuilder queryFilter, Map<String, Object> params, String paramName, String filter, String column, boolean fromValue, boolean isDate, boolean isAggregateFilter) {
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

    private void processInputFilter(StringBuilder queryFilter, Map<String, Object> params, String paramName, String filter, String input) {
        if (filter != null && !filter.isEmpty() && input != null && !input.isEmpty()) {
            queryFilter.append(" AND (");
            String[] filters = filter.split(",");
            for (int i = 0, length = filters.length; i < length; i++) {
                switch (filters[i].toUpperCase()) {
                    case "VULNERABILITY_ID" -> queryFilter.append("v.\"VULNID\"");
                    case "VULNERABILITY_TITLE" -> queryFilter.append("v.\"TITLE\"");
                    case "COMPONENT_NAME" -> queryFilter.append("c.\"NAME\"");
                    case "COMPONENT_VERSION" -> queryFilter.append("c.\"VERSION\"");
                    case "PROJECT_NAME" ->
                            queryFilter.append("concat(p.\"NAME\", ' ', p.\"VERSION\")");
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
}
