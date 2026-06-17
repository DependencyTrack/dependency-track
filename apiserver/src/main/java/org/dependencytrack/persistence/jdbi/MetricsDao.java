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

import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.VulnerabilityMetrics;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterBeanMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlCall;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * @since 5.0.0
 */
public interface MetricsDao extends SqlObject {

    Pattern VALID_TABLE_IDENTIFIER_PATTERN = Pattern.compile("^\"[A-Z][A-Z0-9_]+\"$");

    /**
     * Compute the portfolio metrics for the projects accessible by the calling principal.
     * <p>
     * If portfolio ACL is disabled, or the principal is bypassing ACL in any other
     * way, the query selects from the {@code PORTFOLIOMETRICS_GLOBAL} materialized view
     * rather than performing ad-hoc aggregations. The assumption is that most users
     * will only have access to a small subset of projects, even if the entire portfolio
     * span multiple 10s of thousands of projects. But users who bypass ACL restrictions
     * would need aggregations to be performed over a large set of projects, which is
     * not feasible.
     * <p>
     * Note that <code>generate_series</code> is invoked with integers rather
     * than <code>date</code>s, because the query planner tends to overestimate
     * rows with the latter approach.
     *
     * @see <a href="https://stackoverflow.com/a/66279403">generate_series quirk</a>
     */
    @SqlQuery("""
            <#if apiProjectAclCondition?c_lower_case == 'true'>
            SELECT *
              FROM "PORTFOLIOMETRICS_GLOBAL"
             WHERE "LAST_OCCURRENCE" >= CAST(CURRENT_TIMESTAMP AT TIME ZONE 'UTC' AS date) - (INTERVAL '1 day' * (:days - 1))
             ORDER BY "LAST_OCCURRENCE";
            <#else>
            WITH
            date_range AS(
              SELECT DATE_TRUNC('day', CAST(CURRENT_TIMESTAMP AT TIME ZONE 'UTC' AS date) - (INTERVAL '1 day' * day)) AS metrics_date
                FROM GENERATE_SERIES(0, GREATEST(:days - 1, 0)) day
            ),
            projects_in_scope AS(
              SELECT "ID"
                FROM "PROJECT"
               WHERE "INACTIVE_SINCE" IS NULL
                 AND "COLLECTION_LOGIC" IS NULL
                 AND ${apiProjectAclCondition}
            ),
            latest_daily_project_metrics AS(
              SELECT date_range.metrics_date
                   , latest_metrics.*
               FROM date_range
               LEFT JOIN LATERAL (
                 SELECT DISTINCT ON (pm."PROJECT_ID")
                        pm.*
                   FROM projects_in_scope
                  INNER JOIN "PROJECTMETRICS" pm
                     ON pm."PROJECT_ID" = projects_in_scope."ID"
                  WHERE pm."LAST_OCCURRENCE" < (date_range.metrics_date + INTERVAL '1 day') AT TIME ZONE 'UTC'
                    -- Consider data from previous day in case we don't have any for today.
                    AND pm."LAST_OCCURRENCE" >= (date_range.metrics_date - INTERVAL '1 day') AT TIME ZONE 'UTC'
                  ORDER BY pm."PROJECT_ID", pm."LAST_OCCURRENCE" DESC
               ) AS latest_metrics ON TRUE
            ),
            daily_metrics AS(
              SELECT COUNT(DISTINCT "PROJECT_ID") AS projects
                   , SUM("COMPONENTS") AS components
                   , SUM("CRITICAL") AS critical
                   , metrics_date
                   , SUM("FINDINGS_AUDITED") AS findings_audited
                   , SUM("FINDINGS_TOTAL") AS findings_total
                   , SUM("FINDINGS_UNAUDITED") AS findings_unaudited
                   , SUM("HIGH") AS high
                   , SUM("RISKSCORE") as inherited_risk_score
                   , SUM("LOW") AS low
                   , SUM("MEDIUM") AS medium
                   , SUM("POLICYVIOLATIONS_AUDITED") AS policy_violations_audited
                   , SUM("POLICYVIOLATIONS_FAIL") AS policy_violations_fail
                   , SUM("POLICYVIOLATIONS_INFO") AS policy_violations_info
                   , SUM("POLICYVIOLATIONS_LICENSE_AUDITED") AS policy_violations_license_audited
                   , SUM("POLICYVIOLATIONS_LICENSE_TOTAL") AS policy_violations_license_total
                   , SUM("POLICYVIOLATIONS_LICENSE_UNAUDITED") AS policy_violations_license_unaudited
                   , SUM("POLICYVIOLATIONS_OPERATIONAL_AUDITED") AS policy_violations_operational_audited
                   , SUM("POLICYVIOLATIONS_OPERATIONAL_TOTAL") AS policy_violations_operational_total
                   , SUM("POLICYVIOLATIONS_OPERATIONAL_UNAUDITED") AS policy_violations_operational_unaudited
                   , SUM("POLICYVIOLATIONS_SECURITY_AUDITED") AS policy_violations_security_audited
                   , SUM("POLICYVIOLATIONS_SECURITY_TOTAL") AS policy_violations_security_total
                   , SUM("POLICYVIOLATIONS_SECURITY_UNAUDITED") AS policy_violations_security_unaudited
                   , SUM("POLICYVIOLATIONS_TOTAL") AS policy_violations_total
                   , SUM("POLICYVIOLATIONS_UNAUDITED") AS policy_violations_unaudited
                   , SUM("POLICYVIOLATIONS_WARN") AS policy_violations_warn
                   , SUM("SUPPRESSED") AS suppressed
                   , SUM("UNASSIGNED_SEVERITY") AS unassigned
                   , SUM("VULNERABILITIES") AS vulnerabilities
                   , SUM("VULNERABLECOMPONENTS") AS vulnerable_components
                   , SUM(CASE WHEN "VULNERABLECOMPONENTS" > 0 THEN 1 ELSE 0 END) AS vulnerable_projects
                FROM latest_daily_project_metrics
               GROUP BY metrics_date
            )
            SELECT COALESCE(dm.components, 0) AS components
                 , COALESCE(dm.critical, 0) AS critical
                 , COALESCE(dm.findings_audited, 0) AS findings_audited
                 , COALESCE(dm.findings_total, 0) AS findings_total
                 , COALESCE(dm.findings_unaudited, 0) AS findings_unaudited
                 , date_range.metrics_date AS first_occurrence
                 , COALESCE(dm.high, 0) AS high
                 , COALESCE(dm.inherited_risk_score, 0) AS inherited_risk_score
                 , date_range.metrics_date AS last_occurrence
                 , COALESCE(dm.low, 0) AS low
                 , COALESCE(dm.medium, 0) AS medium
                 , COALESCE(dm.policy_violations_audited, 0) AS policy_violations_audited
                 , COALESCE(dm.policy_violations_fail, 0) AS policy_violations_fail
                 , COALESCE(dm.policy_violations_info, 0) AS policy_violations_info
                 , COALESCE(dm.policy_violations_license_audited, 0) AS policy_violations_license_audited
                 , COALESCE(dm.policy_violations_license_total, 0) AS policy_violations_license_total
                 , COALESCE(dm.policy_violations_license_unaudited, 0) AS policy_violations_license_unaudited
                 , COALESCE(dm.policy_violations_operational_audited, 0) AS policy_violations_operational_audited
                 , COALESCE(dm.policy_violations_operational_total, 0) AS policy_violations_operational_total
                 , COALESCE(dm.policy_violations_operational_unaudited, 0) AS policy_violations_operational_unaudited
                 , COALESCE(dm.policy_violations_security_audited, 0) AS policy_violations_security_audited
                 , COALESCE(dm.policy_violations_security_total, 0) AS policy_violations_security_total
                 , COALESCE(dm.policy_violations_security_unaudited, 0) AS policy_violations_security_unaudited
                 , COALESCE(dm.policy_violations_total, 0) AS policy_violations_total
                 , COALESCE(dm.policy_violations_unaudited, 0) AS policy_violations_unaudited
                 , COALESCE(dm.policy_violations_warn, 0) AS policy_violations_warn
                 , COALESCE(dm.projects, 0) AS projects
                 , COALESCE(dm.suppressed, 0) AS suppressed
                 , COALESCE(dm.unassigned, 0) AS unassigned
                 , COALESCE(dm.vulnerabilities, 0) AS vulnerabilities
                 , COALESCE(dm.vulnerable_components, 0) AS vulnerable_components
                 , COALESCE(dm.vulnerable_projects, 0) AS vulnerable_projects
              FROM date_range
              LEFT JOIN daily_metrics AS dm
                ON date_range.metrics_date = dm.metrics_date
             ORDER BY date_range.metrics_date;
            </#if>
            """)
    @RegisterBeanMapper(PortfolioMetrics.class)
    List<PortfolioMetrics> getPortfolioMetricsForDays(@Bind int days);

    default void refreshGlobalPortfolioMetrics() {
        if (!getHandle().isInTransaction()) {
            // Required so SET LOCAL doesn't silently no-op.
            throw new IllegalStateException(
                    "refreshGlobalPortfolioMetrics must run inside a transaction");
        }

        // NB: All other metrics operations explicitly cast timestamps to UTC
        // and do not require this workaround. Setting the local timezone here
        // was done to avoid having to drop and re-create the materialized view
        // via schema migration. If the view ever needs updating for unrelated
        // reasons, this workaround could be removed.
        getHandle().execute("SET LOCAL TIME ZONE 'UTC'");
        getHandle().execute("REFRESH MATERIALIZED VIEW CONCURRENTLY \"PORTFOLIOMETRICS_GLOBAL\"");
    }

    default void refreshVulnerabilityMetrics() {
        if (!getHandle().isInTransaction()) {
            // Required so SET LOCAL doesn't silently no-op.
            throw new IllegalStateException(
                    "refreshVulnerabilityMetrics must run inside a transaction");
        }

        // NB: All other metrics operations explicitly cast timestamps to UTC
        // and do not require this workaround. Setting the local timezone here
        // was done to avoid having to drop and re-create the materialized view
        // via schema migration. If the view ever needs updating for unrelated
        // reasons, this workaround could be removed.
        getHandle().execute("SET LOCAL TIME ZONE 'UTC'");
        getHandle().execute("REFRESH MATERIALIZED VIEW CONCURRENTLY \"VULNERABILITYMETRICS\"");
    }

    @SqlQuery("""
            SELECT "YEAR" AS "year"
                 , NULLIF("MONTH", 0) AS "month"
                 , "COUNT" AS "count"
                 , "MEASURED_AT" AS "measuredAt"
              FROM "VULNERABILITYMETRICS"
             ORDER BY "YEAR"
                    , NULLIF("MONTH", 0) NULLS LAST
            """)
    @RegisterBeanMapper(VulnerabilityMetrics.class)
    List<VulnerabilityMetrics> getVulnerabilityMetrics();

    @SqlQuery("""
            SELECT *, "RISKSCORE" AS inherited_risk_score FROM "PROJECTMETRICS"
            WHERE "PROJECT_ID" = :projectId
            AND "LAST_OCCURRENCE" >= :since
            ORDER BY "LAST_OCCURRENCE" ASC
            """)
    @RegisterBeanMapper(ProjectMetrics.class)
    List<ProjectMetrics> getProjectMetricsSince(@Bind long projectId, @Bind Instant since);

    @SqlQuery("""
            SELECT *, "RISKSCORE" AS inherited_risk_score FROM "DEPENDENCYMETRICS"
            WHERE "COMPONENT_ID" = :componentId
            AND "LAST_OCCURRENCE" >= :since
            ORDER BY "LAST_OCCURRENCE" ASC
            """)
    @RegisterBeanMapper(DependencyMetrics.class)
    List<DependencyMetrics> getDependencyMetricsSince(@Bind long componentId, @Bind Instant since);

    default PortfolioMetrics getMostRecentPortfolioMetrics() {
        // Request metrics since yesterday, such that we cater for projects that do
        // not have fresh metrics from today yet.
        return getPortfolioMetricsForDays(2).getLast();
    }

    @SqlQuery("""
            SELECT *, "RISKSCORE" AS inherited_risk_score
            FROM "PROJECTMETRICS"
            WHERE "PROJECT_ID" = :projectId
            ORDER BY "LAST_OCCURRENCE" DESC
            LIMIT 1
            """)
    @RegisterBeanMapper(ProjectMetrics.class)
    ProjectMetrics getMostRecentProjectMetrics(@Bind final long projectId);

    @SqlQuery("""
            SELECT metrics.*, metrics."RISKSCORE" AS inherited_risk_score
              FROM UNNEST(:projectIds) AS project(id)
             INNER JOIN LATERAL (
               SELECT *
                 FROM "PROJECTMETRICS"
                WHERE "PROJECT_ID" = project.id
                ORDER BY "LAST_OCCURRENCE" DESC
                LIMIT 1
             ) AS metrics ON TRUE
            """)
    @RegisterBeanMapper(ProjectMetrics.class)
    List<ProjectMetrics> getMostRecentProjectMetrics(@Bind Collection<Long> projectIds);

    @SqlQuery("""
            WITH RECURSIVE
            collection_descendants AS(
              SELECT child."ID" AS project_id
                   , child."COLLECTION_LOGIC"
                   , child."COLLECTION_TAG_ID"
                FROM "PROJECT" parent
               INNER JOIN "PROJECT_HIERARCHY" ph
                  ON ph."PARENT_PROJECT_ID" = parent."ID"
                 AND ph."DEPTH" = 1
               INNER JOIN "PROJECT" child
                  ON child."ID" = ph."CHILD_PROJECT_ID"
                 AND child."INACTIVE_SINCE" IS NULL
                 AND (
                   parent."COLLECTION_LOGIC" != 'AGGREGATE_DIRECT_CHILDREN_WITH_TAG'
                   OR EXISTS (
                     SELECT 1
                       FROM "PROJECTS_TAGS" pt
                      WHERE pt."PROJECT_ID" = child."ID"
                        AND pt."TAG_ID" = parent."COLLECTION_TAG_ID"
                   )
                 )
                 AND (
                   parent."COLLECTION_LOGIC" != 'AGGREGATE_LATEST_VERSION_CHILDREN'
                   OR child."IS_LATEST"
                 )
               WHERE parent."ID" = :projectId
              UNION ALL
              SELECT child."ID"
                   , child."COLLECTION_LOGIC"
                   , child."COLLECTION_TAG_ID"
                FROM collection_descendants cd
               INNER JOIN "PROJECT_HIERARCHY" ph
                  ON ph."PARENT_PROJECT_ID" = cd.project_id
                 AND ph."DEPTH" = 1
               INNER JOIN "PROJECT" child
                  ON child."ID" = ph."CHILD_PROJECT_ID"
               WHERE cd."COLLECTION_LOGIC" IS NOT NULL
                 AND child."INACTIVE_SINCE" IS NULL
                 AND (
                   cd."COLLECTION_LOGIC" != 'AGGREGATE_DIRECT_CHILDREN_WITH_TAG'
                   OR EXISTS (
                     SELECT 1
                       FROM "PROJECTS_TAGS" pt
                      WHERE pt."PROJECT_ID" = child."ID"
                        AND pt."TAG_ID" = cd."COLLECTION_TAG_ID"
                   )
                 )
                 AND (
                   cd."COLLECTION_LOGIC" != 'AGGREGATE_LATEST_VERSION_CHILDREN'
                   OR child."IS_LATEST"
                 )
            )
            CYCLE project_id SET is_cycle USING path,
            leaf_descendants AS(
              SELECT project_id AS "ID"
                FROM collection_descendants
               WHERE "COLLECTION_LOGIC" IS NULL
            ),
            date_range AS(
              SELECT CAST(d AS date) AS metrics_date
                FROM GENERATE_SERIES(CAST(:since AS date), CAST(CURRENT_TIMESTAMP AT TIME ZONE 'UTC' AS date), '1 day') d
            ),
            latest_daily_child_metrics AS(
              SELECT date_range.metrics_date
                   , latest_metrics.*
                FROM date_range
                LEFT JOIN LATERAL (
                  SELECT DISTINCT ON (pm."PROJECT_ID")
                         pm.*
                    FROM leaf_descendants
                   INNER JOIN "PROJECTMETRICS" pm
                      ON pm."PROJECT_ID" = leaf_descendants."ID"
                   WHERE pm."LAST_OCCURRENCE" < (date_range.metrics_date + INTERVAL '1 day') AT TIME ZONE 'UTC'
                     AND pm."LAST_OCCURRENCE" >= (date_range.metrics_date - INTERVAL '1 day') AT TIME ZONE 'UTC'
                   ORDER BY pm."PROJECT_ID", pm."LAST_OCCURRENCE" DESC
                ) AS latest_metrics ON TRUE
            ),
            daily_metrics AS(
              SELECT metrics_date
                   , SUM("COMPONENTS") AS components
                   , SUM("CRITICAL") AS critical
                   , SUM("FINDINGS_AUDITED") AS findings_audited
                   , SUM("FINDINGS_TOTAL") AS findings_total
                   , SUM("FINDINGS_UNAUDITED") AS findings_unaudited
                   , SUM("HIGH") AS high
                   , SUM("LOW") AS low
                   , SUM("MEDIUM") AS medium
                   , SUM("POLICYVIOLATIONS_AUDITED") AS policy_violations_audited
                   , SUM("POLICYVIOLATIONS_FAIL") AS policy_violations_fail
                   , SUM("POLICYVIOLATIONS_INFO") AS policy_violations_info
                   , SUM("POLICYVIOLATIONS_LICENSE_AUDITED") AS policy_violations_license_audited
                   , SUM("POLICYVIOLATIONS_LICENSE_TOTAL") AS policy_violations_license_total
                   , SUM("POLICYVIOLATIONS_LICENSE_UNAUDITED") AS policy_violations_license_unaudited
                   , SUM("POLICYVIOLATIONS_OPERATIONAL_AUDITED") AS policy_violations_operational_audited
                   , SUM("POLICYVIOLATIONS_OPERATIONAL_TOTAL") AS policy_violations_operational_total
                   , SUM("POLICYVIOLATIONS_OPERATIONAL_UNAUDITED") AS policy_violations_operational_unaudited
                   , SUM("POLICYVIOLATIONS_SECURITY_AUDITED") AS policy_violations_security_audited
                   , SUM("POLICYVIOLATIONS_SECURITY_TOTAL") AS policy_violations_security_total
                   , SUM("POLICYVIOLATIONS_SECURITY_UNAUDITED") AS policy_violations_security_unaudited
                   , SUM("POLICYVIOLATIONS_TOTAL") AS policy_violations_total
                   , SUM("POLICYVIOLATIONS_UNAUDITED") AS policy_violations_unaudited
                   , SUM("POLICYVIOLATIONS_WARN") AS policy_violations_warn
                   , SUM("RISKSCORE") AS inherited_risk_score
                   , SUM("SUPPRESSED") AS suppressed
                   , SUM("UNASSIGNED_SEVERITY") AS unassigned
                   , SUM("VULNERABILITIES") AS vulnerabilities
                   , SUM("VULNERABLECOMPONENTS") AS vulnerable_components
                FROM latest_daily_child_metrics
               GROUP BY metrics_date
            )
            SELECT COALESCE(dm.components, 0) AS components
                 , COALESCE(dm.critical, 0) AS critical
                 , COALESCE(dm.findings_audited, 0) AS "findingsAudited"
                 , COALESCE(dm.findings_total, 0) AS "findingsTotal"
                 , COALESCE(dm.findings_unaudited, 0) AS "findingsUnaudited"
                 , date_range.metrics_date AS "firstOccurrence"
                 , COALESCE(dm.high, 0) AS high
                 , COALESCE(dm.inherited_risk_score, 0) AS "inheritedRiskScore"
                 , date_range.metrics_date AS "lastOccurrence"
                 , COALESCE(dm.low, 0) AS low
                 , COALESCE(dm.medium, 0) AS medium
                 , COALESCE(dm.policy_violations_audited, 0) AS "policyViolationsAudited"
                 , COALESCE(dm.policy_violations_fail, 0) AS "policyViolationsFail"
                 , COALESCE(dm.policy_violations_info, 0) AS "policyViolationsInfo"
                 , COALESCE(dm.policy_violations_license_audited, 0) AS "policyViolationsLicenseAudited"
                 , COALESCE(dm.policy_violations_license_total, 0) AS "policyViolationsLicenseTotal"
                 , COALESCE(dm.policy_violations_license_unaudited, 0) AS "policyViolationsLicenseUnaudited"
                 , COALESCE(dm.policy_violations_operational_audited, 0) AS "policyViolationsOperationalAudited"
                 , COALESCE(dm.policy_violations_operational_total, 0) AS "policyViolationsOperationalTotal"
                 , COALESCE(dm.policy_violations_operational_unaudited, 0) AS "policyViolationsOperationalUnaudited"
                 , COALESCE(dm.policy_violations_security_audited, 0) AS "policyViolationsSecurityAudited"
                 , COALESCE(dm.policy_violations_security_total, 0) AS "policyViolationsSecurityTotal"
                 , COALESCE(dm.policy_violations_security_unaudited, 0) AS "policyViolationsSecurityUnaudited"
                 , COALESCE(dm.policy_violations_total, 0) AS "policyViolationsTotal"
                 , COALESCE(dm.policy_violations_unaudited, 0) AS "policyViolationsUnaudited"
                 , COALESCE(dm.policy_violations_warn, 0) AS "policyViolationsWarn"
                 , COALESCE(dm.suppressed, 0) AS suppressed
                 , COALESCE(dm.unassigned, 0) AS unassigned
                 , COALESCE(dm.vulnerabilities, 0) AS vulnerabilities
                 , COALESCE(dm.vulnerable_components, 0) AS "vulnerableComponents"
              FROM date_range
              LEFT JOIN daily_metrics AS dm
                ON date_range.metrics_date = dm.metrics_date
             ORDER BY date_range.metrics_date
            """)
    @RegisterBeanMapper(ProjectMetrics.class)
    List<ProjectMetrics> getCollectionProjectMetricsSince(
            @Bind long projectId,
            @Bind Instant since);

    default @Nullable ProjectMetrics getMostRecentCollectionProjectMetrics(long projectId) {
        final List<ProjectMetrics> metrics =
                getMostRecentCollectionProjectMetrics(List.of(projectId));
        return !metrics.isEmpty() ? metrics.getFirst() : null;
    }

    @SqlQuery("""
            WITH RECURSIVE
            collection_descendants AS(
              SELECT parent."ID" AS root_id
                   , child."ID" AS project_id
                   , child."COLLECTION_LOGIC"
                   , child."COLLECTION_TAG_ID"
                FROM UNNEST(:projectIds) AS input(id)
               INNER JOIN "PROJECT" parent
                  ON parent."ID" = input.id
               INNER JOIN "PROJECT_HIERARCHY" ph
                  ON ph."PARENT_PROJECT_ID" = parent."ID"
                 AND ph."DEPTH" = 1
               INNER JOIN "PROJECT" child
                  ON child."ID" = ph."CHILD_PROJECT_ID"
                 AND child."INACTIVE_SINCE" IS NULL
                 AND (
                   parent."COLLECTION_LOGIC" != 'AGGREGATE_DIRECT_CHILDREN_WITH_TAG'
                   OR EXISTS (
                     SELECT 1
                       FROM "PROJECTS_TAGS" pt
                      WHERE pt."PROJECT_ID" = child."ID"
                        AND pt."TAG_ID" = parent."COLLECTION_TAG_ID"
                   )
                 )
                 AND (
                   parent."COLLECTION_LOGIC" != 'AGGREGATE_LATEST_VERSION_CHILDREN'
                   OR child."IS_LATEST"
                 )
              UNION ALL
              SELECT cd.root_id
                   , child."ID"
                   , child."COLLECTION_LOGIC"
                   , child."COLLECTION_TAG_ID"
                FROM collection_descendants cd
               INNER JOIN "PROJECT_HIERARCHY" ph
                  ON ph."PARENT_PROJECT_ID" = cd.project_id
                 AND ph."DEPTH" = 1
               INNER JOIN "PROJECT" child
                  ON child."ID" = ph."CHILD_PROJECT_ID"
               WHERE cd."COLLECTION_LOGIC" IS NOT NULL
                 AND child."INACTIVE_SINCE" IS NULL
                 AND (
                   cd."COLLECTION_LOGIC" != 'AGGREGATE_DIRECT_CHILDREN_WITH_TAG'
                   OR EXISTS (
                     SELECT 1
                       FROM "PROJECTS_TAGS" pt
                      WHERE pt."PROJECT_ID" = child."ID"
                        AND pt."TAG_ID" = cd."COLLECTION_TAG_ID"
                   )
                 )
                 AND (
                   cd."COLLECTION_LOGIC" != 'AGGREGATE_LATEST_VERSION_CHILDREN'
                   OR child."IS_LATEST"
                 )
            )
            CYCLE project_id SET is_cycle USING path
            SELECT cd.root_id AS "projectId"
                 , COALESCE(SUM(pm."COMPONENTS"), 0) AS components
                 , COALESCE(SUM(pm."CRITICAL"), 0) AS critical
                 , COALESCE(SUM(pm."HIGH"), 0) AS high
                 , COALESCE(SUM(pm."LOW"), 0) AS low
                 , COALESCE(SUM(pm."MEDIUM"), 0) AS medium
                 , COALESCE(SUM(pm."UNASSIGNED_SEVERITY"), 0) AS unassigned
                 , COALESCE(SUM(pm."VULNERABILITIES"), 0) AS vulnerabilities
                 , COALESCE(SUM(pm."VULNERABLECOMPONENTS"), 0) AS "vulnerableComponents"
                 , COALESCE(SUM(pm."FINDINGS_TOTAL"), 0) AS "findingsTotal"
                 , COALESCE(SUM(pm."FINDINGS_AUDITED"), 0) AS "findingsAudited"
                 , COALESCE(SUM(pm."FINDINGS_UNAUDITED"), 0) AS "findingsUnaudited"
                 , COALESCE(SUM(pm."SUPPRESSED"), 0) AS suppressed
                 , COALESCE(SUM(pm."RISKSCORE"), 0) AS "inheritedRiskScore"
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
             GROUP BY cd.root_id
            """)
    @RegisterBeanMapper(ProjectMetrics.class)
    List<ProjectMetrics> getMostRecentCollectionProjectMetrics(@Bind Collection<Long> projectIds);

    @SqlCall("""
            CALL "UPDATE_PROJECT_METRICS"(:uuid)
            """)
    void updateProjectMetrics(@Bind UUID uuid);

    @SqlCall("""
            CALL "UPDATE_COMPONENT_METRICS"(:uuid)
            """)
    void updateComponentMetrics(@Bind UUID uuid);

    @SqlQuery("""
            SELECT *, "RISKSCORE" AS inherited_risk_score
            FROM "DEPENDENCYMETRICS"
            WHERE "COMPONENT_ID" = :componentId
            ORDER BY "LAST_OCCURRENCE" DESC
            LIMIT 1
            """)
    @RegisterBeanMapper(DependencyMetrics.class)
    DependencyMetrics getMostRecentDependencyMetrics(@Bind long componentId);

    @SqlQuery("""
            SELECT metrics.*, metrics."RISKSCORE" AS inherited_risk_score
              FROM UNNEST(:componentIds) AS component(id)
             INNER JOIN LATERAL (
               SELECT *
                 FROM "DEPENDENCYMETRICS"
                WHERE "COMPONENT_ID" = component.id
                ORDER BY "LAST_OCCURRENCE" DESC
                LIMIT 1
             ) AS metrics ON TRUE
            """)
    @RegisterBeanMapper(DependencyMetrics.class)
    List<DependencyMetrics> getMostRecentDependencyMetrics(@Bind Collection<Long> componentIds);

    @SqlQuery("""
            SELECT inhrelid::regclass AS partition_name
            FROM pg_inherits
            WHERE inhparent = '"PROJECTMETRICS"'::regclass
            ORDER BY partition_name;
            """)
    List<String> getProjectMetricsPartitions();

    @SqlQuery("""
            SELECT inhrelid::regclass AS partition_name
            FROM pg_inherits
            WHERE inhparent = '"DEPENDENCYMETRICS"'::regclass
            ORDER BY partition_name;
            """)
    List<String> getDependencyMetricsPartitions();

    @SqlUpdate("""
            DO $$
            DECLARE
                today_utc DATE := CAST(CURRENT_TIMESTAMP AT TIME ZONE 'UTC' AS date);
                target_date DATE;
                next_date DATE;
                partition_suffix TEXT;
                partition_name TEXT;
                partition_exists BOOLEAN;
                table_name TEXT;
                day_offset INT;
                metric_tables TEXT[] := ARRAY['PROJECTMETRICS', 'DEPENDENCYMETRICS'];
            BEGIN
                FOR day_offset IN 0..1 LOOP
                    target_date := today_utc + day_offset;
                    next_date := target_date + 1;
                    partition_suffix := to_char(target_date, 'YYYYMMDD');
            
                    FOREACH table_name IN ARRAY metric_tables
                    LOOP
                        partition_name := format('%s_%s', table_name, partition_suffix);
                        SELECT EXISTS (
                            SELECT 1 FROM pg_class WHERE relname = partition_name
                        ) INTO partition_exists;
            
                        IF NOT partition_exists THEN
                            EXECUTE format(
                                'CREATE TABLE IF NOT EXISTS %I (LIKE %I INCLUDING ALL);',
                                partition_name,
                                table_name
                            );
                            EXECUTE format(
                                'ALTER TABLE %I ATTACH PARTITION %I FOR VALUES FROM (%L) TO (%L);',
                                table_name,
                                partition_name,
                                CAST(target_date AS timestamp) AT TIME ZONE 'UTC',
                                CAST(next_date AS timestamp) AT TIME ZONE 'UTC'
                            );
                        END IF;
                    END LOOP;
                END LOOP;
            END;
            $$;
            """)
    void createMetricsPartitions();

    @SqlQuery("""
            SELECT inhrelid::regclass::text AS partition_name
            FROM pg_inherits
            WHERE inhparent = CAST(:parentTable AS regclass)
              AND to_date(split_part(replace(inhrelid::regclass::text, '"', ''), '_', 2), 'YYYYMMDD') <= CAST(CURRENT_TIMESTAMP AT TIME ZONE 'UTC' AS date) - :retentionDays
            ORDER BY partition_name
            """)
    List<String> getExpiredPartitions(@Bind String parentTable, @Bind int retentionDays);

    default int deleteProjectMetricsForRetentionDuration(Duration retentionDuration) {
        final List<String> expired = getExpiredPartitions(
                "\"PROJECTMETRICS\"", (int) retentionDuration.toDays());
        return dropPartitions("\"PROJECTMETRICS\"", expired);
    }

    default int deleteComponentMetricsForRetentionDuration(Duration retentionDuration) {
        final List<String> expired = getExpiredPartitions(
                "\"DEPENDENCYMETRICS\"", (int) retentionDuration.toDays());
        return dropPartitions("\"DEPENDENCYMETRICS\"", expired);
    }

    default int dropPartitions(final String parentTable, final List<String> partitions) {
        requireValidTableIdentifier(parentTable);

        int deletedCount = 0;
        for (final String partition : partitions) {
            requireValidTableIdentifier(partition);
            if (isPartitionDetachPending(parentTable, partition)) {
                getHandle().useTransaction(trx -> {
                    trx.execute("SET LOCAL lock_timeout = '5s'");
                    trx.execute("ALTER TABLE %s DETACH PARTITION %s FINALIZE".formatted(parentTable, partition));
                });
            } else {
                getHandle().execute("ALTER TABLE %s DETACH PARTITION %s CONCURRENTLY".formatted(parentTable, partition));
            }
            getHandle().execute("DROP TABLE IF EXISTS %s CASCADE".formatted(partition));
            deletedCount++;
        }
        return deletedCount;
    }

    default boolean isPartitionDetachPending(String parentTable, String partition) {
        return getHandle().createQuery("""
                        SELECT inhdetachpending
                          FROM pg_inherits
                          WHERE inhparent = CAST(:parentTable AS regclass)
                            AND inhrelid = CAST(:partition AS regclass)
                        """)
                .bind("parentTable", parentTable)
                .bind("partition", partition)
                .mapTo(Boolean.class)
                .findOne()
                .orElse(false);
    }

    private static void requireValidTableIdentifier(final String identifier) {
        if (!VALID_TABLE_IDENTIFIER_PATTERN.matcher(identifier).matches()) {
            throw new IllegalArgumentException("Invalid identifier: " + identifier);
        }
    }
}
