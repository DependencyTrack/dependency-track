DROP MATERIALIZED VIEW IF EXISTS "PORTFOLIOMETRICS_GLOBAL";

CREATE MATERIALIZED VIEW "PORTFOLIOMETRICS_GLOBAL" AS
  WITH retention AS (
    SELECT COALESCE(
      (
        SELECT "CONFIGPROPERTY"."PROPERTYVALUE"::INT AS "PROPERTYVALUE"
          FROM "CONFIGPROPERTY"
         WHERE "CONFIGPROPERTY"."GROUPNAME" = 'maintenance'
           AND "CONFIGPROPERTY"."PROPERTYNAME" = 'metrics.retention.days'
      ),
      90
    ) AS days
  ),
  date_range AS (
    SELECT date_trunc('day', (CAST(CURRENT_TIMESTAMP AT TIME ZONE 'UTC' AS date) - ('1 day'::INTERVAL * (day.day)::DOUBLE PRECISION))) AS metrics_date
      FROM generate_series(0, GREATEST(((SELECT retention.days FROM retention) - 1), 0)) AS day(day)
  ),
  latest_daily_project_metrics AS (
    SELECT date_range.metrics_date
         , latest_metrics."COMPONENTS"
         , latest_metrics."CRITICAL"
         , latest_metrics."FINDINGS_AUDITED"
         , latest_metrics."FINDINGS_TOTAL"
         , latest_metrics."FINDINGS_UNAUDITED"
         , latest_metrics."FIRST_OCCURRENCE"
         , latest_metrics."HIGH"
         , latest_metrics."KEV"
         , latest_metrics."RISKSCORE"
         , latest_metrics."LAST_OCCURRENCE"
         , latest_metrics."LOW"
         , latest_metrics."MEDIUM"
         , latest_metrics."POLICYVIOLATIONS_AUDITED"
         , latest_metrics."POLICYVIOLATIONS_FAIL"
         , latest_metrics."POLICYVIOLATIONS_INFO"
         , latest_metrics."POLICYVIOLATIONS_LICENSE_AUDITED"
         , latest_metrics."POLICYVIOLATIONS_LICENSE_TOTAL"
         , latest_metrics."POLICYVIOLATIONS_LICENSE_UNAUDITED"
         , latest_metrics."POLICYVIOLATIONS_OPERATIONAL_AUDITED"
         , latest_metrics."POLICYVIOLATIONS_OPERATIONAL_TOTAL"
         , latest_metrics."POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
         , latest_metrics."POLICYVIOLATIONS_SECURITY_AUDITED"
         , latest_metrics."POLICYVIOLATIONS_SECURITY_TOTAL"
         , latest_metrics."POLICYVIOLATIONS_SECURITY_UNAUDITED"
         , latest_metrics."POLICYVIOLATIONS_TOTAL"
         , latest_metrics."POLICYVIOLATIONS_UNAUDITED"
         , latest_metrics."POLICYVIOLATIONS_WARN"
         , latest_metrics."PROJECT_ID"
         , latest_metrics."SUPPRESSED"
         , latest_metrics."UNASSIGNED_SEVERITY"
         , latest_metrics."VULNERABILITIES"
         , latest_metrics."VULNERABLECOMPONENTS"
      FROM date_range
      LEFT JOIN LATERAL (
        SELECT DISTINCT ON (pm."PROJECT_ID")
               pm."COMPONENTS"
             , pm."CRITICAL"
             , pm."FINDINGS_AUDITED"
             , pm."FINDINGS_TOTAL"
             , pm."FINDINGS_UNAUDITED"
             , pm."FIRST_OCCURRENCE"
             , pm."HIGH"
             , pm."KEV"
             , pm."RISKSCORE"
             , pm."LAST_OCCURRENCE"
             , pm."LOW"
             , pm."MEDIUM"
             , pm."POLICYVIOLATIONS_AUDITED"
             , pm."POLICYVIOLATIONS_FAIL"
             , pm."POLICYVIOLATIONS_INFO"
             , pm."POLICYVIOLATIONS_LICENSE_AUDITED"
             , pm."POLICYVIOLATIONS_LICENSE_TOTAL"
             , pm."POLICYVIOLATIONS_LICENSE_UNAUDITED"
             , pm."POLICYVIOLATIONS_OPERATIONAL_AUDITED"
             , pm."POLICYVIOLATIONS_OPERATIONAL_TOTAL"
             , pm."POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
             , pm."POLICYVIOLATIONS_SECURITY_AUDITED"
             , pm."POLICYVIOLATIONS_SECURITY_TOTAL"
             , pm."POLICYVIOLATIONS_SECURITY_UNAUDITED"
             , pm."POLICYVIOLATIONS_TOTAL"
             , pm."POLICYVIOLATIONS_UNAUDITED"
             , pm."POLICYVIOLATIONS_WARN"
             , pm."PROJECT_ID"
             , pm."SUPPRESSED"
             , pm."UNASSIGNED_SEVERITY"
             , pm."VULNERABILITIES"
             , pm."VULNERABLECOMPONENTS"
          FROM "PROJECT" p
          JOIN "PROJECTMETRICS" pm
            ON pm."PROJECT_ID" = p."ID"
           AND p."INACTIVE_SINCE" IS NULL
           AND p."COLLECTION_LOGIC" IS NULL
         WHERE pm."LAST_OCCURRENCE" < (date_range.metrics_date + '1 day'::INTERVAL) AT TIME ZONE 'UTC'
           AND pm."LAST_OCCURRENCE" >= (date_range.metrics_date - '1 day'::INTERVAL) AT TIME ZONE 'UTC'
         ORDER BY pm."PROJECT_ID"
                , pm."LAST_OCCURRENCE" DESC
      ) latest_metrics ON (true)
  ),
  daily_metrics AS (
    SELECT count(DISTINCT latest_daily_project_metrics."PROJECT_ID") AS projects
         , sum(latest_daily_project_metrics."COMPONENTS") AS components
         , sum(latest_daily_project_metrics."CRITICAL") AS critical
         , latest_daily_project_metrics.metrics_date
         , sum(latest_daily_project_metrics."FINDINGS_AUDITED") AS findings_audited
         , sum(latest_daily_project_metrics."FINDINGS_TOTAL") AS findings_total
         , sum(latest_daily_project_metrics."FINDINGS_UNAUDITED") AS findings_unaudited
         , sum(latest_daily_project_metrics."HIGH") AS high
         , sum(latest_daily_project_metrics."KEV") AS kev
         , sum(latest_daily_project_metrics."RISKSCORE") AS inherited_risk_score
         , sum(latest_daily_project_metrics."LOW") AS low
         , sum(latest_daily_project_metrics."MEDIUM") AS medium
         , sum(latest_daily_project_metrics."POLICYVIOLATIONS_AUDITED") AS policy_violations_audited
         , sum(latest_daily_project_metrics."POLICYVIOLATIONS_FAIL") AS policy_violations_fail
         , sum(latest_daily_project_metrics."POLICYVIOLATIONS_INFO") AS policy_violations_info
         , sum(latest_daily_project_metrics."POLICYVIOLATIONS_LICENSE_AUDITED") AS policy_violations_license_audited
         , sum(latest_daily_project_metrics."POLICYVIOLATIONS_LICENSE_TOTAL") AS policy_violations_license_total
         , sum(latest_daily_project_metrics."POLICYVIOLATIONS_LICENSE_UNAUDITED") AS policy_violations_license_unaudited
         , sum(latest_daily_project_metrics."POLICYVIOLATIONS_OPERATIONAL_AUDITED") AS policy_violations_operational_audited
         , sum(latest_daily_project_metrics."POLICYVIOLATIONS_OPERATIONAL_TOTAL") AS policy_violations_operational_total
         , sum(latest_daily_project_metrics."POLICYVIOLATIONS_OPERATIONAL_UNAUDITED") AS policy_violations_operational_unaudited
         , sum(latest_daily_project_metrics."POLICYVIOLATIONS_SECURITY_AUDITED") AS policy_violations_security_audited
         , sum(latest_daily_project_metrics."POLICYVIOLATIONS_SECURITY_TOTAL") AS policy_violations_security_total
         , sum(latest_daily_project_metrics."POLICYVIOLATIONS_SECURITY_UNAUDITED") AS policy_violations_security_unaudited
         , sum(latest_daily_project_metrics."POLICYVIOLATIONS_TOTAL") AS policy_violations_total
         , sum(latest_daily_project_metrics."POLICYVIOLATIONS_UNAUDITED") AS policy_violations_unaudited
         , sum(latest_daily_project_metrics."POLICYVIOLATIONS_WARN") AS policy_violations_warn
         , sum(latest_daily_project_metrics."SUPPRESSED") AS suppressed
         , sum(latest_daily_project_metrics."UNASSIGNED_SEVERITY") AS unassigned
         , sum(latest_daily_project_metrics."VULNERABILITIES") AS vulnerabilities
         , sum(latest_daily_project_metrics."VULNERABLECOMPONENTS") AS vulnerable_components
         , sum(
             CASE
               WHEN latest_daily_project_metrics."VULNERABLECOMPONENTS" > 0
               THEN 1
               ELSE 0
               END
           ) AS vulnerable_projects
      FROM latest_daily_project_metrics
     GROUP BY latest_daily_project_metrics.metrics_date
  )
  SELECT COALESCE(dm.components, (0)::bigint) AS "COMPONENTS"
       , COALESCE(dm.critical, (0)::bigint) AS "CRITICAL"
       , COALESCE(dm.findings_audited, (0)::bigint) AS "FINDINGS_AUDITED"
       , COALESCE(dm.findings_total, (0)::bigint) AS "FINDINGS_TOTAL"
       , COALESCE(dm.findings_unaudited, (0)::bigint) AS "FINDINGS_UNAUDITED"
       , date_range.metrics_date AS "FIRST_OCCURRENCE"
       , COALESCE(dm.high, (0)::bigint) AS "HIGH"
       , COALESCE(dm.kev, (0)::bigint) AS "KEV"
       , COALESCE(dm.inherited_risk_score, (0)::double precision) AS "INHERITED_RISK_SCORE"
       , date_range.metrics_date AS "LAST_OCCURRENCE"
       , COALESCE(dm.low, (0)::bigint) AS "LOW"
       , COALESCE(dm.medium, (0)::bigint) AS "MEDIUM"
       , COALESCE(dm.policy_violations_audited, (0)::bigint) AS "POLICY_VIOLATIONS_AUDITED"
       , COALESCE(dm.policy_violations_fail, (0)::bigint) AS "POLICY_VIOLATIONS_FAIL"
       , COALESCE(dm.policy_violations_info, (0)::bigint) AS "POLICY_VIOLATIONS_INFO"
       , COALESCE(dm.policy_violations_license_audited, (0)::bigint) AS "POLICY_VIOLATIONS_LICENSE_AUDITED"
       , COALESCE(dm.policy_violations_license_total, (0)::bigint) AS "POLICY_VIOLATIONS_LICENSE_TOTAL"
       , COALESCE(dm.policy_violations_license_unaudited, (0)::bigint) AS "POLICY_VIOLATIONS_LICENSE_UNAUDITED"
       , COALESCE(dm.policy_violations_operational_audited, (0)::bigint) AS "POLICY_VIOLATIONS_OPERATIONAL_AUDITED"
       , COALESCE(dm.policy_violations_operational_total, (0)::bigint) AS "POLICY_VIOLATIONS_OPERATIONAL_TOTAL"
       , COALESCE(dm.policy_violations_operational_unaudited, (0)::bigint) AS "POLICY_VIOLATIONS_OPERATIONAL_UNAUDITED"
       , COALESCE(dm.policy_violations_security_audited, (0)::bigint) AS "POLICY_VIOLATIONS_SECURITY_AUDITED"
       , COALESCE(dm.policy_violations_security_total, (0)::bigint) AS "POLICY_VIOLATIONS_SECURITY_TOTAL"
       , COALESCE(dm.policy_violations_security_unaudited, (0)::bigint) AS "POLICY_VIOLATIONS_SECURITY_UNAUDITED"
       , COALESCE(dm.policy_violations_total, (0)::bigint) AS "POLICY_VIOLATIONS_TOTAL"
       , COALESCE(dm.policy_violations_unaudited, (0)::bigint) AS "POLICY_VIOLATIONS_UNAUDITED"
       , COALESCE(dm.policy_violations_warn, (0)::bigint) AS "POLICY_VIOLATIONS_WARN"
       , COALESCE(dm.projects, (0)::bigint) AS "PROJECTS"
       , COALESCE(dm.suppressed, (0)::bigint) AS "SUPPRESSED"
       , COALESCE(dm.unassigned, (0)::bigint) AS "UNASSIGNED"
       , COALESCE(dm.vulnerabilities, (0)::bigint) AS "VULNERABILITIES"
       , COALESCE(dm.vulnerable_components, (0)::bigint) AS "VULNERABLE_COMPONENTS"
       , COALESCE(dm.vulnerable_projects, (0)::bigint) AS "VULNERABLE_PROJECTS"
    FROM date_range
    LEFT JOIN daily_metrics dm
      ON date_range.metrics_date = dm.metrics_date
  WITH NO DATA;

-- squawk-ignore require-concurrent-index-creation
CREATE UNIQUE INDEX IF NOT EXISTS "PORTFOLIOMETRICS_GLOBAL_LAST_OCCURRENCE_IDX" ON "PORTFOLIOMETRICS_GLOBAL" USING btree ("LAST_OCCURRENCE");

REFRESH MATERIALIZED VIEW "PORTFOLIOMETRICS_GLOBAL";
