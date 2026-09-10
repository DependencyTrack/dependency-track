-- NB: CREATE OR REPLACE cannot change a function's return type,
-- so adding or removing a RETURNS TABLE column would fail on existing databases.
-- Drop first to keep this migration repeatable even when new return columns are added.
DROP FUNCTION IF EXISTS "COMPUTE_COMPONENT_METRICS"(BIGINT[]);

CREATE FUNCTION "COMPUTE_COMPONENT_METRICS"(
  component_ids BIGINT[]
)
  RETURNS TABLE (
    component_id BIGINT
  , vulnerabilities INT
  , critical INT
  , high INT
  , medium INT
  , low INT
  , unassigned INT
  , kev INT
  , risk_score NUMERIC
  , findings_total INT
  , findings_audited INT
  , findings_unaudited INT
  , findings_suppressed INT
  , policy_violations_total INT
  , policy_violations_fail INT
  , policy_violations_warn INT
  , policy_violations_info INT
  , policy_violations_audited INT
  , policy_violations_unaudited INT
  , policy_violations_license_total INT
  , policy_violations_license_audited INT
  , policy_violations_license_unaudited INT
  , policy_violations_operational_total INT
  , policy_violations_operational_audited INT
  , policy_violations_operational_unaudited INT
  , policy_violations_security_total INT
  , policy_violations_security_audited INT
  , policy_violations_security_unaudited INT
  )
  LANGUAGE "sql"
  STABLE
AS
$$
  WITH comp AS (
    SELECT UNNEST(component_ids) AS id
  ),
  risk_score_weights AS (
    SELECT MAX("PROPERTYVALUE"::INT) FILTER (WHERE "PROPERTYNAME" = 'weight.critical') AS w_critical
         , MAX("PROPERTYVALUE"::INT) FILTER (WHERE "PROPERTYNAME" = 'weight.high') AS w_high
         , MAX("PROPERTYVALUE"::INT) FILTER (WHERE "PROPERTYNAME" = 'weight.medium') AS w_medium
         , MAX("PROPERTYVALUE"::INT) FILTER (WHERE "PROPERTYNAME" = 'weight.low') AS w_low
         , MAX("PROPERTYVALUE"::INT) FILTER (WHERE "PROPERTYNAME" = 'weight.unassigned') AS w_unassigned
      FROM "CONFIGPROPERTY"
     WHERE "GROUPNAME" = 'risk-score'
       AND "PROPERTYTYPE" = 'INTEGER'
  ),
  components_vulns AS (
    SELECT cv.component_id
         , cv.vulnerability_id
         , cv.analysis_severity
         , cv.analysis_suppressed
      FROM comp
     CROSS JOIN LATERAL (
       -- Fetch analyses once per component, not once per finding. Forced via MATERIALIZED.
       -- Don't want this to fire N times if a component is affected by N vulns.
       WITH a AS MATERIALIZED (
         SELECT "VULNERABILITY_ID", "SEVERITY", "SUPPRESSED"
           FROM "ANALYSIS"
          WHERE "COMPONENT_ID" = comp.id
       )
       SELECT cv."COMPONENT_ID" AS component_id
            , cv."VULNERABILITY_ID" AS vulnerability_id
            , a."SEVERITY" AS analysis_severity
            , a."SUPPRESSED" AS analysis_suppressed
         FROM "COMPONENTS_VULNERABILITIES" AS cv
         LEFT JOIN a
           ON a."VULNERABILITY_ID" = cv."VULNERABILITY_ID"
        WHERE cv."COMPONENT_ID" = comp.id
          AND EXISTS(
            SELECT 1
              FROM "FINDINGATTRIBUTION" AS fa
             WHERE fa."COMPONENT_ID" = cv."COMPONENT_ID"
               AND fa."VULNERABILITY_ID" = cv."VULNERABILITY_ID"
               AND fa."DELETED_AT" IS NULL
          )
       -- Prevent the planner from inlining this subquery (https://stackoverflow.com/a/14897817).
       -- Naively joining `comp` with COMPONENT_VULNERABILITIES has been observed to produce
       -- bad query plans due to inaccurate n_distinct statistics on the COMPONENT_ID column of the latter.
       -- By forcing a for-each access pattern, every component gets a predictable index lookup regardless of bad stats.
       OFFSET 0
     ) AS cv
  ),
  kev_alias_group AS MATERIALIZED (
    SELECT DISTINCT va."GROUP_ID" AS group_id
      FROM "VULNERABILITY" AS v
     INNER JOIN "VULNERABILITY_ALIAS" AS va
        ON va."SOURCE" = v."SOURCE"
       AND va."VULN_ID" = v."VULNID"
     INNER JOIN "VULNERABILITY_ALIAS" AS va2
        ON va2."GROUP_ID" = va."GROUP_ID"
     INNER JOIN "KEV_ASSERTION" AS ka
        ON ka."VULN_SOURCE" = va2."SOURCE"
       AND ka."VULN_ID" = va2."VULN_ID"
     WHERE v."ID" IN (SELECT vulnerability_id FROM components_vulns)
  ),
  -- Resolve alias groups once per vulnerability rather than once per
  -- component-vulnerability pair, which could lead to a nested loop
  -- over VULNERABILITY_ALIAS.
  --
  -- NB: MATERIALIZED is required to prevent the CTE from getting inlined,
  -- which would defeat its purpose.
  vuln_alias_group AS MATERIALIZED (
    SELECT v."ID" AS vulnerability_id
         , v."SEVERITY" AS severity
         , va."GROUP_ID" AS group_id
         , (
             EXISTS (
               SELECT 1
                 FROM kev_alias_group AS kag
                WHERE kag.group_id = va."GROUP_ID"
             )
             OR EXISTS (
               SELECT 1
                 FROM "KEV_ASSERTION" AS ka
                WHERE ka."VULN_SOURCE" = v."SOURCE"
                  AND ka."VULN_ID" = v."VULNID"
             )
           ) AS is_kev
      FROM "VULNERABILITY" AS v
      LEFT JOIN "VULNERABILITY_ALIAS" AS va
        ON va."SOURCE" = v."SOURCE"
       AND va."VULN_ID" = v."VULNID"
     WHERE v."ID" IN (SELECT vulnerability_id FROM components_vulns)
  ),
  vuln_deduped AS (
    SELECT DISTINCT ON (cvs.component_id, vag.group_id, CASE WHEN vag.group_id IS NULL THEN vag.vulnerability_id END)
           cvs.component_id AS component_id
         , COALESCE(cvs.analysis_severity, vag.severity) AS effective_severity
         , vag.is_kev AS is_kev
      FROM components_vulns AS cvs
     INNER JOIN vuln_alias_group AS vag
        ON vag.vulnerability_id = cvs.vulnerability_id
     WHERE cvs.analysis_suppressed IS DISTINCT FROM TRUE
     ORDER BY cvs.component_id
            , vag.group_id
            , CASE WHEN vag.group_id IS NULL THEN vag.vulnerability_id END
            , COALESCE(cvs.analysis_severity, vag.severity) DESC
  ),
  vuln_counts AS (
    SELECT vuln_deduped.component_id
         , COUNT(*)::INT AS vulnerabilities
         , COUNT(*) FILTER (WHERE effective_severity = 'CRITICAL')::INT AS critical
         , COUNT(*) FILTER (WHERE effective_severity = 'HIGH')::INT AS high
         , COUNT(*) FILTER (WHERE effective_severity = 'MEDIUM')::INT AS medium
         , COUNT(*) FILTER (WHERE effective_severity = 'LOW')::INT AS low
         , COUNT(*) FILTER (WHERE effective_severity NOT IN ('CRITICAL','HIGH','MEDIUM','LOW'))::INT AS unassigned
         , COUNT(*) FILTER (WHERE is_kev)::INT AS kev
      FROM vuln_deduped
     GROUP BY vuln_deduped.component_id
  )
  SELECT comp.id
       , COALESCE(vc.vulnerabilities, 0)
       , COALESCE(vc.critical, 0)
       , COALESCE(vc.high, 0)
       , COALESCE(vc.medium, 0)
       , COALESCE(vc.low, 0)
       , COALESCE(vc.unassigned, 0)
       , COALESCE(vc.kev, 0)
       , COALESCE(
           COALESCE(vc.critical, 0) * risk_score_weights.w_critical
           + COALESCE(vc.high, 0) * risk_score_weights.w_high
           + COALESCE(vc.medium, 0) * risk_score_weights.w_medium
           + COALESCE(vc.low, 0) * risk_score_weights.w_low
           + COALESCE(vc.unassigned, 0) * risk_score_weights.w_unassigned
         , 0)::NUMERIC
       , COALESCE(vc.vulnerabilities, 0)
       , ac.findings_audited
       , COALESCE(vc.vulnerabilities, 0) - ac.findings_audited
       , ac.findings_suppressed
       , pvc.total
       , pvc.fail
       , pvc.warn
       , pvc.info
       , pvac.license_audited
         + pvac.operational_audited
         + pvac.security_audited
       , pvc.total
         - (pvac.license_audited
            + pvac.operational_audited
            + pvac.security_audited)
       , pvc.license_total
       , pvac.license_audited
       , pvc.license_total - pvac.license_audited
       , pvc.operational_total
       , pvac.operational_audited
       , pvc.operational_total - pvac.operational_audited
       , pvc.security_total
       , pvac.security_audited
       , pvc.security_total - pvac.security_audited
    FROM comp
   CROSS JOIN risk_score_weights
    LEFT JOIN vuln_counts AS vc
      ON vc.component_id = comp.id
   CROSS JOIN LATERAL (
     SELECT COUNT(*) FILTER (
              WHERE a."SUPPRESSED" = FALSE
                AND a."STATE" NOT IN ('NOT_SET', 'IN_TRIAGE')
            )::INT AS findings_audited
          , COUNT(*) FILTER (WHERE a."SUPPRESSED" = TRUE)::INT AS findings_suppressed
       FROM (
         SELECT "COMPONENT_ID", "VULNERABILITY_ID", "STATE", "SUPPRESSED"
           FROM "ANALYSIS"
          WHERE "COMPONENT_ID" = comp.id
         OFFSET 0
       ) AS a
      WHERE EXISTS(
          SELECT 1 FROM "FINDINGATTRIBUTION" AS fa
           WHERE fa."COMPONENT_ID" = a."COMPONENT_ID"
             AND fa."VULNERABILITY_ID" = a."VULNERABILITY_ID"
             AND fa."DELETED_AT" IS NULL
        )
   ) AS ac
   CROSS JOIN LATERAL (
     SELECT COUNT(*)::INT AS total
          , COUNT(*) FILTER (WHERE p."VIOLATIONSTATE" = 'FAIL')::INT AS fail
          , COUNT(*) FILTER (WHERE p."VIOLATIONSTATE" = 'WARN')::INT AS warn
          , COUNT(*) FILTER (WHERE p."VIOLATIONSTATE" = 'INFO')::INT AS info
          , COUNT(*) FILTER (WHERE pv."TYPE" = 'LICENSE')::INT AS license_total
          , COUNT(*) FILTER (WHERE pv."TYPE" = 'OPERATIONAL')::INT AS operational_total
          , COUNT(*) FILTER (WHERE pv."TYPE" = 'SECURITY')::INT AS security_total
       FROM "POLICYVIOLATION" AS pv
      INNER JOIN "POLICYCONDITION" AS pc
         ON pv."POLICYCONDITION_ID" = pc."ID"
      INNER JOIN "POLICY" AS p
         ON pc."POLICY_ID" = p."ID"
       LEFT JOIN "VIOLATIONANALYSIS" AS va
         ON va."COMPONENT_ID" = pv."COMPONENT_ID"
        AND va."POLICYVIOLATION_ID" = pv."ID"
      WHERE pv."COMPONENT_ID" = comp.id
        AND (va IS NULL OR va."SUPPRESSED" = FALSE)
   ) AS pvc
   CROSS JOIN LATERAL (
     SELECT COUNT(*) FILTER (WHERE pv."TYPE" = 'LICENSE')::INT AS license_audited
          , COUNT(*) FILTER (WHERE pv."TYPE" = 'OPERATIONAL')::INT AS operational_audited
          , COUNT(*) FILTER (WHERE pv."TYPE" = 'SECURITY')::INT AS security_audited
       FROM "VIOLATIONANALYSIS" AS va
      INNER JOIN "POLICYVIOLATION" AS pv
         ON pv."ID" = va."POLICYVIOLATION_ID"
      WHERE va."COMPONENT_ID" = comp.id
        AND va."SUPPRESSED" = FALSE
        AND va."STATE" != 'NOT_SET'
   ) AS pvac
$$;
