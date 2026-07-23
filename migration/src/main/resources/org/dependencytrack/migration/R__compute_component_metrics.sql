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
  vuln_deduped AS (
    SELECT DISTINCT ON (cv."COMPONENT_ID", va."GROUP_ID", CASE WHEN va."GROUP_ID" IS NULL THEN v."ID" END)
           cv."COMPONENT_ID" AS component_id
         , COALESCE(a."SEVERITY", v."SEVERITY") AS effective_severity
         , EXISTS (
             SELECT 1
               FROM "KEV_ASSERTION" AS ka
              WHERE (ka."VULN_SOURCE", ka."VULN_ID") IN (
                SELECT v."SOURCE", v."VULNID"
                 UNION
                SELECT alias_sibling."SOURCE", alias_sibling."VULN_ID"
                  FROM "VULNERABILITY_ALIAS" AS alias_sibling
                 WHERE alias_sibling."GROUP_ID" = va."GROUP_ID"
              )
           ) AS is_kev
      FROM "COMPONENTS_VULNERABILITIES" AS cv
     INNER JOIN comp
        ON comp.id = cv."COMPONENT_ID"
     INNER JOIN "VULNERABILITY" AS v
        ON v."ID" = cv."VULNERABILITY_ID"
      LEFT JOIN "ANALYSIS" AS a
        ON a."COMPONENT_ID" = cv."COMPONENT_ID"
       AND a."VULNERABILITY_ID" = v."ID"
      LEFT JOIN "VULNERABILITY_ALIAS" AS va
        ON va."SOURCE" = v."SOURCE"
       AND va."VULN_ID" = v."VULNID"
     WHERE a."SUPPRESSED" IS DISTINCT FROM TRUE
       AND EXISTS(
         SELECT 1 FROM "FINDINGATTRIBUTION" AS fa
          WHERE fa."COMPONENT_ID" = cv."COMPONENT_ID"
            AND fa."VULNERABILITY_ID" = cv."VULNERABILITY_ID"
            AND fa."DELETED_AT" IS NULL
       )
     ORDER BY cv."COMPONENT_ID"
            , va."GROUP_ID"
            , CASE WHEN va."GROUP_ID" IS NULL THEN v."ID" END
            , COALESCE(a."SEVERITY", v."SEVERITY") DESC
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
  ),
  analysis_counts AS (
    SELECT a."COMPONENT_ID" AS component_id
         , COUNT(*) FILTER (
             WHERE a."SUPPRESSED" = FALSE
               AND a."STATE" NOT IN ('NOT_SET', 'IN_TRIAGE')
           )::INT AS findings_audited
         , COUNT(*) FILTER (WHERE a."SUPPRESSED" = TRUE)::INT AS findings_suppressed
      FROM "ANALYSIS" AS a
     INNER JOIN comp
        ON comp.id = a."COMPONENT_ID"
     WHERE EXISTS(
       SELECT 1 FROM "FINDINGATTRIBUTION" AS fa
        WHERE fa."COMPONENT_ID" = a."COMPONENT_ID"
          AND fa."VULNERABILITY_ID" = a."VULNERABILITY_ID"
          AND fa."DELETED_AT" IS NULL
     )
     GROUP BY a."COMPONENT_ID"
  ),
  violation_counts AS (
    SELECT pv."COMPONENT_ID" AS component_id
         , COUNT(*)::INT AS total
         , COUNT(*) FILTER (WHERE p."VIOLATIONSTATE" = 'FAIL')::INT AS fail
         , COUNT(*) FILTER (WHERE p."VIOLATIONSTATE" = 'WARN')::INT AS warn
         , COUNT(*) FILTER (WHERE p."VIOLATIONSTATE" = 'INFO')::INT AS info
         , COUNT(*) FILTER (WHERE pv."TYPE" = 'LICENSE')::INT AS license_total
         , COUNT(*) FILTER (WHERE pv."TYPE" = 'OPERATIONAL')::INT AS operational_total
         , COUNT(*) FILTER (WHERE pv."TYPE" = 'SECURITY')::INT AS security_total
      FROM "POLICYVIOLATION" AS pv
     INNER JOIN comp
        ON comp.id = pv."COMPONENT_ID"
     INNER JOIN "POLICYCONDITION" AS pc
        ON pv."POLICYCONDITION_ID" = pc."ID"
     INNER JOIN "POLICY" AS p
        ON pc."POLICY_ID" = p."ID"
      LEFT JOIN "VIOLATIONANALYSIS" AS va
        ON va."COMPONENT_ID" = pv."COMPONENT_ID"
       AND va."POLICYVIOLATION_ID" = pv."ID"
     WHERE (va IS NULL OR va."SUPPRESSED" = FALSE)
     GROUP BY pv."COMPONENT_ID"
  ),
  violation_audit_counts AS (
    SELECT va."COMPONENT_ID" AS component_id
         , COUNT(*) FILTER (WHERE pv."TYPE" = 'LICENSE')::INT AS license_audited
         , COUNT(*) FILTER (WHERE pv."TYPE" = 'OPERATIONAL')::INT AS operational_audited
         , COUNT(*) FILTER (WHERE pv."TYPE" = 'SECURITY')::INT AS security_audited
      FROM "VIOLATIONANALYSIS" AS va
     INNER JOIN comp
        ON comp.id = va."COMPONENT_ID"
     INNER JOIN "POLICYVIOLATION" AS pv
        ON pv."ID" = va."POLICYVIOLATION_ID"
     WHERE va."SUPPRESSED" = FALSE
       AND va."STATE" != 'NOT_SET'
     GROUP BY va."COMPONENT_ID"
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
       , COALESCE(ac.findings_audited, 0)
       , COALESCE(vc.vulnerabilities, 0) - COALESCE(ac.findings_audited, 0)
       , COALESCE(ac.findings_suppressed, 0)
       , COALESCE(pvc.total, 0)
       , COALESCE(pvc.fail, 0)
       , COALESCE(pvc.warn, 0)
       , COALESCE(pvc.info, 0)
       , COALESCE(pvac.license_audited, 0)
         + COALESCE(pvac.operational_audited, 0)
         + COALESCE(pvac.security_audited, 0)
       , COALESCE(pvc.total, 0)
         - (COALESCE(pvac.license_audited, 0)
            + COALESCE(pvac.operational_audited, 0)
            + COALESCE(pvac.security_audited, 0))
       , COALESCE(pvc.license_total, 0)
       , COALESCE(pvac.license_audited, 0)
       , COALESCE(pvc.license_total, 0) - COALESCE(pvac.license_audited, 0)
       , COALESCE(pvc.operational_total, 0)
       , COALESCE(pvac.operational_audited, 0)
       , COALESCE(pvc.operational_total, 0) - COALESCE(pvac.operational_audited, 0)
       , COALESCE(pvc.security_total, 0)
       , COALESCE(pvac.security_audited, 0)
       , COALESCE(pvc.security_total, 0) - COALESCE(pvac.security_audited, 0)
    FROM comp
   CROSS JOIN risk_score_weights
    LEFT JOIN vuln_counts AS vc
      ON vc.component_id = comp.id
    LEFT JOIN analysis_counts AS ac
      ON ac.component_id = comp.id
    LEFT JOIN violation_counts AS pvc
      ON pvc.component_id = comp.id
    LEFT JOIN violation_audit_counts AS pvac
      ON pvac.component_id = comp.id
$$;
