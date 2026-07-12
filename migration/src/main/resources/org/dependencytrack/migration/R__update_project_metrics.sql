CREATE OR REPLACE PROCEDURE "UPDATE_PROJECT_METRICS"(
  project_uuid UUID
)
  LANGUAGE "plpgsql"
AS
$$
DECLARE
  v_project_id   BIGINT; -- ID of the project to update metrics for
  v_today        TIMESTAMPTZ := DATE_TRUNC('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
  v_project      RECORD; -- Aggregated project-level metrics
BEGIN
  SELECT "ID"
    INTO v_project_id
    FROM "PROJECT"
   WHERE "UUID" = project_uuid
     AND "COLLECTION_LOGIC" IS NULL;
  IF v_project_id IS NULL THEN
    RETURN;
  END IF;

  WITH computed AS (
    SELECT *
      FROM "COMPUTE_COMPONENT_METRICS"(
        ARRAY(
          SELECT "ID"
            FROM "COMPONENT"
           WHERE "PROJECT_ID" = v_project_id
        )
      )
  ),
  classified AS (
    SELECT c.*
         , (
             l."VULNERABILITIES"
           , l."CRITICAL"
           , l."HIGH"
           , l."MEDIUM"
           , l."LOW"
           , l."UNASSIGNED_SEVERITY"
           , l."RISKSCORE"
           , l."FINDINGS_TOTAL"
           , l."FINDINGS_AUDITED"
           , l."FINDINGS_UNAUDITED"
           , l."SUPPRESSED"
           , l."POLICYVIOLATIONS_TOTAL"
           , l."POLICYVIOLATIONS_FAIL"
           , l."POLICYVIOLATIONS_WARN"
           , l."POLICYVIOLATIONS_INFO"
           , l."POLICYVIOLATIONS_AUDITED"
           , l."POLICYVIOLATIONS_UNAUDITED"
           , l."POLICYVIOLATIONS_LICENSE_TOTAL"
           , l."POLICYVIOLATIONS_LICENSE_AUDITED"
           , l."POLICYVIOLATIONS_LICENSE_UNAUDITED"
           , l."POLICYVIOLATIONS_OPERATIONAL_TOTAL"
           , l."POLICYVIOLATIONS_OPERATIONAL_AUDITED"
           , l."POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
           , l."POLICYVIOLATIONS_SECURITY_TOTAL"
           , l."POLICYVIOLATIONS_SECURITY_AUDITED"
           , l."POLICYVIOLATIONS_SECURITY_UNAUDITED"
           ) IS NOT DISTINCT FROM (
             c.vulnerabilities
           , c.critical
           , c.high
           , c.medium
           , c.low
           , c.unassigned
           , c.risk_score
           , c.findings_total
           , c.findings_audited
           , c.findings_unaudited
           , c.findings_suppressed
           , c.policy_violations_total
           , c.policy_violations_fail
           , c.policy_violations_warn
           , c.policy_violations_info
           , c.policy_violations_audited
           , c.policy_violations_unaudited
           , c.policy_violations_license_total
           , c.policy_violations_license_audited
           , c.policy_violations_license_unaudited
           , c.policy_violations_operational_total
           , c.policy_violations_operational_audited
           , c.policy_violations_operational_unaudited
           , c.policy_violations_security_total
           , c.policy_violations_security_audited
           , c.policy_violations_security_unaudited
           ) AS unchanged
      FROM computed AS c
      LEFT JOIN LATERAL (
        SELECT *
          FROM "DEPENDENCYMETRICS"
         WHERE "COMPONENT_ID" = c.component_id
           AND "LAST_OCCURRENCE" >= v_today
         ORDER BY "LAST_OCCURRENCE" DESC
         LIMIT 1
      ) AS l ON TRUE
  ),
  inserted AS (
    INSERT INTO "DEPENDENCYMETRICS" (
      "COMPONENT_ID"
    , "PROJECT_ID"
    , "VULNERABILITIES"
    , "CRITICAL"
    , "HIGH"
    , "MEDIUM"
    , "LOW"
    , "UNASSIGNED_SEVERITY"
    , "RISKSCORE"
    , "FINDINGS_TOTAL"
    , "FINDINGS_AUDITED"
    , "FINDINGS_UNAUDITED"
    , "SUPPRESSED"
    , "POLICYVIOLATIONS_TOTAL"
    , "POLICYVIOLATIONS_FAIL"
    , "POLICYVIOLATIONS_WARN"
    , "POLICYVIOLATIONS_INFO"
    , "POLICYVIOLATIONS_AUDITED"
    , "POLICYVIOLATIONS_UNAUDITED"
    , "POLICYVIOLATIONS_LICENSE_TOTAL"
    , "POLICYVIOLATIONS_LICENSE_AUDITED"
    , "POLICYVIOLATIONS_LICENSE_UNAUDITED"
    , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"
    , "POLICYVIOLATIONS_OPERATIONAL_AUDITED"
    , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
    , "POLICYVIOLATIONS_SECURITY_TOTAL"
    , "POLICYVIOLATIONS_SECURITY_AUDITED"
    , "POLICYVIOLATIONS_SECURITY_UNAUDITED"
    , "FIRST_OCCURRENCE"
    , "LAST_OCCURRENCE"
    )
    SELECT component_id
         , v_project_id
         , vulnerabilities
         , critical
         , high
         , medium
         , low
         , unassigned
         , risk_score
         , findings_total
         , findings_audited
         , findings_unaudited
         , findings_suppressed
         , policy_violations_total
         , policy_violations_fail
         , policy_violations_warn
         , policy_violations_info
         , policy_violations_audited
         , policy_violations_unaudited
         , policy_violations_license_total
         , policy_violations_license_audited
         , policy_violations_license_unaudited
         , policy_violations_operational_total
         , policy_violations_operational_audited
         , policy_violations_operational_unaudited
         , policy_violations_security_total
         , policy_violations_security_audited
         , policy_violations_security_unaudited
         , NOW()
         , NOW()
      FROM classified
     WHERE NOT unchanged
  ),
  component_updates AS (
    UPDATE "COMPONENT"
       SET "LAST_RISKSCORE" = c.risk_score
      FROM classified AS c
     WHERE "COMPONENT"."ID" = c.component_id
       AND "COMPONENT"."LAST_RISKSCORE" IS DISTINCT FROM c.risk_score
  )
  SELECT COUNT(*)::INT AS components
       , COALESCE(SUM(CASE WHEN vulnerabilities > 0 THEN 1 ELSE 0 END)::INT, 0) AS vulnerable_components
       , COALESCE(SUM(vulnerabilities)::INT, 0) AS vulnerabilities
       , COALESCE(SUM(critical)::INT, 0) AS critical
       , COALESCE(SUM(high)::INT, 0) AS high
       , COALESCE(SUM(medium)::INT, 0) AS medium
       , COALESCE(SUM(low)::INT, 0) AS low
       , COALESCE(SUM(unassigned)::INT, 0) AS unassigned
       , COALESCE(SUM(findings_total)::INT, 0) AS findings_total
       , COALESCE(SUM(findings_audited)::INT, 0) AS findings_audited
       , COALESCE(SUM(findings_unaudited)::INT, 0) AS findings_unaudited
       , COALESCE(SUM(findings_suppressed)::INT, 0) AS findings_suppressed
       , COALESCE(SUM(policy_violations_total)::INT, 0) AS policy_violations_total
       , COALESCE(SUM(policy_violations_fail)::INT, 0) AS policy_violations_fail
       , COALESCE(SUM(policy_violations_warn)::INT, 0) AS policy_violations_warn
       , COALESCE(SUM(policy_violations_info)::INT, 0) AS policy_violations_info
       , COALESCE(SUM(policy_violations_audited)::INT, 0) AS policy_violations_audited
       , COALESCE(SUM(policy_violations_unaudited)::INT, 0) AS policy_violations_unaudited
       , COALESCE(SUM(policy_violations_license_total)::INT, 0) AS policy_violations_license_total
       , COALESCE(SUM(policy_violations_license_audited)::INT, 0) AS policy_violations_license_audited
       , COALESCE(SUM(policy_violations_license_unaudited)::INT, 0) AS policy_violations_license_unaudited
       , COALESCE(SUM(policy_violations_operational_total)::INT, 0) AS policy_violations_operational_total
       , COALESCE(SUM(policy_violations_operational_audited)::INT, 0) AS policy_violations_operational_audited
       , COALESCE(SUM(policy_violations_operational_unaudited)::INT, 0) AS policy_violations_operational_unaudited
       , COALESCE(SUM(policy_violations_security_total)::INT, 0) AS policy_violations_security_total
       , COALESCE(SUM(policy_violations_security_audited)::INT, 0) AS policy_violations_security_audited
       , COALESCE(SUM(policy_violations_security_unaudited)::INT, 0) AS policy_violations_security_unaudited
       , COALESCE(SUM(risk_score), 0)::NUMERIC AS risk_score
    FROM computed
    INTO v_project;

  IF NOT EXISTS (
    SELECT 1
      FROM (
        SELECT *
          FROM "PROJECTMETRICS"
         WHERE "PROJECT_ID" = v_project_id
           AND "LAST_OCCURRENCE" >= v_today
         ORDER BY "LAST_OCCURRENCE" DESC
         LIMIT 1
      ) AS pm
     WHERE (
             pm."COMPONENTS"
           , pm."VULNERABLECOMPONENTS"
           , pm."VULNERABILITIES"
           , pm."CRITICAL"
           , pm."HIGH"
           , pm."MEDIUM"
           , pm."LOW"
           , pm."UNASSIGNED_SEVERITY"
           , pm."RISKSCORE"
           , pm."FINDINGS_TOTAL"
           , pm."FINDINGS_AUDITED"
           , pm."FINDINGS_UNAUDITED"
           , pm."SUPPRESSED"
           , pm."POLICYVIOLATIONS_TOTAL"
           , pm."POLICYVIOLATIONS_FAIL"
           , pm."POLICYVIOLATIONS_WARN"
           , pm."POLICYVIOLATIONS_INFO"
           , pm."POLICYVIOLATIONS_AUDITED"
           , pm."POLICYVIOLATIONS_UNAUDITED"
           , pm."POLICYVIOLATIONS_LICENSE_TOTAL"
           , pm."POLICYVIOLATIONS_LICENSE_AUDITED"
           , pm."POLICYVIOLATIONS_LICENSE_UNAUDITED"
           , pm."POLICYVIOLATIONS_OPERATIONAL_TOTAL"
           , pm."POLICYVIOLATIONS_OPERATIONAL_AUDITED"
           , pm."POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
           , pm."POLICYVIOLATIONS_SECURITY_TOTAL"
           , pm."POLICYVIOLATIONS_SECURITY_AUDITED"
           , pm."POLICYVIOLATIONS_SECURITY_UNAUDITED"
           ) IS NOT DISTINCT FROM (
             v_project.components
           , v_project.vulnerable_components
           , v_project.vulnerabilities
           , v_project.critical
           , v_project.high
           , v_project.medium
           , v_project.low
           , v_project.unassigned
           , v_project.risk_score
           , v_project.findings_total
           , v_project.findings_audited
           , v_project.findings_unaudited
           , v_project.findings_suppressed
           , v_project.policy_violations_total
           , v_project.policy_violations_fail
           , v_project.policy_violations_warn
           , v_project.policy_violations_info
           , v_project.policy_violations_audited
           , v_project.policy_violations_unaudited
           , v_project.policy_violations_license_total
           , v_project.policy_violations_license_audited
           , v_project.policy_violations_license_unaudited
           , v_project.policy_violations_operational_total
           , v_project.policy_violations_operational_audited
           , v_project.policy_violations_operational_unaudited
           , v_project.policy_violations_security_total
           , v_project.policy_violations_security_audited
           , v_project.policy_violations_security_unaudited
           )
  ) THEN
    INSERT INTO "PROJECTMETRICS" (
      "PROJECT_ID"
    , "COMPONENTS"
    , "VULNERABLECOMPONENTS"
    , "VULNERABILITIES"
    , "CRITICAL"
    , "HIGH"
    , "MEDIUM"
    , "LOW"
    , "UNASSIGNED_SEVERITY"
    , "RISKSCORE"
    , "FINDINGS_TOTAL"
    , "FINDINGS_AUDITED"
    , "FINDINGS_UNAUDITED"
    , "SUPPRESSED"
    , "POLICYVIOLATIONS_TOTAL"
    , "POLICYVIOLATIONS_FAIL"
    , "POLICYVIOLATIONS_WARN"
    , "POLICYVIOLATIONS_INFO"
    , "POLICYVIOLATIONS_AUDITED"
    , "POLICYVIOLATIONS_UNAUDITED"
    , "POLICYVIOLATIONS_LICENSE_TOTAL"
    , "POLICYVIOLATIONS_LICENSE_AUDITED"
    , "POLICYVIOLATIONS_LICENSE_UNAUDITED"
    , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"
    , "POLICYVIOLATIONS_OPERATIONAL_AUDITED"
    , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
    , "POLICYVIOLATIONS_SECURITY_TOTAL"
    , "POLICYVIOLATIONS_SECURITY_AUDITED"
    , "POLICYVIOLATIONS_SECURITY_UNAUDITED"
    , "FIRST_OCCURRENCE"
    , "LAST_OCCURRENCE"
    )
    SELECT v_project_id
         , v_project.components
         , v_project.vulnerable_components
         , v_project.vulnerabilities
         , v_project.critical
         , v_project.high
         , v_project.medium
         , v_project.low
         , v_project.unassigned
         , v_project.risk_score
         , v_project.findings_total
         , v_project.findings_audited
         , v_project.findings_unaudited
         , v_project.findings_suppressed
         , v_project.policy_violations_total
         , v_project.policy_violations_fail
         , v_project.policy_violations_warn
         , v_project.policy_violations_info
         , v_project.policy_violations_audited
         , v_project.policy_violations_unaudited
         , v_project.policy_violations_license_total
         , v_project.policy_violations_license_audited
         , v_project.policy_violations_license_unaudited
         , v_project.policy_violations_operational_total
         , v_project.policy_violations_operational_audited
         , v_project.policy_violations_operational_unaudited
         , v_project.policy_violations_security_total
         , v_project.policy_violations_security_audited
         , v_project.policy_violations_security_unaudited
         , NOW()
         , NOW()
     -- Skip insert if the project was deleted while metrics were being computed.
     WHERE EXISTS (
       SELECT 1
         FROM "PROJECT"
        WHERE "ID" = v_project_id
     );
  END IF;

  UPDATE "PROJECT"
     SET "LAST_RISKSCORE" = v_project.risk_score
   WHERE "ID" = v_project_id
     AND "LAST_RISKSCORE" IS DISTINCT FROM v_project.risk_score;
END;
$$;
