CREATE OR REPLACE PROCEDURE "UPDATE_PROJECT_METRICS"(
  project_uuid UUID
)
  LANGUAGE "plpgsql"
AS
$$
DECLARE
  v_project_id    BIGINT; -- ID of the project to update metrics for
  v_today         TIMESTAMPTZ := DATE_TRUNC('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
  v_project       RECORD; -- Aggregated project-level metrics
  v_today_metrics RECORD; -- Today's existing PROJECTMETRICS row, if any
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
           , l."KEV"
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
           , c.kev
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
    , "KEV"
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
         , kev
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
       , COALESCE(SUM(kev)::INT, 0) AS kev
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

  SELECT *
    INTO v_today_metrics
    FROM "PROJECTMETRICS"
   WHERE "PROJECT_ID" = v_project_id
     AND "LAST_OCCURRENCE" >= v_today
   ORDER BY "LAST_OCCURRENCE" DESC
   LIMIT 1;

  -- NB: FOUND is automatically set by Postgres: https://www.postgresql.org/docs/current/plpgsql-statements.html#PLPGSQL-STATEMENTS-DIAGNOSTICS
  IF FOUND
     AND ( v_today_metrics."COMPONENTS"
         , v_today_metrics."VULNERABLECOMPONENTS"
         , v_today_metrics."VULNERABILITIES"
         , v_today_metrics."CRITICAL"
         , v_today_metrics."HIGH"
         , v_today_metrics."MEDIUM"
         , v_today_metrics."LOW"
         , v_today_metrics."UNASSIGNED_SEVERITY"
         , v_today_metrics."KEV"
         , v_today_metrics."RISKSCORE"
         , v_today_metrics."FINDINGS_TOTAL"
         , v_today_metrics."FINDINGS_AUDITED"
         , v_today_metrics."FINDINGS_UNAUDITED"
         , v_today_metrics."SUPPRESSED"
         , v_today_metrics."POLICYVIOLATIONS_TOTAL"
         , v_today_metrics."POLICYVIOLATIONS_FAIL"
         , v_today_metrics."POLICYVIOLATIONS_WARN"
         , v_today_metrics."POLICYVIOLATIONS_INFO"
         , v_today_metrics."POLICYVIOLATIONS_AUDITED"
         , v_today_metrics."POLICYVIOLATIONS_UNAUDITED"
         , v_today_metrics."POLICYVIOLATIONS_LICENSE_TOTAL"
         , v_today_metrics."POLICYVIOLATIONS_LICENSE_AUDITED"
         , v_today_metrics."POLICYVIOLATIONS_LICENSE_UNAUDITED"
         , v_today_metrics."POLICYVIOLATIONS_OPERATIONAL_TOTAL"
         , v_today_metrics."POLICYVIOLATIONS_OPERATIONAL_AUDITED"
         , v_today_metrics."POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
         , v_today_metrics."POLICYVIOLATIONS_SECURITY_TOTAL"
         , v_today_metrics."POLICYVIOLATIONS_SECURITY_AUDITED"
         , v_today_metrics."POLICYVIOLATIONS_SECURITY_UNAUDITED"
         ) IS NOT DISTINCT FROM (
             v_project.components
           , v_project.vulnerable_components
           , v_project.vulnerabilities
           , v_project.critical
           , v_project.high
           , v_project.medium
           , v_project.low
           , v_project.unassigned
           , v_project.kev
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
  THEN
    -- Nothing has changed since the last computation today. Touch LAST_OCCURRENCE forward
    -- instead of inserting a duplicate row, so that it keeps meaning "last confirmed as of",
    -- not just "last changed" - callers polling it to detect that a re-analysis has completed
    -- would otherwise wait on a write that will never happen.
    UPDATE "PROJECTMETRICS"
       SET "LAST_OCCURRENCE" = NOW()
     WHERE "PROJECT_ID" = v_project_id
       AND "LAST_OCCURRENCE" >= v_today;
  ELSE
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
    , "KEV"
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
         , v_project.kev
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
