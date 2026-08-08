CREATE OR REPLACE PROCEDURE "UPDATE_COMPONENT_METRICS"(
  component_uuid UUID
)
  LANGUAGE "plpgsql"
AS
$$
DECLARE
  v_component RECORD; -- The component to update metrics for
  v_metrics   RECORD; -- The computed metrics of the component
  v_latest    RECORD; -- The latest DEPENDENCYMETRICS snapshot of the component
  v_today     TIMESTAMPTZ := DATE_TRUNC('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
BEGIN
  SELECT "ID"
       , "PROJECT_ID"
    INTO v_component
    FROM "COMPONENT"
   WHERE "UUID" = component_uuid;
  IF v_component IS NULL THEN
    RAISE EXCEPTION 'Component with UUID % does not exist', component_uuid;
  END IF;

  SELECT *
    INTO v_metrics
    FROM "COMPUTE_COMPONENT_METRICS"(ARRAY[v_component."ID"]);

  UPDATE "COMPONENT"
     SET "LAST_RISKSCORE" = v_metrics.risk_score
   WHERE "ID" = v_component."ID"
     AND "LAST_RISKSCORE" IS DISTINCT FROM v_metrics.risk_score;

  SELECT *
    INTO v_latest
    FROM "DEPENDENCYMETRICS"
   WHERE "COMPONENT_ID" = v_component."ID"
     AND "LAST_OCCURRENCE" >= v_today
   ORDER BY "LAST_OCCURRENCE" DESC
   LIMIT 1;

  -- Do not proceed if a record with identical values already exists for today.
  -- No need to pollute the metrics table with redundant data.
  -- NB: FOUND is automatically set by Postgres: https://www.postgresql.org/docs/current/plpgsql-statements.html#PLPGSQL-STATEMENTS-DIAGNOSTICS
  IF FOUND
     AND ( v_latest."VULNERABILITIES"
         , v_latest."CRITICAL"
         , v_latest."HIGH"
         , v_latest."MEDIUM"
         , v_latest."LOW"
         , v_latest."UNASSIGNED_SEVERITY"
         , v_latest."KEV"
         , v_latest."RISKSCORE"
         , v_latest."FINDINGS_TOTAL"
         , v_latest."FINDINGS_AUDITED"
         , v_latest."FINDINGS_UNAUDITED"
         , v_latest."SUPPRESSED"
         , v_latest."POLICYVIOLATIONS_TOTAL"
         , v_latest."POLICYVIOLATIONS_FAIL"
         , v_latest."POLICYVIOLATIONS_WARN"
         , v_latest."POLICYVIOLATIONS_INFO"
         , v_latest."POLICYVIOLATIONS_AUDITED"
         , v_latest."POLICYVIOLATIONS_UNAUDITED"
         , v_latest."POLICYVIOLATIONS_LICENSE_TOTAL"
         , v_latest."POLICYVIOLATIONS_LICENSE_AUDITED"
         , v_latest."POLICYVIOLATIONS_LICENSE_UNAUDITED"
         , v_latest."POLICYVIOLATIONS_OPERATIONAL_TOTAL"
         , v_latest."POLICYVIOLATIONS_OPERATIONAL_AUDITED"
         , v_latest."POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
         , v_latest."POLICYVIOLATIONS_SECURITY_TOTAL"
         , v_latest."POLICYVIOLATIONS_SECURITY_AUDITED"
         , v_latest."POLICYVIOLATIONS_SECURITY_UNAUDITED"
         ) IS NOT DISTINCT FROM
         ( v_metrics.vulnerabilities
         , v_metrics.critical
         , v_metrics.high
         , v_metrics.medium
         , v_metrics.low
         , v_metrics.unassigned
         , v_metrics.kev
         , v_metrics.risk_score
         , v_metrics.findings_total
         , v_metrics.findings_audited
         , v_metrics.findings_unaudited
         , v_metrics.findings_suppressed
         , v_metrics.policy_violations_total
         , v_metrics.policy_violations_fail
         , v_metrics.policy_violations_warn
         , v_metrics.policy_violations_info
         , v_metrics.policy_violations_audited
         , v_metrics.policy_violations_unaudited
         , v_metrics.policy_violations_license_total
         , v_metrics.policy_violations_license_audited
         , v_metrics.policy_violations_license_unaudited
         , v_metrics.policy_violations_operational_total
         , v_metrics.policy_violations_operational_audited
         , v_metrics.policy_violations_operational_unaudited
         , v_metrics.policy_violations_security_total
         , v_metrics.policy_violations_security_audited
         , v_metrics.policy_violations_security_unaudited
         ) THEN
    RETURN;
  END IF;

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
  SELECT v_component."ID"
       , v_component."PROJECT_ID"
       , v_metrics.vulnerabilities
       , v_metrics.critical
       , v_metrics.high
       , v_metrics.medium
       , v_metrics.low
       , v_metrics.unassigned
       , v_metrics.kev
       , v_metrics.risk_score
       , v_metrics.findings_total
       , v_metrics.findings_audited
       , v_metrics.findings_unaudited
       , v_metrics.findings_suppressed
       , v_metrics.policy_violations_total
       , v_metrics.policy_violations_fail
       , v_metrics.policy_violations_warn
       , v_metrics.policy_violations_info
       , v_metrics.policy_violations_audited
       , v_metrics.policy_violations_unaudited
       , v_metrics.policy_violations_license_total
       , v_metrics.policy_violations_license_audited
       , v_metrics.policy_violations_license_unaudited
       , v_metrics.policy_violations_operational_total
       , v_metrics.policy_violations_operational_audited
       , v_metrics.policy_violations_operational_unaudited
       , v_metrics.policy_violations_security_total
       , v_metrics.policy_violations_security_audited
       , v_metrics.policy_violations_security_unaudited
       , NOW()
       , NOW()
   -- Skip insert if the component was deleted while metrics were being computed.
   WHERE EXISTS (
     SELECT 1
       FROM "COMPONENT"
      WHERE "ID" = v_component."ID"
   );
END;
$$;
