CREATE OR REPLACE PROCEDURE "UPDATE_COMPONENT_METRICS"(
  component_uuid UUID
)
  LANGUAGE "plpgsql"
AS
$$
DECLARE
  v_component                               RECORD; -- The component to update metrics for
  v_vulnerabilities                         INT     := 0; -- Total number of vulnerabilities
  v_critical                                INT     := 0; -- Number of vulnerabilities with critical severity
  v_high                                    INT     := 0; -- Number of vulnerabilities with high severity
  v_medium                                  INT     := 0; -- Number of vulnerabilities with medium severity
  v_low                                     INT     := 0; -- Number of vulnerabilities with low severity
  v_unassigned                              INT     := 0; -- Number of vulnerabilities with unassigned severity
  v_risk_score                              NUMERIC := 0; -- Inherited risk score
  v_findings_total                          INT     := 0; -- Total number of findings
  v_findings_audited                        INT     := 0; -- Number of audited findings
  v_findings_unaudited                      INT     := 0; -- Number of unaudited findings
  v_findings_suppressed                     INT     := 0; -- Number of suppressed findings
  v_policy_violations_total                 INT     := 0; -- Total number of policy violations
  v_policy_violations_fail                  INT     := 0; -- Number of policy violations with level fail
  v_policy_violations_warn                  INT     := 0; -- Number of policy violations with level warn
  v_policy_violations_info                  INT     := 0; -- Number of policy violations with level info
  v_policy_violations_audited               INT     := 0; -- Number of audited policy violations
  v_policy_violations_unaudited             INT     := 0; -- Number of unaudited policy violations
  v_policy_violations_license_total         INT     := 0; -- Total number of policy violations of type license
  v_policy_violations_license_audited       INT     := 0; -- Number of audited policy violations of type license
  v_policy_violations_license_unaudited     INT     := 0; -- Number of unaudited policy violations of type license
  v_policy_violations_operational_total     INT     := 0; -- Total number of policy violations of type operational
  v_policy_violations_operational_audited   INT     := 0; -- Number of audited policy violations of type operational
  v_policy_violations_operational_unaudited INT     := 0; -- Number of unaudited policy violations of type operational
  v_policy_violations_security_total        INT     := 0; -- Total number of policy violations of type security
  v_policy_violations_security_audited      INT     := 0; -- Number of audited policy violations of type security
  v_policy_violations_security_unaudited    INT     := 0; -- Number of unaudited policy violations of type security
BEGIN
  SELECT "ID"
       , "PROJECT_ID"
    INTO v_component
    FROM "COMPONENT"
   WHERE "UUID" = component_uuid;
  IF v_component IS NULL THEN
    RAISE EXCEPTION 'Component with UUID % does not exist', component_uuid;
  END IF;

  WITH deduped AS (
    SELECT DISTINCT ON (va."GROUP_ID", CASE WHEN va."GROUP_ID" IS NULL THEN v."ID" END)
           COALESCE(a."SEVERITY", v."SEVERITY") AS effective_severity
      FROM "VULNERABILITY" AS v
     INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
        ON cv."COMPONENT_ID" = v_component."ID"
       AND cv."VULNERABILITY_ID" = v."ID"
      LEFT JOIN "ANALYSIS" AS a
        ON a."COMPONENT_ID" = v_component."ID"
       AND a."VULNERABILITY_ID" = v."ID"
      LEFT JOIN "VULNERABILITY_ALIAS" AS va
        ON va."SOURCE" = v."SOURCE"
       AND va."VULN_ID" = v."VULNID"
     WHERE (a."SUPPRESSED" != TRUE OR a."SUPPRESSED" IS NULL)
       AND EXISTS(
         SELECT 1 FROM "FINDINGATTRIBUTION" AS fa
          WHERE fa."COMPONENT_ID" = cv."COMPONENT_ID"
            AND fa."VULNERABILITY_ID" = cv."VULNERABILITY_ID"
            AND fa."DELETED_AT" IS NULL
       )
     ORDER BY va."GROUP_ID"
            , CASE WHEN va."GROUP_ID" IS NULL THEN v."ID" END
            , COALESCE(a."SEVERITY", v."SEVERITY") DESC
  )
  SELECT COUNT(*)::INT
       , COUNT(*) FILTER (WHERE effective_severity = 'CRITICAL')::INT
       , COUNT(*) FILTER (WHERE effective_severity = 'HIGH')::INT
       , COUNT(*) FILTER (WHERE effective_severity = 'MEDIUM')::INT
       , COUNT(*) FILTER (WHERE effective_severity = 'LOW')::INT
       , COUNT(*) FILTER (WHERE effective_severity NOT IN ('CRITICAL','HIGH','MEDIUM','LOW'))::INT
    FROM deduped
    INTO v_vulnerabilities
       , v_critical
       , v_high
       , v_medium
       , v_low
       , v_unassigned;

  v_risk_score = COALESCE("CALC_RISK_SCORE"(v_critical, v_high, v_medium, v_low, v_unassigned), 0);

  SELECT COALESCE(COUNT(*) FILTER (
             WHERE a."SUPPRESSED" = FALSE
               AND a."STATE" NOT IN ('NOT_SET', 'IN_TRIAGE')
         ), 0)::INT
       , COALESCE(COUNT(*) FILTER (
             WHERE a."SUPPRESSED" = TRUE
         ), 0)::INT
    FROM "ANALYSIS" AS a
   WHERE a."COMPONENT_ID" = v_component."ID"
     AND EXISTS(
       SELECT 1 FROM "FINDINGATTRIBUTION" AS fa
        WHERE fa."COMPONENT_ID" = a."COMPONENT_ID"
          AND fa."VULNERABILITY_ID" = a."VULNERABILITY_ID"
          AND fa."DELETED_AT" IS NULL
     )
    INTO v_findings_audited
       , v_findings_suppressed;

  v_findings_total = v_vulnerabilities;
  v_findings_unaudited = v_findings_total - v_findings_audited;

  SELECT COUNT(*)::INT
       , COUNT(*) FILTER (WHERE p."VIOLATIONSTATE" = 'FAIL')::INT
       , COUNT(*) FILTER (WHERE p."VIOLATIONSTATE" = 'WARN')::INT
       , COUNT(*) FILTER (WHERE p."VIOLATIONSTATE" = 'INFO')::INT
       , COUNT(*) FILTER (WHERE pv."TYPE" = 'LICENSE')::INT
       , COUNT(*) FILTER (WHERE pv."TYPE" = 'OPERATIONAL')::INT
       , COUNT(*) FILTER (WHERE pv."TYPE" = 'SECURITY')::INT
    FROM "POLICYVIOLATION" AS pv
   INNER JOIN "POLICYCONDITION" AS pc
      ON pv."POLICYCONDITION_ID" = pc."ID"
   INNER JOIN "POLICY" AS p
      ON pc."POLICY_ID" = p."ID"
    LEFT JOIN "VIOLATIONANALYSIS" AS va
      ON va."COMPONENT_ID" = v_component."ID"
     AND va."POLICYVIOLATION_ID" = pv."ID"
   WHERE pv."COMPONENT_ID" = v_component."ID"
     AND (va IS NULL OR va."SUPPRESSED" = FALSE)
    INTO v_policy_violations_total
       , v_policy_violations_fail
       , v_policy_violations_warn
       , v_policy_violations_info
       , v_policy_violations_license_total
       , v_policy_violations_operational_total
       , v_policy_violations_security_total;

  SELECT COALESCE(COUNT(*) FILTER (WHERE pv."TYPE" = 'LICENSE'), 0)::INT
       , COALESCE(COUNT(*) FILTER (WHERE pv."TYPE" = 'OPERATIONAL'), 0)::INT
       , COALESCE(COUNT(*) FILTER (WHERE pv."TYPE" = 'SECURITY'), 0)::INT
    FROM "VIOLATIONANALYSIS" AS va
   INNER JOIN "POLICYVIOLATION" AS pv
      ON pv."ID" = va."POLICYVIOLATION_ID"
   WHERE va."COMPONENT_ID" = v_component."ID"
     AND va."SUPPRESSED" = FALSE
     AND va."STATE" != 'NOT_SET'
    INTO v_policy_violations_license_audited
       , v_policy_violations_operational_audited
       , v_policy_violations_security_audited;

  v_policy_violations_license_unaudited =
      v_policy_violations_license_total - v_policy_violations_license_audited;
  v_policy_violations_operational_unaudited =
      v_policy_violations_operational_total - v_policy_violations_operational_audited;
  v_policy_violations_security_unaudited =
      v_policy_violations_security_total - v_policy_violations_security_audited;

  v_policy_violations_audited = v_policy_violations_license_audited
    + v_policy_violations_operational_audited
    + v_policy_violations_security_audited;
  v_policy_violations_unaudited = v_policy_violations_total - v_policy_violations_audited;

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
  ) VALUES (
    v_component."ID"
  , v_component."PROJECT_ID"
  , v_vulnerabilities
  , v_critical
  , v_high
  , v_medium
  , v_low
  , v_unassigned
  , v_risk_score
  , v_findings_total
  , v_findings_audited
  , v_findings_unaudited
  , v_findings_suppressed
  , v_policy_violations_total
  , v_policy_violations_fail
  , v_policy_violations_warn
  , v_policy_violations_info
  , v_policy_violations_audited
  , v_policy_violations_unaudited
  , v_policy_violations_license_total
  , v_policy_violations_license_audited
  , v_policy_violations_license_unaudited
  , v_policy_violations_operational_total
  , v_policy_violations_operational_audited
  , v_policy_violations_operational_unaudited
  , v_policy_violations_security_total
  , v_policy_violations_security_audited
  , v_policy_violations_security_unaudited
  , NOW()
  , NOW()
  );

  UPDATE "COMPONENT"
     SET "LAST_RISKSCORE" = v_risk_score
   WHERE "ID" = v_component."ID"
     AND "LAST_RISKSCORE" IS DISTINCT FROM v_risk_score;
END;
$$;
