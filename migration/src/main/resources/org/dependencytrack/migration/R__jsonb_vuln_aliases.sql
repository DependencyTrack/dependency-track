CREATE OR REPLACE FUNCTION JSONB_VULN_ALIASES(
  "vuln_source" TEXT
, "vuln_id" TEXT
) RETURNS JSONB
  LANGUAGE "sql"
  PARALLEL SAFE
  STABLE
AS
$$
SELECT JSONB_AGG(DISTINCT JSONB_STRIP_NULLS(JSONB_BUILD_OBJECT(
         'cveId', CASE WHEN va."SOURCE" = 'NVD' THEN va."VULN_ID" END
       , 'ghsaId', CASE WHEN va."SOURCE" = 'GITHUB' THEN va."VULN_ID" END
       , 'gsdId', CASE WHEN va."SOURCE" = 'GSD' THEN va."VULN_ID" END
       , 'internalId', CASE WHEN va."SOURCE" = 'INTERNAL' THEN va."VULN_ID" END
       , 'osvId', CASE WHEN va."SOURCE" = 'OSV' THEN va."VULN_ID" END
       , 'sonatypeId', CASE WHEN va."SOURCE" = 'OSSINDEX' THEN va."VULN_ID" END
       , 'snykId', CASE WHEN va."SOURCE" = 'SNYK' THEN va."VULN_ID" END
       , 'vulnDbId', CASE WHEN va."SOURCE" = 'VULNDB' THEN va."VULN_ID" END
       )))
  FROM "VULNERABILITY_ALIAS" AS va
 WHERE va."GROUP_ID" IN (
    SELECT "GROUP_ID"
      FROM "VULNERABILITY_ALIAS"
     WHERE "SOURCE" = "vuln_source"
       AND "VULN_ID" = "vuln_id"
 )
   AND (va."SOURCE", va."VULN_ID") != ("vuln_source" ,"vuln_id")
$$;
