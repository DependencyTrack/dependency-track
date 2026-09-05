<#--
  Shared SQL macros, auto-imported as the "sql" namespace for every JDBI query.
  Reference as `<@sql.macroName .../>`.
-->

<#macro vulnAliasGroup vulnSource vulnId>
  SELECT ${vulnSource}
       , ${vulnId}
   UNION
  SELECT alias_sibling."SOURCE"
       , alias_sibling."VULN_ID"
    FROM "VULNERABILITY_ALIAS" AS alias_self
   INNER JOIN "VULNERABILITY_ALIAS" AS alias_sibling
      ON alias_sibling."GROUP_ID" = alias_self."GROUP_ID"
   WHERE alias_self."SOURCE" = ${vulnSource}
     AND alias_self."VULN_ID" = ${vulnId}
</#macro>

<#--
  Whether one vulnerability is known exploited.
  Use for point-lookups or enrichment in a SELECT, NOT for filtering large result sets.
-->
<#macro isKevColumn vulnSource vulnId>
  EXISTS (
    SELECT 1
      FROM "KEV_ASSERTION" AS ka
     WHERE (ka."VULN_SOURCE", ka."VULN_ID") IN (<@vulnAliasGroup vulnSource=vulnSource vulnId=vulnId/>)
  )
</#macro>

<#--
  Whether a vulnerability is known exploited.
  Use for filtering large result sets, use `isKevColumn` otherwise.

  This variant computes the full set of KEV vulns upfront,
  which pays off for filtering but degrades badly for point-lookups and SELECT enrichment.

  NB: Keep the ARRAY(...) notation! Postgres then builds the set once and counts it,
  so it knows the filter keeps very few rows. IN or a join leaves it guessing,
  and for a sorted page it scans the whole VULNERABILITY table instead of the
  few rows that match.
-->
<#macro isKevFilter vulnIdColumn>
  (
    ${vulnIdColumn} = ANY(ARRAY(
      SELECT DISTINCT kev_v."ID"
        FROM "KEV_ASSERTION" AS kev_ka
       INNER JOIN LATERAL (
         <@vulnAliasGroup vulnSource='kev_ka."VULN_SOURCE"' vulnId='kev_ka."VULN_ID"'/>
       ) AS kev_group("SOURCE", "VULN_ID") ON TRUE
       INNER JOIN "VULNERABILITY" AS kev_v
          ON kev_v."VULNID" = kev_group."VULN_ID"
         AND kev_v."SOURCE" = kev_group."SOURCE"
    ))
  )
</#macro>

<#--
  EPSS candidate rows (CVE, score, percentile) for a vulnerability,
  resolving the vulnerability's NVD aliases when it isn't itself an NVD record.
-->
<#macro epssCandidates vulnSource vulnId>
    SELECT ee."CVE"
         , ee."SCORE"
         , ee."PERCENTILE"
      FROM "EPSS" AS ee
     WHERE ${vulnSource} = 'NVD'
       AND ee."CVE" = ${vulnId}
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
     WHERE ${vulnSource} != 'NVD'
       AND va."SOURCE" = ${vulnSource}
       AND va."VULN_ID" = ${vulnId}
</#macro>

<#--
  The highest-scoring EPSS row (score, percentile) for a vulnerability.
  Ties break on the higher percentile, then on the lower CVE.
-->
<#macro epssBestRow vulnSource vulnId>
    SELECT "SCORE"
         , "PERCENTILE"
      FROM (
        <@epssCandidates vulnSource=vulnSource vulnId=vulnId/>
      ) AS candidates
     ORDER BY "SCORE" DESC NULLS LAST
            , "PERCENTILE" DESC NULLS LAST
            , "CVE"
     LIMIT 1
</#macro>

<#--
  CTE body picking one EPSS row (score, percentile) per vulnerability,
  for those vulnerabilities that are attached to at least one component.
  Picks the same row as epssBestRow.
-->
<#macro epssDedup>
  epss_dedup AS (
    SELECT dv."ID" AS "vulnerabilityId"
         , ep."SCORE"
         , ep."PERCENTILE"
      FROM (
        SELECT DISTINCT
               v."ID"
             , v."SOURCE"
             , v."VULNID"
          FROM "VULNERABILITY" AS v
         WHERE v."ID" IN (
           SELECT "VULNERABILITY_ID"
             FROM "COMPONENTS_VULNERABILITIES"
         )
      ) AS dv
      LEFT JOIN LATERAL (
        <@epssBestRow vulnSource='dv."SOURCE"' vulnId='dv."VULNID"'/>
      ) AS ep ON TRUE
  )
</#macro>
