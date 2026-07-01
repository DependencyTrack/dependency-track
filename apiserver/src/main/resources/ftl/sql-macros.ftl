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

<#macro isKev vulnSource vulnId>
  EXISTS (
    SELECT 1
      FROM "KEV_ASSERTION" AS ka
     WHERE (ka."VULN_SOURCE", ka."VULN_ID") IN (<@vulnAliasGroup vulnSource=vulnSource vulnId=vulnId/>)
  )
</#macro>
