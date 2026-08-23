DELETE
  FROM "EXTENSION_KV_STORE"
 WHERE "EXTENSION_POINT" = 'vuln-data-source'
   AND "EXTENSION" = 'osv'
   AND "KEY" LIKE 'watermark/%';
