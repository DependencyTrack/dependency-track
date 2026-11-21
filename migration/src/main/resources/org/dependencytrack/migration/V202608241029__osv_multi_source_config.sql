-- Convert legacy OSV config to multi-source config
-- example: {"enabled": true, ...} -> {"feeds": [{"name":"default", "enabled": true, ...}]}.
UPDATE "EXTENSION_RUNTIME_CONFIG"
    SET "CONFIG" = jsonb_build_object(
        'feeds',
        jsonb_build_array( "CONFIG" || jsonb_build_object('name', 'default') )
    ),
    "UPDATED_AT" = now()
WHERE "EXTENSION_POINT" = 'vuln-data-source'
    AND "EXTENSION" = 'osv'
    AND NOT ("CONFIG" ? 'feeds');

-- Legacy OSV watermarks were keyed by source name, which can become stale after a
-- source is recreated with a different URL. The current implementation keys them by
-- the source URL hash instead, so old entries are no longer used and must be cleared.
DELETE FROM "EXTENSION_KV_STORE"
WHERE "EXTENSION_POINT" = 'vuln-data-source'
    AND "EXTENSION" = 'osv'
    AND "KEY" LIKE 'watermark/%';
