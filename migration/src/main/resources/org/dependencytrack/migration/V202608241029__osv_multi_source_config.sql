-- Convert legacy OSV config to multi-source config
-- example: {"enabled": true, ...} -> {"sources": [{"name":"default", "enabled": true, ...}]}.
UPDATE "EXTENSION_RUNTIME_CONFIG"
    SET "CONFIG" = jsonb_build_object(
        'sources',
        jsonb_build_array( "CONFIG" || jsonb_build_object('name', 'default') )
    ),
    "UPDATED_AT" = now()
WHERE "EXTENSION_POINT" = 'vuln-data-source'
    AND "EXTENSION" = 'osv'
    AND NOT ("CONFIG" ? 'sources');

-- Watermarks are namespaced by source name. Move existing watermarks to the default source.
UPDATE "EXTENSION_KV_STORE"
    SET "KEY" = 'watermark/default/' || replace("KEY", 'watermark/', '')
WHERE "EXTENSION_POINT" = 'vuln-data-source'
    AND "EXTENSION" = 'osv'
    AND "KEY" LIKE 'watermark/%'
    AND NOT "KEY" LIKE 'watermark/default/%';