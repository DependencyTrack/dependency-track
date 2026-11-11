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

-- Watermarks are namespaced by the source URL hash. Move legacy default-source
-- watermarks to the default feed's URL-derived namespace.
UPDATE "EXTENSION_KV_STORE" kv
SET "KEY" = 'watermark/' || substr(encode(digest(feed."dataUrl", 'sha256'), 'hex'), 1, 12) || '/' || split_part(kv."KEY", '/', 3)
FROM "EXTENSION_RUNTIME_CONFIG" rc
CROSS JOIN LATERAL (
    SELECT value->>'dataUrl' AS "dataUrl"
    FROM jsonb_array_elements(rc."CONFIG"->'feeds') AS value
    WHERE value->>'name' = 'default'
) AS feed
WHERE kv."EXTENSION_POINT" = 'vuln-data-source'
    AND kv."EXTENSION" = 'osv'
    AND kv."KEY" LIKE 'watermark/default/%'
    AND rc."EXTENSION_POINT" = kv."EXTENSION_POINT"
    AND rc."EXTENSION" = kv."EXTENSION"
    AND rc."CONFIG" ? 'feeds';
