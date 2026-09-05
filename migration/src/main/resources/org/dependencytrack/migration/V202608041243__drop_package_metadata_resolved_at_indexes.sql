-- The RESOLVED_AT columns no longer drive resolution candidacy (see ADR 035)
-- so the indexes are no longer needed.
-- NB: Removal of these indexes also enables HOT updates on both tables.
DROP INDEX CONCURRENTLY IF EXISTS "PACKAGE_METADATA_RESOLVED_AT_IDX";
DROP INDEX CONCURRENTLY IF EXISTS "PACKAGE_ARTIFACT_METADATA_RESOLVED_AT_IDX";
