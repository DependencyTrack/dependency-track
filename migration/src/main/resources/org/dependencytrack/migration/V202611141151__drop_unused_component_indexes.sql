-- No query needs these indexes:
--   * CLASSIFIER and PURLCOORDINATES are only filtered within a project, which COMPONENT_PROJECT_ID_IDX serves
--   * SWIDTAGID is only searched with a leading-wildcard LIKE
-- Dropping them reduces the cost of COMPONENT inserts during BOM import.
DROP INDEX CONCURRENTLY IF EXISTS "COMPONENT_CLASSIFIER_IDX";
DROP INDEX CONCURRENTLY IF EXISTS "COMPONENT_PURL_COORDINATES_IDX";
DROP INDEX CONCURRENTLY IF EXISTS "COMPONENT_SWID_TAGID_IDX";
