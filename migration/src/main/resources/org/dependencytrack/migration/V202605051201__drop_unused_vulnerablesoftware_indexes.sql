-- Redundant: Superset of VULNERABLESOFTWARE_PART_VENDOR_PRODUCT_IDX.
-- No query filters on CPE parts and PURL parts together, so the trailing PURL columns are never used.
DROP INDEX IF EXISTS "VULNERABLESOFTWARE_CPE_PURL_PARTS_IDX";

-- Unused: Indexes the legacy combined PURL column, but all PURL lookups go via
-- the split PURL_TYPE / PURL_NAMESPACE / PURL_NAME columns.
DROP INDEX IF EXISTS "VULNERABLESOFTWARE_PURL_VERSION_RANGE_IDX";
