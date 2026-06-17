-- Restore index supporting internal CPE vulnerability matching.
--
-- V202605051201__drop_unused_vulnerablesoftware_indexes dropped VULNERABLESOFTWARE_CPE_PURL_PARTS_IDX,
-- assuming a VULNERABLESOFTWARE_PART_VENDOR_PRODUCT_IDX existed to cover (PART, VENDOR, PRODUCT)
-- lookups. That index only ever existed in the v4 schema and was never created here,
-- so CPE matching was left with no usable index and sequentially scanned VULNERABLESOFTWARE on every batch.
--
-- NB: Index columns are specified from most selective to least selective.
-- Conditional on "PART" which is never set for PURL rows.
CREATE INDEX CONCURRENTLY IF NOT EXISTS "VULNERABLESOFTWARE_CPE_PRODUCT_VENDOR_PART_IDX"
    ON "VULNERABLESOFTWARE" ("PRODUCT", "VENDOR", "PART")
 WHERE "PART" IS NOT NULL;
