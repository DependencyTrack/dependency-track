-- Remove unused AFFECTEDVERSIONATTRIBUTION.UUID column.
-- The associated unique index grows unproportionally large
-- (i.e. multiple GBs) on deployments with multiple vuln data
-- sources enabled.
ALTER TABLE "AFFECTEDVERSIONATTRIBUTION" DROP COLUMN IF EXISTS "UUID";
