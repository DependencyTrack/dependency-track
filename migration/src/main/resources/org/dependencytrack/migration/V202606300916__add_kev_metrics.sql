-- squawk-ignore prefer-bigint-over-int
ALTER TABLE "DEPENDENCYMETRICS" ADD COLUMN IF NOT EXISTS "KEV" integer NOT NULL DEFAULT 0;

-- squawk-ignore prefer-bigint-over-int
ALTER TABLE "PROJECTMETRICS" ADD COLUMN IF NOT EXISTS "KEV" integer NOT NULL DEFAULT 0;
