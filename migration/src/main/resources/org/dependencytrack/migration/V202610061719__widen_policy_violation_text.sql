-- Policy expressions may return a violation message of up to 1024 characters.
-- Changing VARCHAR to TEXT does not rewrite the table in Postgres.
-- squawk-ignore changing-column-type, prefer-robust-stmts
ALTER TABLE "POLICYVIOLATION" ALTER COLUMN "TEXT" TYPE TEXT;
