-- squawk-ignore ban-drop-column
ALTER TABLE "COMPONENTLICENSES" DROP COLUMN IF EXISTS "ID";

-- squawk-ignore adding-serial-primary-key-field, constraint-missing-not-valid, prefer-robust-stmts
ALTER TABLE "COMPONENTLICENSES" ADD CONSTRAINT "COMPONENTLICENSES_PK" PRIMARY KEY ("COMPONENT_ID", "ORDINALITY");

-- squawk-ignore require-concurrent-index-deletion
DROP INDEX IF EXISTS "COMPONENTLICENSES_COMPONENT_ORDINALITY_IDX";

-- squawk-ignore require-concurrent-index-creation
CREATE UNIQUE INDEX IF NOT EXISTS "COMPONENTLICENSES_LICENSE_COMPONENT_IDX"
    ON "COMPONENTLICENSES" ("LICENSE_ID", "COMPONENT_ID")
 WHERE "LICENSE_ID" IS NOT NULL;

-- squawk-ignore require-concurrent-index-deletion
DROP INDEX IF EXISTS "COMPONENTLICENSES_ID_IDX";

-- squawk-ignore require-concurrent-index-deletion
DROP INDEX IF EXISTS "COMPONENTLICENSES_LICENSE_ID_IDX";
