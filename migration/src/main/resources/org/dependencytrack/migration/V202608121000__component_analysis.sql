-- Component policies: automated license curation. A CEL condition matched
-- against each component at BOM ingest (first match by priority wins)
-- creates/maintains a component analysis with the patch below. Manual
-- analyses always win over policies.
CREATE TABLE IF NOT EXISTS "COMPONENT_POLICY" (
  "ID"          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  "NAME"        TEXT NOT NULL CONSTRAINT "COMPONENT_POLICY_NAME_UNIQUE" UNIQUE,
  "DESCRIPTION" TEXT,
  "AUTHOR"      TEXT,
  "ENABLED"     BOOLEAN NOT NULL DEFAULT TRUE,
  "PRIORITY"    BIGINT NOT NULL DEFAULT 0,
  "CONDITION"   TEXT NOT NULL,
  "LICENSE_ID"  BIGINT REFERENCES "LICENSE" ("ID") ON DELETE SET NULL,
  "DETAILS"     TEXT,
  -- Optional validity window; the policy only applies while NOW() is inside.
  "VALID_FROM"  TIMESTAMPTZ,
  "VALID_UNTIL" TIMESTAMPTZ,
  "CREATED_AT"  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "UPDATED_AT"  TIMESTAMPTZ
);

-- Durable, identity-keyed license curation for components. Component rows are
-- deleted and recreated across BOM uploads, so the analysis is keyed by the
-- component's identity (purl, or group/name/version) within a project and
-- re-applied on every ingest.
CREATE TABLE IF NOT EXISTS "COMPONENT_ANALYSIS" (
  "ID"                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  "PROJECT_ID"         BIGINT NOT NULL REFERENCES "PROJECT" ("ID") ON DELETE CASCADE,
  "PURL"               TEXT,
  "GROUP"              TEXT,
  "NAME"               TEXT NOT NULL,
  "VERSION"            TEXT,
  -- License override: a resolved license, incl. custom licenses.
  "LICENSE_ID"         BIGINT REFERENCES "LICENSE" ("ID") ON DELETE SET NULL,
  -- Snapshot of the BOM-declared license taken whenever the override is
  -- applied, refreshed on every ingest: clearing the override restores the
  -- uploaded value instantly, without waiting for the next upload.
  "DECLARED_LICENSE_ID"         BIGINT REFERENCES "LICENSE" ("ID") ON DELETE SET NULL,
  "DECLARED_LICENSE_NAME"       TEXT,
  "DECLARED_LICENSE_EXPRESSION" TEXT,
  "DETAILS"            TEXT,
  -- Set when the analysis is created and maintained by a component policy;
  -- NULL = manual analysis, which a policy never touches. Deleting a policy
  -- keeps the analyses and their audit trails, converting them to manual.
  "POLICY_ID"          BIGINT REFERENCES "COMPONENT_POLICY" ("ID") ON DELETE SET NULL,
  "CREATED_AT"         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "UPDATED_AT"         TIMESTAMPTZ
);

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "COMPONENT_ANALYSIS_IDENTITY_IDX"
    ON "COMPONENT_ANALYSIS" (
       "PROJECT_ID",
       COALESCE("PURL", ''),
       COALESCE("GROUP", ''),
       "NAME",
       COALESCE("VERSION", ''));

-- Append-only audit trail of curation decisions (manual edits and, later,
-- component-policy applications; distinguished by the COMMENTER identity).
CREATE TABLE IF NOT EXISTS "COMPONENT_ANALYSIS_COMMENT" (
  "ID"                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  "COMPONENT_ANALYSIS_ID" BIGINT NOT NULL REFERENCES "COMPONENT_ANALYSIS" ("ID") ON DELETE CASCADE,
  "TIMESTAMP"             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "COMMENTER"             TEXT,
  "COMMENT"               TEXT NOT NULL
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS "COMPONENT_ANALYSIS_COMMENT_ANALYSIS_IDX"
    ON "COMPONENT_ANALYSIS_COMMENT" ("COMPONENT_ANALYSIS_ID");
