DO $$
DECLARE
  conflicting_usernames TEXT;
BEGIN
  SELECT STRING_AGG("USERNAME" || ' (' || "TYPE" || ')', ', ' ORDER BY "USERNAME")
    INTO conflicting_usernames
    FROM "USER"
   WHERE "USERNAME" ILIKE 'svc-%';

  IF conflicting_usernames IS NOT NULL THEN
    RAISE EXCEPTION 'The username prefix "svc-" is reserved for service accounts, but these users already use it: %. '
      'Rename or delete MANAGED users directly in the "USER" table. '
      'Rename LDAP and OIDC users in the identity provider, then delete them from the "USER" table. '
      'Then retry the upgrade.', conflicting_usernames;
  END IF;
END
$$;

ALTER TABLE "USER" DROP CONSTRAINT IF EXISTS user_type_check;

-- squawk-ignore constraint-missing-not-valid, prefer-robust-stmts
ALTER TABLE "USER" ADD CONSTRAINT user_type_check
  CHECK ("TYPE" IN ('MANAGED', 'LDAP', 'OIDC', 'SERVICE'));

ALTER TABLE "USER" DROP CONSTRAINT IF EXISTS user_managed_check;

-- squawk-ignore constraint-missing-not-valid, prefer-robust-stmts
ALTER TABLE "USER" ADD CONSTRAINT user_managed_check
  CHECK (
    ("TYPE" = 'MANAGED'
      AND "FORCE_PASSWORD_CHANGE" IS NOT NULL
      AND "LAST_PASSWORD_CHANGE" IS NOT NULL
      AND "NON_EXPIRY_PASSWORD" IS NOT NULL
      AND "PASSWORD" IS NOT NULL
      AND "SUSPENDED" IS NOT NULL)
    OR ("TYPE" != 'MANAGED'
      AND "FORCE_PASSWORD_CHANGE" IS NULL
      AND "FULLNAME" IS NULL
      AND "LAST_PASSWORD_CHANGE" IS NULL
      AND "NON_EXPIRY_PASSWORD" IS NULL
      AND "PASSWORD" IS NULL
      AND ("SUSPENDED" IS NULL OR "TYPE" = 'SERVICE'))
  );

-- squawk-ignore constraint-missing-not-valid, prefer-robust-stmts
ALTER TABLE "USER" ADD CONSTRAINT user_service_check
  CHECK (
    ("TYPE" = 'SERVICE' AND "USERNAME" LIKE 'svc-%' AND "SUSPENDED" IS NOT NULL)
    OR ("TYPE" != 'SERVICE' AND "USERNAME" NOT ILIKE 'svc-%')
  );

ALTER TABLE "APIKEY" ADD COLUMN IF NOT EXISTS "USER_ID" BIGINT;

-- squawk-ignore adding-foreign-key-constraint, constraint-missing-not-valid, prefer-robust-stmts
ALTER TABLE "APIKEY" ADD CONSTRAINT "APIKEY_USER_FK"
  FOREIGN KEY ("USER_ID") REFERENCES "USER" ("ID") ON DELETE CASCADE;

-- squawk-ignore require-concurrent-index-creation
CREATE INDEX IF NOT EXISTS "APIKEY_USER_IDX"
    ON "APIKEY" ("USER_ID");
