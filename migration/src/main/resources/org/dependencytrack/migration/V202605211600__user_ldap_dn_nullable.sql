-- Allow USER.DN to be null for LDAP users.
-- DN is now populated on the first successful login rather than via a
-- background sync task, matching how OIDC's SUBJECT_IDENTIFIER is handled.
-- Non-LDAP users must still have a null DN.
ALTER TABLE "USER" DROP CONSTRAINT user_ldap_check;
ALTER TABLE "USER" ADD CONSTRAINT user_ldap_check
    CHECK (("TYPE" = 'LDAP'::text) OR ("DN" IS NULL));
