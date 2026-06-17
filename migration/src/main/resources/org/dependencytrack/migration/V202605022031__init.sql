
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TYPE notification_level AS ENUM (
    'INFORMATIONAL',
    'WARNING',
    'ERROR'
);

CREATE TYPE severity AS ENUM (
    'UNASSIGNED',
    'INFO',
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL'
);

CREATE FUNCTION prevent_direct_project_access_users_writes() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
            BEGIN
              IF pg_trigger_depth() < 2 THEN
                RAISE EXCEPTION 'Direct modifications to PROJECT_ACCESS_USERS are not allowed.';
              END IF;
              RETURN NEW;
            END;
            $$;

CREATE FUNCTION project_access_users_on_pat_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
            BEGIN
              WITH rows_to_delete AS (
                SELECT pau."PROJECT_ID"
                     , pau."USER_ID"
                  FROM "PROJECT_ACCESS_USERS" AS pau
                 WHERE EXISTS (
                   SELECT 1
                     FROM old_table AS ot
                    WHERE ot."PROJECT_ID" = pau."PROJECT_ID"
                 )
                 AND NOT EXISTS (
                   SELECT 1
                     FROM "PROJECT_ACCESS_TEAMS" AS pat
                    INNER JOIN "USERS_TEAMS" AS ut
                       ON ut."TEAM_ID" = pat."TEAM_ID"
                    WHERE pat."PROJECT_ID" = pau."PROJECT_ID"
                      AND ut."USER_ID" = pau."USER_ID"
                 )
                 ORDER BY pau."PROJECT_ID"
                        , pau."USER_ID"
                   FOR UPDATE
              )
              DELETE
                FROM "PROJECT_ACCESS_USERS" AS pau
               USING rows_to_delete AS r
               WHERE pau."PROJECT_ID" = r."PROJECT_ID"
                 AND pau."USER_ID" = r."USER_ID";
              RETURN NULL;
            END;
            $$;

CREATE FUNCTION project_access_users_on_pat_insert() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
            BEGIN
              INSERT INTO "PROJECT_ACCESS_USERS" ("PROJECT_ID", "USER_ID")
              SELECT DISTINCT nt."PROJECT_ID"
                            , ut."USER_ID"
                FROM new_table AS nt
               INNER JOIN "USERS_TEAMS" AS ut
                  ON ut."TEAM_ID" = nt."TEAM_ID"
               ORDER BY nt."PROJECT_ID"
                      , ut."USER_ID"
              ON CONFLICT DO NOTHING;
              RETURN NULL;
            END;
            $$;

CREATE FUNCTION project_access_users_on_pat_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
            BEGIN
              WITH rows_to_delete AS (
                SELECT pau."PROJECT_ID"
                     , pau."USER_ID"
                  FROM "PROJECT_ACCESS_USERS" AS pau
                 WHERE EXISTS (
                   SELECT 1
                     FROM old_table AS ot
                    WHERE ot."PROJECT_ID" = pau."PROJECT_ID"
                 )
                 AND NOT EXISTS (
                   SELECT 1
                     FROM "PROJECT_ACCESS_TEAMS" AS pat
                    INNER JOIN "USERS_TEAMS" AS ut
                       ON ut."TEAM_ID" = pat."TEAM_ID"
                    WHERE pat."PROJECT_ID" = pau."PROJECT_ID"
                      AND ut."USER_ID" = pau."USER_ID"
                 )
                 ORDER BY pau."PROJECT_ID"
                        , pau."USER_ID"
                   FOR UPDATE
              )
              DELETE
                FROM "PROJECT_ACCESS_USERS" AS pau
               USING rows_to_delete AS r
               WHERE pau."PROJECT_ID" = r."PROJECT_ID"
                 AND pau."USER_ID" = r."USER_ID";

              INSERT INTO "PROJECT_ACCESS_USERS" ("PROJECT_ID", "USER_ID")
              SELECT DISTINCT nt."PROJECT_ID"
                            , ut."USER_ID"
                FROM new_table AS nt
               INNER JOIN "USERS_TEAMS" AS ut
                  ON ut."TEAM_ID" = nt."TEAM_ID"
               ORDER BY nt."PROJECT_ID"
                      , ut."USER_ID"
              ON CONFLICT DO NOTHING;

              RETURN NULL;
            END;
            $$;

CREATE FUNCTION project_access_users_on_ut_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
            BEGIN
              WITH rows_to_delete AS (
                SELECT pau."PROJECT_ID"
                     , pau."USER_ID"
                  FROM "PROJECT_ACCESS_USERS" AS pau
                 WHERE EXISTS (
                   SELECT 1
                     FROM old_table AS ot
                    WHERE ot."USER_ID" = pau."USER_ID"
                 )
                 AND NOT EXISTS (
                   SELECT 1 FROM "USERS_TEAMS" AS ut
                    INNER JOIN "PROJECT_ACCESS_TEAMS" AS pat
                       ON pat."TEAM_ID" = ut."TEAM_ID"
                    WHERE ut."USER_ID" = pau."USER_ID"
                      AND pat."PROJECT_ID" = pau."PROJECT_ID"
                 )
                 ORDER BY pau."PROJECT_ID"
                        , pau."USER_ID"
                   FOR UPDATE
              )
              DELETE
                FROM "PROJECT_ACCESS_USERS" AS pau
               USING rows_to_delete AS r
               WHERE pau."PROJECT_ID" = r."PROJECT_ID"
                 AND pau."USER_ID" = r."USER_ID";
              RETURN NULL;
            END;
            $$;

CREATE FUNCTION project_access_users_on_ut_insert() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
            BEGIN
              INSERT INTO "PROJECT_ACCESS_USERS" ("PROJECT_ID", "USER_ID")
              SELECT DISTINCT pat."PROJECT_ID"
                            , nt."USER_ID"
                FROM new_table AS nt
               INNER JOIN "PROJECT_ACCESS_TEAMS" AS pat
                  ON pat."TEAM_ID" = nt."TEAM_ID"
               ORDER BY pat."PROJECT_ID"
                      , nt."USER_ID"
              ON CONFLICT DO NOTHING;
              RETURN NULL;
            END;
            $$;

CREATE FUNCTION project_access_users_on_ut_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
            BEGIN
              WITH rows_to_delete AS (
                SELECT pau."PROJECT_ID"
                     , pau."USER_ID"
                  FROM "PROJECT_ACCESS_USERS" AS pau
                 WHERE EXISTS (
                   SELECT 1
                     FROM old_table AS ot
                    WHERE ot."USER_ID" = pau."USER_ID"
                 )
                 AND NOT EXISTS (
                   SELECT 1
                     FROM "USERS_TEAMS" AS ut
                    INNER JOIN "PROJECT_ACCESS_TEAMS" AS pat
                       ON pat."TEAM_ID" = ut."TEAM_ID"
                    WHERE ut."USER_ID" = pau."USER_ID"
                      AND pat."PROJECT_ID" = pau."PROJECT_ID"
                 )
                 ORDER BY pau."PROJECT_ID"
                        , pau."USER_ID"
                   FOR UPDATE
              )
              DELETE
                FROM "PROJECT_ACCESS_USERS" AS pau
               USING rows_to_delete AS r
               WHERE pau."PROJECT_ID" = r."PROJECT_ID"
                 AND pau."USER_ID" = r."USER_ID";

              INSERT INTO "PROJECT_ACCESS_USERS" ("PROJECT_ID", "USER_ID")
              SELECT DISTINCT pat."PROJECT_ID"
                            , nt."USER_ID"
                FROM new_table AS nt
               INNER JOIN "PROJECT_ACCESS_TEAMS" AS pat
                  ON pat."TEAM_ID" = nt."TEAM_ID"
               ORDER BY pat."PROJECT_ID"
                      , nt."USER_ID"
              ON CONFLICT DO NOTHING;

              RETURN NULL;
            END;
            $$;

CREATE FUNCTION project_hierarchy_maintenance_on_project_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
            BEGIN
              DELETE FROM "PROJECT_HIERARCHY"
               WHERE "PARENT_PROJECT_ID" IN (SELECT "ID" FROM old_table)
                  OR "CHILD_PROJECT_ID" IN (SELECT "ID" FROM old_table);

              RETURN NULL;
            END;
            $$;

CREATE FUNCTION project_hierarchy_maintenance_on_project_insert() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
            BEGIN
              INSERT INTO "PROJECT_HIERARCHY" ("PARENT_PROJECT_ID", "CHILD_PROJECT_ID", "DEPTH")
              VALUES(NEW."ID", NEW."ID", 0);

              INSERT INTO "PROJECT_HIERARCHY" ("PARENT_PROJECT_ID", "CHILD_PROJECT_ID", "DEPTH")
              SELECT "PARENT_PROJECT_ID", NEW."ID", "DEPTH" + 1
                FROM "PROJECT_HIERARCHY"
               WHERE "CHILD_PROJECT_ID" = NEW."PARENT_PROJECT_ID";

              RETURN NEW;
            END;
            $$;

CREATE FUNCTION project_hierarchy_maintenance_on_project_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
            BEGIN
              DELETE FROM "PROJECT_HIERARCHY" WHERE "CHILD_PROJECT_ID" = old."ID";

              INSERT INTO "PROJECT_HIERARCHY" ("PARENT_PROJECT_ID", "CHILD_PROJECT_ID", "DEPTH")
              VALUES (NEW."ID", NEW."ID", 0);

              INSERT INTO "PROJECT_HIERARCHY" ("PARENT_PROJECT_ID", "CHILD_PROJECT_ID", "DEPTH")
              SELECT "PARENT_PROJECT_ID", NEW."ID", "DEPTH" + 1
                FROM "PROJECT_HIERARCHY"
               WHERE "CHILD_PROJECT_ID" = NEW."PARENT_PROJECT_ID";

              RETURN NEW;
            END;
            $$;

CREATE TABLE "AFFECTEDVERSIONATTRIBUTION" (
    "ID" bigint NOT NULL,
    "FIRST_SEEN" timestamp with time zone NOT NULL,
    "LAST_SEEN" timestamp with time zone NOT NULL,
    "SOURCE" character varying(255) NOT NULL,
    "UUID" uuid NOT NULL,
    "VULNERABILITY" bigint NOT NULL,
    "VULNERABLE_SOFTWARE" bigint NOT NULL
);

ALTER TABLE "AFFECTEDVERSIONATTRIBUTION" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "AFFECTEDVERSIONATTRIBUTION_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "ANALYSIS" (
    "ID" bigint NOT NULL,
    "DETAILS" text,
    "JUSTIFICATION" character varying(255),
    "RESPONSE" character varying(255),
    "STATE" character varying(255) NOT NULL,
    "COMPONENT_ID" bigint,
    "PROJECT_ID" bigint,
    "SUPPRESSED" boolean NOT NULL,
    "VULNERABILITY_ID" bigint NOT NULL,
    "CVSSV2VECTOR" character varying(255),
    "CVSSV3SCORE" numeric,
    "OWASPSCORE" numeric,
    "CVSSV2SCORE" numeric,
    "OWASPVECTOR" character varying(255),
    "CVSSV3VECTOR" character varying(255),
    "SEVERITY" severity,
    "VULNERABILITY_POLICY_ID" bigint,
    "CVSSV4VECTOR" character varying(255),
    "CVSSV4SCORE" numeric
);

CREATE TABLE "ANALYSISCOMMENT" (
    "ID" bigint NOT NULL,
    "ANALYSIS_ID" bigint NOT NULL,
    "COMMENT" text NOT NULL,
    "COMMENTER" character varying(255),
    "TIMESTAMP" timestamp with time zone NOT NULL
);

ALTER TABLE "ANALYSISCOMMENT" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "ANALYSISCOMMENT_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

ALTER TABLE "ANALYSIS" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "ANALYSIS_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "APIKEY" (
    "ID" bigint NOT NULL,
    "COMMENT" character varying(255),
    "CREATED" timestamp with time zone,
    "LAST_USED" timestamp with time zone,
    "SECRET_HASH" character varying(64) NOT NULL,
    "PUBLIC_ID" character varying(8) NOT NULL,
    "IS_LEGACY" boolean DEFAULT false NOT NULL
);

CREATE TABLE "APIKEYS_TEAMS" (
    "TEAM_ID" bigint NOT NULL,
    "APIKEY_ID" bigint NOT NULL
);

ALTER TABLE "APIKEY" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "APIKEY_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "BOM" (
    "ID" bigint NOT NULL,
    "BOM_FORMAT" character varying(255),
    "BOM_VERSION" integer,
    "IMPORTED" timestamp with time zone NOT NULL,
    "PROJECT_ID" bigint NOT NULL,
    "SERIAL_NUMBER" character varying(255),
    "SPEC_VERSION" character varying(255),
    "UUID" uuid NOT NULL,
    "GENERATED" timestamp with time zone
);

ALTER TABLE "BOM" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "BOM_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE UNLOGGED TABLE "CACHE_ENTRY" (
    "CACHE_NAME" text NOT NULL,
    "KEY" text NOT NULL,
    "VALUE" bytea,
    "EXPIRES_AT" timestamp with time zone NOT NULL
);

CREATE TABLE "COMPONENT" (
    "ID" bigint NOT NULL,
    "BLAKE2B_256" character varying(64),
    "BLAKE2B_384" character varying(96),
    "BLAKE2B_512" character varying(128),
    "BLAKE3" character varying(255),
    "CLASSIFIER" character varying(255),
    "COPYRIGHT" character varying(1024),
    "CPE" character varying(255),
    "DESCRIPTION" character varying(1024),
    "DIRECT_DEPENDENCIES" jsonb,
    "EXTENSION" character varying(255),
    "EXTERNAL_REFERENCES" bytea,
    "FILENAME" character varying(255),
    "GROUP" character varying(255),
    "INTERNAL" boolean,
    "LAST_RISKSCORE" double precision,
    "LICENSE" character varying(255),
    "LICENSE_EXPRESSION" text,
    "LICENSE_URL" character varying(255),
    "MD5" character varying(32),
    "NAME" character varying(255) NOT NULL,
    "TEXT" text,
    "PARENT_COMPONENT_ID" bigint,
    "PROJECT_ID" bigint NOT NULL,
    "PUBLISHER" character varying(255),
    "PURL" character varying(1024),
    "PURLCOORDINATES" character varying(1024),
    "LICENSE_ID" bigint,
    "SHA1" character varying(40),
    "SHA_256" character varying(64),
    "SHA_384" character varying(96),
    "SHA3_256" character varying(64),
    "SHA3_384" character varying(96),
    "SHA3_512" character varying(128),
    "SHA_512" character varying(128),
    "SWIDTAGID" character varying(255),
    "UUID" uuid NOT NULL,
    "VERSION" character varying(255),
    "SUPPLIER" text,
    "AUTHORS" text,
    "SCOPE" character varying(255),
    CONSTRAINT "COMPONENT_CLASSIFIER_check" CHECK ((("CLASSIFIER" IS NULL) OR (("CLASSIFIER")::text = ANY (ARRAY['APPLICATION'::text, 'CONTAINER'::text, 'CRYPTOGRAPHIC_ASSET'::text, 'DATA'::text, 'DEVICE'::text, 'DEVICE_DRIVER'::text, 'FILE'::text, 'FIRMWARE'::text, 'FRAMEWORK'::text, 'LIBRARY'::text, 'MACHINE_LEARNING_MODEL'::text, 'OPERATING_SYSTEM'::text, 'PLATFORM'::text])))),
    CONSTRAINT "COMPONENT_SCOPE_check" CHECK ((("SCOPE" IS NULL) OR (("SCOPE")::text = ANY (ARRAY['REQUIRED'::text, 'OPTIONAL'::text, 'EXCLUDED'::text]))))
);

CREATE TABLE "COMPONENTS_VULNERABILITIES" (
    "COMPONENT_ID" bigint NOT NULL,
    "VULNERABILITY_ID" bigint NOT NULL
);

ALTER TABLE "COMPONENT" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "COMPONENT_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "COMPONENT_OCCURRENCE" (
    "ID" uuid NOT NULL,
    "COMPONENT_ID" bigint NOT NULL,
    "LOCATION" text NOT NULL,
    "LINE" integer,
    "OFFSET" integer,
    "SYMBOL" text,
    "CREATED_AT" timestamp(3) with time zone DEFAULT now() NOT NULL
);

CREATE TABLE "COMPONENT_PROPERTY" (
    "ID" bigint NOT NULL,
    "COMPONENT_ID" bigint NOT NULL,
    "GROUPNAME" character varying(255),
    "PROPERTYNAME" character varying(255) NOT NULL,
    "PROPERTYVALUE" character varying(1024),
    "PROPERTYTYPE" text NOT NULL,
    "DESCRIPTION" character varying(255),
    "UUID" uuid NOT NULL,
    CONSTRAINT "COMPONENT_PROPERTY_TYPE_check" CHECK ((("PROPERTYTYPE" IS NULL) OR ("PROPERTYTYPE" = ANY (ARRAY['BOOLEAN'::text, 'INTEGER'::text, 'NUMBER'::text, 'STRING'::text, 'TIMESTAMP'::text, 'URL'::text, 'UUID'::text]))))
);

ALTER TABLE "COMPONENT_PROPERTY" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "COMPONENT_PROPERTY_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "CONFIGPROPERTY" (
    "ID" bigint NOT NULL,
    "DESCRIPTION" character varying(255),
    "GROUPNAME" character varying(255) NOT NULL,
    "PROPERTYNAME" character varying(255) NOT NULL,
    "PROPERTYTYPE" character varying(255) NOT NULL,
    "PROPERTYVALUE" text
);

ALTER TABLE "CONFIGPROPERTY" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "CONFIGPROPERTY_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "DEPENDENCYMETRICS" (
    "COMPONENT_ID" bigint NOT NULL,
    "CRITICAL" integer NOT NULL,
    "FINDINGS_AUDITED" integer,
    "FINDINGS_TOTAL" integer,
    "FINDINGS_UNAUDITED" integer,
    "FIRST_OCCURRENCE" timestamp with time zone NOT NULL,
    "HIGH" integer NOT NULL,
    "RISKSCORE" double precision NOT NULL,
    "LAST_OCCURRENCE" timestamp with time zone NOT NULL,
    "LOW" integer NOT NULL,
    "MEDIUM" integer NOT NULL,
    "POLICYVIOLATIONS_AUDITED" integer,
    "POLICYVIOLATIONS_FAIL" integer,
    "POLICYVIOLATIONS_INFO" integer,
    "POLICYVIOLATIONS_LICENSE_AUDITED" integer,
    "POLICYVIOLATIONS_LICENSE_TOTAL" integer,
    "POLICYVIOLATIONS_LICENSE_UNAUDITED" integer,
    "POLICYVIOLATIONS_OPERATIONAL_AUDITED" integer,
    "POLICYVIOLATIONS_OPERATIONAL_TOTAL" integer,
    "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED" integer,
    "POLICYVIOLATIONS_SECURITY_AUDITED" integer,
    "POLICYVIOLATIONS_SECURITY_TOTAL" integer,
    "POLICYVIOLATIONS_SECURITY_UNAUDITED" integer,
    "POLICYVIOLATIONS_TOTAL" integer,
    "POLICYVIOLATIONS_UNAUDITED" integer,
    "POLICYVIOLATIONS_WARN" integer,
    "PROJECT_ID" bigint NOT NULL,
    "SUPPRESSED" integer NOT NULL,
    "UNASSIGNED_SEVERITY" integer,
    "VULNERABILITIES" integer NOT NULL
)
PARTITION BY RANGE ("LAST_OCCURRENCE");

CREATE TABLE "EPSS" (
    "ID" bigint NOT NULL,
    "CVE" text NOT NULL,
    "PERCENTILE" numeric,
    "SCORE" numeric
);

ALTER TABLE "EPSS" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "EPSS_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "EXTENSION_KV_STORE" (
    "EXTENSION_POINT" text NOT NULL,
    "EXTENSION" text NOT NULL,
    "KEY" text NOT NULL,
    "VALUE" text NOT NULL,
    "CREATED_AT" timestamp(3) with time zone NOT NULL,
    "UPDATED_AT" timestamp(3) with time zone,
    "VERSION" bigint NOT NULL
);

CREATE TABLE "EXTENSION_RUNTIME_CONFIG" (
    "EXTENSION_POINT" text NOT NULL,
    "EXTENSION" text NOT NULL,
    "CONFIG" jsonb NOT NULL,
    "CREATED_AT" timestamp(3) with time zone NOT NULL,
    "UPDATED_AT" timestamp(3) with time zone
);

CREATE TABLE "FINDINGATTRIBUTION" (
    "ID" bigint NOT NULL,
    "ALT_ID" character varying(255),
    "ANALYZERIDENTITY" character varying(255) NOT NULL,
    "ATTRIBUTED_ON" timestamp with time zone NOT NULL,
    "COMPONENT_ID" bigint NOT NULL,
    "PROJECT_ID" bigint NOT NULL,
    "REFERENCE_URL" text,
    "VULNERABILITY_ID" bigint NOT NULL,
    "MATCHING_PERCENTAGE" smallint,
    "DELETED_AT" timestamp with time zone
);

ALTER TABLE "FINDINGATTRIBUTION" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "FINDINGATTRIBUTION_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "LICENSE" (
    "ID" bigint NOT NULL,
    "COMMENT" text,
    "ISCUSTOMLICENSE" boolean,
    "ISDEPRECATED" boolean NOT NULL,
    "FSFLIBRE" boolean,
    "HEADER" text,
    "LICENSEID" character varying(255),
    "NAME" character varying(255) NOT NULL,
    "ISOSIAPPROVED" boolean NOT NULL,
    "SEEALSO" bytea,
    "TEMPLATE" text,
    "TEXT" text,
    "UUID" uuid NOT NULL
);

CREATE TABLE "LICENSEGROUP" (
    "ID" bigint NOT NULL,
    "NAME" character varying(255) NOT NULL,
    "RISKWEIGHT" integer NOT NULL,
    "UUID" uuid NOT NULL
);

ALTER TABLE "LICENSEGROUP" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "LICENSEGROUP_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "LICENSEGROUP_LICENSE" (
    "LICENSEGROUP_ID" bigint NOT NULL,
    "LICENSE_ID" bigint NOT NULL
);

ALTER TABLE "LICENSE" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "LICENSE_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "MAPPEDLDAPGROUP" (
    "ID" bigint NOT NULL,
    "DN" character varying(1024) NOT NULL,
    "TEAM_ID" bigint NOT NULL,
    "UUID" character varying(36) NOT NULL
);

ALTER TABLE "MAPPEDLDAPGROUP" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "MAPPEDLDAPGROUP_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "MAPPEDOIDCGROUP" (
    "ID" bigint NOT NULL,
    "GROUP_ID" bigint NOT NULL,
    "TEAM_ID" bigint NOT NULL,
    "UUID" character varying(36) NOT NULL
);

ALTER TABLE "MAPPEDOIDCGROUP" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "MAPPEDOIDCGROUP_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "NOTIFICATIONPUBLISHER" (
    "ID" bigint NOT NULL,
    "DEFAULT_PUBLISHER" boolean NOT NULL,
    "DESCRIPTION" character varying(255),
    "NAME" character varying(255) NOT NULL,
    "EXTENSION_NAME" character varying(1024) NOT NULL,
    "TEMPLATE" text,
    "TEMPLATE_MIME_TYPE" character varying(255),
    "UUID" uuid NOT NULL
);

ALTER TABLE "NOTIFICATIONPUBLISHER" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "NOTIFICATIONPUBLISHER_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "NOTIFICATIONRULE" (
    "ID" bigint NOT NULL,
    "ENABLED" boolean NOT NULL,
    "MESSAGE" character varying(1024),
    "NAME" character varying(255) NOT NULL,
    "NOTIFICATION_LEVEL" notification_level,
    "NOTIFY_CHILDREN" boolean,
    "PUBLISHER" bigint,
    "PUBLISHER_CONFIG" jsonb,
    "SCOPE" character varying(255) NOT NULL,
    "UUID" uuid NOT NULL,
    "LOG_SUCCESSFUL_PUBLISH" boolean,
    "NOTIFY_ON" text[],
    "TRIGGER_TYPE" text DEFAULT 'EVENT'::text NOT NULL,
    "SCHEDULE_CRON" text,
    "SCHEDULE_LAST_TRIGGERED_AT" timestamp with time zone,
    "SCHEDULE_NEXT_TRIGGER_AT" timestamp with time zone,
    "SCHEDULE_SKIP_UNCHANGED" boolean,
    "FILTER_EXPRESSION" text,
    CONSTRAINT "NOTIFICATIONRULE_TRIGGER_TYPE_check" CHECK (("TRIGGER_TYPE" = ANY (ARRAY['EVENT'::text, 'SCHEDULE'::text])))
);

ALTER TABLE "NOTIFICATIONRULE" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "NOTIFICATIONRULE_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "NOTIFICATIONRULE_PROJECTS" (
    "NOTIFICATIONRULE_ID" bigint NOT NULL,
    "PROJECT_ID" bigint
);

CREATE TABLE "NOTIFICATIONRULE_TAGS" (
    "NOTIFICATIONRULE_ID" bigint NOT NULL,
    "TAG_ID" bigint NOT NULL
);

CREATE TABLE "NOTIFICATIONRULE_TEAMS" (
    "NOTIFICATIONRULE_ID" bigint NOT NULL,
    "TEAM_ID" bigint NOT NULL
);

CREATE TABLE "NOTIFICATION_OUTBOX" (
    "ID" uuid NOT NULL,
    "TIMESTAMP" timestamp(3) with time zone NOT NULL,
    "SCOPE" text NOT NULL,
    "GROUP" text NOT NULL,
    "LEVEL" text NOT NULL,
    "PAYLOAD" bytea NOT NULL
)
WITH (autovacuum_vacuum_scale_factor='0.1');

CREATE TABLE "OIDCGROUP" (
    "ID" bigint NOT NULL,
    "NAME" character varying(1024) NOT NULL,
    "UUID" character varying(36) NOT NULL
);

ALTER TABLE "OIDCGROUP" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "OIDCGROUP_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "PACKAGE_ARTIFACT_METADATA" (
    "PURL" text NOT NULL,
    "PACKAGE_PURL" text NOT NULL,
    "HASH_MD5" character varying(32),
    "HASH_SHA1" character varying(40),
    "HASH_SHA256" character varying(64),
    "HASH_SHA512" character varying(128),
    "PUBLISHED_AT" timestamp with time zone,
    "RESOLVED_BY" text,
    "RESOLVED_FROM" text,
    "RESOLVED_AT" timestamp with time zone
);

CREATE TABLE "PACKAGE_METADATA" (
    "PURL" text NOT NULL,
    "LATEST_VERSION" text,
    "RESOLVED_BY" text,
    "RESOLVED_FROM" text,
    "RESOLVED_AT" timestamp with time zone NOT NULL,
    CONSTRAINT "PACKAGE_METADATA_PURL_CHECK" CHECK ((("PURL" !~~ '%@%'::text) AND ("PURL" !~~ '%?%'::text) AND ("PURL" !~~ '%&%'::text) AND ("PURL" !~~ '%#%'::text)))
);

CREATE TABLE "PERMISSION" (
    "ID" bigint NOT NULL,
    "DESCRIPTION" text,
    "NAME" character varying(255) NOT NULL
);

ALTER TABLE "PERMISSION" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "PERMISSION_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "POLICY" (
    "ID" bigint NOT NULL,
    "INCLUDE_CHILDREN" boolean,
    "NAME" character varying(255) NOT NULL,
    "OPERATOR" character varying(255) NOT NULL,
    "UUID" uuid NOT NULL,
    "VIOLATIONSTATE" character varying(255) NOT NULL,
    "ONLY_LATEST_PROJECT_VERSION" boolean DEFAULT false NOT NULL
);

CREATE TABLE "POLICYCONDITION" (
    "ID" bigint NOT NULL,
    "OPERATOR" character varying(255) NOT NULL,
    "POLICY_ID" bigint NOT NULL,
    "SUBJECT" character varying(255) NOT NULL,
    "UUID" uuid NOT NULL,
    "VALUE" text NOT NULL,
    "VIOLATIONTYPE" character varying(255)
);

ALTER TABLE "POLICYCONDITION" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "POLICYCONDITION_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "POLICYVIOLATION" (
    "ID" bigint NOT NULL,
    "COMPONENT_ID" bigint NOT NULL,
    "POLICYCONDITION_ID" bigint NOT NULL,
    "PROJECT_ID" bigint NOT NULL,
    "TEXT" character varying(255),
    "TIMESTAMP" timestamp with time zone NOT NULL,
    "TYPE" character varying(255) NOT NULL,
    "UUID" uuid NOT NULL
);

ALTER TABLE "POLICYVIOLATION" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "POLICYVIOLATION_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

ALTER TABLE "POLICY" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "POLICY_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "POLICY_PROJECTS" (
    "POLICY_ID" bigint NOT NULL,
    "PROJECT_ID" bigint
);

CREATE TABLE "POLICY_TAGS" (
    "POLICY_ID" bigint NOT NULL,
    "TAG_ID" bigint NOT NULL
);

CREATE TABLE "PROJECT" (
    "ID" bigint NOT NULL,
    "CLASSIFIER" character varying(255),
    "CPE" character varying(255),
    "DESCRIPTION" character varying(255),
    "DIRECT_DEPENDENCIES" jsonb,
    "EXTERNAL_REFERENCES" bytea,
    "GROUP" character varying(255),
    "LAST_BOM_IMPORTED" timestamp with time zone,
    "LAST_BOM_IMPORTED_FORMAT" character varying(255),
    "LAST_RISKSCORE" double precision,
    "NAME" character varying(255) NOT NULL,
    "PARENT_PROJECT_ID" bigint,
    "PUBLISHER" character varying(255),
    "PURL" character varying(1024),
    "SWIDTAGID" character varying(255),
    "UUID" uuid NOT NULL,
    "VERSION" character varying(255),
    "SUPPLIER" text,
    "MANUFACTURER" text,
    "AUTHORS" text,
    "IS_LATEST" boolean DEFAULT false NOT NULL,
    "INACTIVE_SINCE" timestamp with time zone,
    "COLLECTION_LOGIC" text,
    "COLLECTION_TAG_ID" bigint,
    "LAST_VULNERABILITY_ANALYSIS" timestamp with time zone,
    CONSTRAINT "PROJECT_CLASSIFIER_check" CHECK ((("CLASSIFIER" IS NULL) OR (("CLASSIFIER")::text = ANY (ARRAY['APPLICATION'::text, 'CONTAINER'::text, 'CRYPTOGRAPHIC_ASSET'::text, 'DATA'::text, 'DEVICE'::text, 'DEVICE_DRIVER'::text, 'FILE'::text, 'FIRMWARE'::text, 'FRAMEWORK'::text, 'LIBRARY'::text, 'MACHINE_LEARNING_MODEL'::text, 'OPERATING_SYSTEM'::text, 'PLATFORM'::text])))),
    CONSTRAINT "PROJECT_COLLECTION_CLASSIFIER_check" CHECK ((("COLLECTION_LOGIC" IS NULL) OR ("CLASSIFIER" IS NULL))),
    CONSTRAINT "PROJECT_COLLECTION_LOGIC_check" CHECK ((("COLLECTION_LOGIC" IS NULL) OR ("COLLECTION_LOGIC" = ANY (ARRAY['AGGREGATE_DIRECT_CHILDREN'::text, 'AGGREGATE_DIRECT_CHILDREN_WITH_TAG'::text, 'AGGREGATE_LATEST_VERSION_CHILDREN'::text])))),
    CONSTRAINT "PROJECT_COLLECTION_TAG_REQUIRED_check" CHECK (((("COLLECTION_LOGIC" IS DISTINCT FROM 'AGGREGATE_DIRECT_CHILDREN_WITH_TAG'::text) AND ("COLLECTION_TAG_ID" IS NULL)) OR (("COLLECTION_LOGIC" = 'AGGREGATE_DIRECT_CHILDREN_WITH_TAG'::text) AND ("COLLECTION_TAG_ID" IS NOT NULL))))
);

CREATE TABLE "PROJECTMETRICS" (
    "COMPONENTS" integer NOT NULL,
    "CRITICAL" integer NOT NULL,
    "FINDINGS_AUDITED" integer,
    "FINDINGS_TOTAL" integer,
    "FINDINGS_UNAUDITED" integer,
    "FIRST_OCCURRENCE" timestamp with time zone NOT NULL,
    "HIGH" integer NOT NULL,
    "RISKSCORE" double precision NOT NULL,
    "LAST_OCCURRENCE" timestamp with time zone NOT NULL,
    "LOW" integer NOT NULL,
    "MEDIUM" integer NOT NULL,
    "POLICYVIOLATIONS_AUDITED" integer,
    "POLICYVIOLATIONS_FAIL" integer,
    "POLICYVIOLATIONS_INFO" integer,
    "POLICYVIOLATIONS_LICENSE_AUDITED" integer,
    "POLICYVIOLATIONS_LICENSE_TOTAL" integer,
    "POLICYVIOLATIONS_LICENSE_UNAUDITED" integer,
    "POLICYVIOLATIONS_OPERATIONAL_AUDITED" integer,
    "POLICYVIOLATIONS_OPERATIONAL_TOTAL" integer,
    "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED" integer,
    "POLICYVIOLATIONS_SECURITY_AUDITED" integer,
    "POLICYVIOLATIONS_SECURITY_TOTAL" integer,
    "POLICYVIOLATIONS_SECURITY_UNAUDITED" integer,
    "POLICYVIOLATIONS_TOTAL" integer,
    "POLICYVIOLATIONS_UNAUDITED" integer,
    "POLICYVIOLATIONS_WARN" integer,
    "PROJECT_ID" bigint NOT NULL,
    "SUPPRESSED" integer NOT NULL,
    "UNASSIGNED_SEVERITY" integer,
    "VULNERABILITIES" integer NOT NULL,
    "VULNERABLECOMPONENTS" integer NOT NULL
)
PARTITION BY RANGE ("LAST_OCCURRENCE");

CREATE MATERIALIZED VIEW "PORTFOLIOMETRICS_GLOBAL" AS
 WITH retention AS (
         SELECT COALESCE(( SELECT ("CONFIGPROPERTY"."PROPERTYVALUE")::integer AS "PROPERTYVALUE"
                   FROM "CONFIGPROPERTY"
                  WHERE ((("CONFIGPROPERTY"."GROUPNAME")::text = 'maintenance'::text) AND (("CONFIGPROPERTY"."PROPERTYNAME")::text = 'metrics.retention.days'::text))), 90) AS days
        ), date_range AS (
         SELECT date_trunc('day'::text, (CURRENT_DATE - ('1 day'::interval * (day.day)::double precision))) AS metrics_date
           FROM generate_series(0, GREATEST((( SELECT retention.days
                   FROM retention) - 1), 0)) day(day)
        ), latest_daily_project_metrics AS (
         SELECT date_range_1.metrics_date,
            latest_metrics."COMPONENTS",
            latest_metrics."CRITICAL",
            latest_metrics."FINDINGS_AUDITED",
            latest_metrics."FINDINGS_TOTAL",
            latest_metrics."FINDINGS_UNAUDITED",
            latest_metrics."FIRST_OCCURRENCE",
            latest_metrics."HIGH",
            latest_metrics."RISKSCORE",
            latest_metrics."LAST_OCCURRENCE",
            latest_metrics."LOW",
            latest_metrics."MEDIUM",
            latest_metrics."POLICYVIOLATIONS_AUDITED",
            latest_metrics."POLICYVIOLATIONS_FAIL",
            latest_metrics."POLICYVIOLATIONS_INFO",
            latest_metrics."POLICYVIOLATIONS_LICENSE_AUDITED",
            latest_metrics."POLICYVIOLATIONS_LICENSE_TOTAL",
            latest_metrics."POLICYVIOLATIONS_LICENSE_UNAUDITED",
            latest_metrics."POLICYVIOLATIONS_OPERATIONAL_AUDITED",
            latest_metrics."POLICYVIOLATIONS_OPERATIONAL_TOTAL",
            latest_metrics."POLICYVIOLATIONS_OPERATIONAL_UNAUDITED",
            latest_metrics."POLICYVIOLATIONS_SECURITY_AUDITED",
            latest_metrics."POLICYVIOLATIONS_SECURITY_TOTAL",
            latest_metrics."POLICYVIOLATIONS_SECURITY_UNAUDITED",
            latest_metrics."POLICYVIOLATIONS_TOTAL",
            latest_metrics."POLICYVIOLATIONS_UNAUDITED",
            latest_metrics."POLICYVIOLATIONS_WARN",
            latest_metrics."PROJECT_ID",
            latest_metrics."SUPPRESSED",
            latest_metrics."UNASSIGNED_SEVERITY",
            latest_metrics."VULNERABILITIES",
            latest_metrics."VULNERABLECOMPONENTS"
           FROM (date_range date_range_1
             LEFT JOIN LATERAL ( SELECT DISTINCT ON (pm."PROJECT_ID") pm."COMPONENTS",
                    pm."CRITICAL",
                    pm."FINDINGS_AUDITED",
                    pm."FINDINGS_TOTAL",
                    pm."FINDINGS_UNAUDITED",
                    pm."FIRST_OCCURRENCE",
                    pm."HIGH",
                    pm."RISKSCORE",
                    pm."LAST_OCCURRENCE",
                    pm."LOW",
                    pm."MEDIUM",
                    pm."POLICYVIOLATIONS_AUDITED",
                    pm."POLICYVIOLATIONS_FAIL",
                    pm."POLICYVIOLATIONS_INFO",
                    pm."POLICYVIOLATIONS_LICENSE_AUDITED",
                    pm."POLICYVIOLATIONS_LICENSE_TOTAL",
                    pm."POLICYVIOLATIONS_LICENSE_UNAUDITED",
                    pm."POLICYVIOLATIONS_OPERATIONAL_AUDITED",
                    pm."POLICYVIOLATIONS_OPERATIONAL_TOTAL",
                    pm."POLICYVIOLATIONS_OPERATIONAL_UNAUDITED",
                    pm."POLICYVIOLATIONS_SECURITY_AUDITED",
                    pm."POLICYVIOLATIONS_SECURITY_TOTAL",
                    pm."POLICYVIOLATIONS_SECURITY_UNAUDITED",
                    pm."POLICYVIOLATIONS_TOTAL",
                    pm."POLICYVIOLATIONS_UNAUDITED",
                    pm."POLICYVIOLATIONS_WARN",
                    pm."PROJECT_ID",
                    pm."SUPPRESSED",
                    pm."UNASSIGNED_SEVERITY",
                    pm."VULNERABILITIES",
                    pm."VULNERABLECOMPONENTS"
                   FROM ("PROJECT" p
                     JOIN "PROJECTMETRICS" pm ON (((pm."PROJECT_ID" = p."ID") AND (p."INACTIVE_SINCE" IS NULL) AND (p."COLLECTION_LOGIC" IS NULL))))
                  WHERE ((pm."LAST_OCCURRENCE" < (date_range_1.metrics_date + '1 day'::interval)) AND (pm."LAST_OCCURRENCE" >= (date_range_1.metrics_date - '1 day'::interval)))
                  ORDER BY pm."PROJECT_ID", pm."LAST_OCCURRENCE" DESC) latest_metrics ON (true))
        ), daily_metrics AS (
         SELECT count(DISTINCT latest_daily_project_metrics."PROJECT_ID") AS projects,
            sum(latest_daily_project_metrics."COMPONENTS") AS components,
            sum(latest_daily_project_metrics."CRITICAL") AS critical,
            latest_daily_project_metrics.metrics_date,
            sum(latest_daily_project_metrics."FINDINGS_AUDITED") AS findings_audited,
            sum(latest_daily_project_metrics."FINDINGS_TOTAL") AS findings_total,
            sum(latest_daily_project_metrics."FINDINGS_UNAUDITED") AS findings_unaudited,
            sum(latest_daily_project_metrics."HIGH") AS high,
            sum(latest_daily_project_metrics."RISKSCORE") AS inherited_risk_score,
            sum(latest_daily_project_metrics."LOW") AS low,
            sum(latest_daily_project_metrics."MEDIUM") AS medium,
            sum(latest_daily_project_metrics."POLICYVIOLATIONS_AUDITED") AS policy_violations_audited,
            sum(latest_daily_project_metrics."POLICYVIOLATIONS_FAIL") AS policy_violations_fail,
            sum(latest_daily_project_metrics."POLICYVIOLATIONS_INFO") AS policy_violations_info,
            sum(latest_daily_project_metrics."POLICYVIOLATIONS_LICENSE_AUDITED") AS policy_violations_license_audited,
            sum(latest_daily_project_metrics."POLICYVIOLATIONS_LICENSE_TOTAL") AS policy_violations_license_total,
            sum(latest_daily_project_metrics."POLICYVIOLATIONS_LICENSE_UNAUDITED") AS policy_violations_license_unaudited,
            sum(latest_daily_project_metrics."POLICYVIOLATIONS_OPERATIONAL_AUDITED") AS policy_violations_operational_audited,
            sum(latest_daily_project_metrics."POLICYVIOLATIONS_OPERATIONAL_TOTAL") AS policy_violations_operational_total,
            sum(latest_daily_project_metrics."POLICYVIOLATIONS_OPERATIONAL_UNAUDITED") AS policy_violations_operational_unaudited,
            sum(latest_daily_project_metrics."POLICYVIOLATIONS_SECURITY_AUDITED") AS policy_violations_security_audited,
            sum(latest_daily_project_metrics."POLICYVIOLATIONS_SECURITY_TOTAL") AS policy_violations_security_total,
            sum(latest_daily_project_metrics."POLICYVIOLATIONS_SECURITY_UNAUDITED") AS policy_violations_security_unaudited,
            sum(latest_daily_project_metrics."POLICYVIOLATIONS_TOTAL") AS policy_violations_total,
            sum(latest_daily_project_metrics."POLICYVIOLATIONS_UNAUDITED") AS policy_violations_unaudited,
            sum(latest_daily_project_metrics."POLICYVIOLATIONS_WARN") AS policy_violations_warn,
            sum(latest_daily_project_metrics."SUPPRESSED") AS suppressed,
            sum(latest_daily_project_metrics."UNASSIGNED_SEVERITY") AS unassigned,
            sum(latest_daily_project_metrics."VULNERABILITIES") AS vulnerabilities,
            sum(latest_daily_project_metrics."VULNERABLECOMPONENTS") AS vulnerable_components,
            sum(
                CASE
                    WHEN (latest_daily_project_metrics."VULNERABLECOMPONENTS" > 0) THEN 1
                    ELSE 0
                END) AS vulnerable_projects
           FROM latest_daily_project_metrics
          GROUP BY latest_daily_project_metrics.metrics_date
        )
 SELECT COALESCE(dm.components, (0)::bigint) AS "COMPONENTS",
    COALESCE(dm.critical, (0)::bigint) AS "CRITICAL",
    COALESCE(dm.findings_audited, (0)::bigint) AS "FINDINGS_AUDITED",
    COALESCE(dm.findings_total, (0)::bigint) AS "FINDINGS_TOTAL",
    COALESCE(dm.findings_unaudited, (0)::bigint) AS "FINDINGS_UNAUDITED",
    date_range.metrics_date AS "FIRST_OCCURRENCE",
    COALESCE(dm.high, (0)::bigint) AS "HIGH",
    COALESCE(dm.inherited_risk_score, (0)::double precision) AS "INHERITED_RISK_SCORE",
    date_range.metrics_date AS "LAST_OCCURRENCE",
    COALESCE(dm.low, (0)::bigint) AS "LOW",
    COALESCE(dm.medium, (0)::bigint) AS "MEDIUM",
    COALESCE(dm.policy_violations_audited, (0)::bigint) AS "POLICY_VIOLATIONS_AUDITED",
    COALESCE(dm.policy_violations_fail, (0)::bigint) AS "POLICY_VIOLATIONS_FAIL",
    COALESCE(dm.policy_violations_info, (0)::bigint) AS "POLICY_VIOLATIONS_INFO",
    COALESCE(dm.policy_violations_license_audited, (0)::bigint) AS "POLICY_VIOLATIONS_LICENSE_AUDITED",
    COALESCE(dm.policy_violations_license_total, (0)::bigint) AS "POLICY_VIOLATIONS_LICENSE_TOTAL",
    COALESCE(dm.policy_violations_license_unaudited, (0)::bigint) AS "POLICY_VIOLATIONS_LICENSE_UNAUDITED",
    COALESCE(dm.policy_violations_operational_audited, (0)::bigint) AS "POLICY_VIOLATIONS_OPERATIONAL_AUDITED",
    COALESCE(dm.policy_violations_operational_total, (0)::bigint) AS "POLICY_VIOLATIONS_OPERATIONAL_TOTAL",
    COALESCE(dm.policy_violations_operational_unaudited, (0)::bigint) AS "POLICY_VIOLATIONS_OPERATIONAL_UNAUDITED",
    COALESCE(dm.policy_violations_security_audited, (0)::bigint) AS "POLICY_VIOLATIONS_SECURITY_AUDITED",
    COALESCE(dm.policy_violations_security_total, (0)::bigint) AS "POLICY_VIOLATIONS_SECURITY_TOTAL",
    COALESCE(dm.policy_violations_security_unaudited, (0)::bigint) AS "POLICY_VIOLATIONS_SECURITY_UNAUDITED",
    COALESCE(dm.policy_violations_total, (0)::bigint) AS "POLICY_VIOLATIONS_TOTAL",
    COALESCE(dm.policy_violations_unaudited, (0)::bigint) AS "POLICY_VIOLATIONS_UNAUDITED",
    COALESCE(dm.policy_violations_warn, (0)::bigint) AS "POLICY_VIOLATIONS_WARN",
    COALESCE(dm.projects, (0)::bigint) AS "PROJECTS",
    COALESCE(dm.suppressed, (0)::bigint) AS "SUPPRESSED",
    COALESCE(dm.unassigned, (0)::bigint) AS "UNASSIGNED",
    COALESCE(dm.vulnerabilities, (0)::bigint) AS "VULNERABILITIES",
    COALESCE(dm.vulnerable_components, (0)::bigint) AS "VULNERABLE_COMPONENTS",
    COALESCE(dm.vulnerable_projects, (0)::bigint) AS "VULNERABLE_PROJECTS"
   FROM (date_range
     LEFT JOIN daily_metrics dm ON ((date_range.metrics_date = dm.metrics_date)))
  WITH NO DATA;

CREATE TABLE "PROJECTS_TAGS" (
    "TAG_ID" bigint NOT NULL,
    "PROJECT_ID" bigint NOT NULL
);

CREATE TABLE "PROJECT_ACCESS_TEAMS" (
    "PROJECT_ID" bigint NOT NULL,
    "TEAM_ID" bigint NOT NULL
);

CREATE TABLE "PROJECT_ACCESS_USERS" (
    "PROJECT_ID" bigint NOT NULL,
    "USER_ID" bigint NOT NULL
);

CREATE TABLE "PROJECT_HIERARCHY" (
    "PARENT_PROJECT_ID" bigint NOT NULL,
    "CHILD_PROJECT_ID" bigint NOT NULL,
    "DEPTH" smallint NOT NULL
);

ALTER TABLE "PROJECT" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "PROJECT_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "PROJECT_METADATA" (
    "ID" bigint NOT NULL,
    "PROJECT_ID" bigint NOT NULL,
    "SUPPLIER" text,
    "AUTHORS" text,
    "TOOLS" text
);

ALTER TABLE "PROJECT_METADATA" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "PROJECT_METADATA_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "PROJECT_PROPERTY" (
    "ID" bigint NOT NULL,
    "DESCRIPTION" character varying(255),
    "GROUPNAME" character varying(255) NOT NULL,
    "PROJECT_ID" bigint NOT NULL,
    "PROPERTYNAME" character varying(255) NOT NULL,
    "PROPERTYTYPE" character varying(255) NOT NULL,
    "PROPERTYVALUE" character varying(1024)
);

ALTER TABLE "PROJECT_PROPERTY" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "PROJECT_PROPERTY_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "REPOSITORY" (
    "ID" bigint NOT NULL,
    "AUTHENTICATIONREQUIRED" boolean,
    "ENABLED" boolean NOT NULL,
    "IDENTIFIER" character varying(255) NOT NULL,
    "INTERNAL" boolean,
    "PASSWORD" character varying(255),
    "RESOLUTION_ORDER" integer NOT NULL,
    "TYPE" character varying(255) NOT NULL,
    "URL" character varying(255),
    "USERNAME" character varying(255),
    "UUID" uuid
);

ALTER TABLE "REPOSITORY" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "REPOSITORY_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "SCHEDULED_TASK_EXECUTION" (
    "TASK_ID" text NOT NULL,
    "LAST_EXECUTED_AT" timestamp with time zone,
    "LOCK_VERSION" bigint NOT NULL
);

CREATE TABLE "SECRET" (
    "NAME" text NOT NULL,
    "DESCRIPTION" text,
    "VALUE" bytea NOT NULL,
    "DEK" bytea NOT NULL,
    "CREATED_AT" timestamp(3) with time zone NOT NULL,
    "UPDATED_AT" timestamp(3) with time zone
);

CREATE TABLE "SERVICECOMPONENT" (
    "ID" bigint NOT NULL,
    "AUTHENTICATED" boolean,
    "X_TRUST_BOUNDARY" boolean,
    "DATA" bytea,
    "DESCRIPTION" character varying(1024),
    "ENDPOINTS" bytea,
    "EXTERNAL_REFERENCES" bytea,
    "GROUP" character varying(255),
    "LAST_RISKSCORE" double precision DEFAULT '0'::double precision NOT NULL,
    "NAME" character varying(255) NOT NULL,
    "TEXT" text,
    "PARENT_SERVICECOMPONENT_ID" bigint,
    "PROJECT_ID" bigint NOT NULL,
    "PROVIDER_ID" bytea,
    "UUID" uuid NOT NULL,
    "VERSION" character varying(255)
);

CREATE TABLE "SERVICECOMPONENTS_VULNERABILITIES" (
    "VULNERABILITY_ID" bigint NOT NULL,
    "SERVICECOMPONENT_ID" bigint NOT NULL
);

ALTER TABLE "SERVICECOMPONENT" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "SERVICECOMPONENT_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "TAG" (
    "ID" bigint NOT NULL,
    "NAME" character varying(255) NOT NULL
);

ALTER TABLE "TAG" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "TAG_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "TEAM" (
    "ID" bigint NOT NULL,
    "NAME" character varying(255) NOT NULL,
    "UUID" character varying(36) NOT NULL
);

CREATE TABLE "TEAMS_PERMISSIONS" (
    "TEAM_ID" bigint NOT NULL,
    "PERMISSION_ID" bigint NOT NULL
);

ALTER TABLE "TEAM" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "TEAM_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "USER" (
    "ID" bigint NOT NULL,
    "USERNAME" text NOT NULL,
    "EMAIL" text,
    "TYPE" text NOT NULL,
    "DN" text,
    "FULLNAME" text,
    "FORCE_PASSWORD_CHANGE" boolean,
    "SUSPENDED" boolean,
    "NON_EXPIRY_PASSWORD" boolean,
    "LAST_PASSWORD_CHANGE" timestamp with time zone,
    "PASSWORD" text,
    "SUBJECT_IDENTIFIER" text,
    CONSTRAINT user_ldap_check CHECK (((("TYPE" = 'LDAP'::text) AND ("DN" IS NOT NULL)) OR (("TYPE" <> 'LDAP'::text) AND ("DN" IS NULL)))),
    CONSTRAINT user_managed_check CHECK (((("TYPE" = 'MANAGED'::text) AND ("FORCE_PASSWORD_CHANGE" IS NOT NULL) AND ("LAST_PASSWORD_CHANGE" IS NOT NULL) AND ("NON_EXPIRY_PASSWORD" IS NOT NULL) AND ("PASSWORD" IS NOT NULL) AND ("SUSPENDED" IS NOT NULL)) OR (("TYPE" <> 'MANAGED'::text) AND ("FORCE_PASSWORD_CHANGE" IS NULL) AND ("FULLNAME" IS NULL) AND ("LAST_PASSWORD_CHANGE" IS NULL) AND ("NON_EXPIRY_PASSWORD" IS NULL) AND ("PASSWORD" IS NULL) AND ("SUSPENDED" IS NULL)))),
    CONSTRAINT user_oidc_check CHECK ((("TYPE" = 'OIDC'::text) OR ("SUBJECT_IDENTIFIER" IS NULL))),
    CONSTRAINT user_type_check CHECK (("TYPE" = ANY (ARRAY['MANAGED'::text, 'LDAP'::text, 'OIDC'::text])))
);

CREATE TABLE "USERS_PERMISSIONS" (
    "USER_ID" bigint NOT NULL,
    "PERMISSION_ID" bigint NOT NULL
);

CREATE TABLE "USERS_TEAMS" (
    "USER_ID" bigint NOT NULL,
    "TEAM_ID" bigint NOT NULL
);

ALTER TABLE "USER" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "USER_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "USER_SESSION" (
    "TOKEN_HASH" character varying(64) NOT NULL,
    "USER_ID" bigint NOT NULL,
    "CREATED_AT" timestamp with time zone DEFAULT now() NOT NULL,
    "EXPIRES_AT" timestamp with time zone NOT NULL,
    "LAST_USED_AT" timestamp with time zone
);

CREATE TABLE "VEX" (
    "ID" bigint NOT NULL,
    "IMPORTED" timestamp with time zone NOT NULL,
    "PROJECT_ID" bigint NOT NULL,
    "SERIAL_NUMBER" character varying(255),
    "SPEC_VERSION" character varying(255),
    "UUID" uuid NOT NULL,
    "VEX_FORMAT" character varying(255),
    "VEX_VERSION" integer
);

ALTER TABLE "VEX" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "VEX_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "VIOLATIONANALYSIS" (
    "ID" bigint NOT NULL,
    "STATE" character varying(255) NOT NULL,
    "COMPONENT_ID" bigint,
    "POLICYVIOLATION_ID" bigint NOT NULL,
    "PROJECT_ID" bigint,
    "SUPPRESSED" boolean NOT NULL
);

CREATE TABLE "VIOLATIONANALYSISCOMMENT" (
    "ID" bigint NOT NULL,
    "COMMENT" text NOT NULL,
    "COMMENTER" character varying(255),
    "TIMESTAMP" timestamp with time zone NOT NULL,
    "VIOLATIONANALYSIS_ID" bigint NOT NULL
);

ALTER TABLE "VIOLATIONANALYSISCOMMENT" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "VIOLATIONANALYSISCOMMENT_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

ALTER TABLE "VIOLATIONANALYSIS" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "VIOLATIONANALYSIS_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "VULNERABILITIES_TAGS" (
    "TAG_ID" bigint NOT NULL,
    "VULNERABILITY_ID" bigint NOT NULL
);

CREATE TABLE "VULNERABILITY" (
    "ID" bigint NOT NULL,
    "CREATED" timestamp with time zone,
    "CREDITS" text,
    "CVSSV2BASESCORE" numeric,
    "CVSSV2EXPLOITSCORE" numeric,
    "CVSSV2IMPACTSCORE" numeric,
    "CVSSV2VECTOR" character varying(255),
    "CVSSV3BASESCORE" numeric,
    "CVSSV3EXPLOITSCORE" numeric,
    "CVSSV3IMPACTSCORE" numeric,
    "CVSSV3VECTOR" character varying(255),
    "CWES" character varying(255),
    "DESCRIPTION" text,
    "DETAIL" text,
    "FRIENDLYVULNID" character varying(255),
    "OWASPRRBUSINESSIMPACTSCORE" numeric,
    "OWASPRRLIKELIHOODSCORE" numeric,
    "OWASPRRTECHNICALIMPACTSCORE" numeric,
    "OWASPRRVECTOR" character varying(255),
    "PATCHEDVERSIONS" character varying(255),
    "PUBLISHED" timestamp with time zone,
    "RECOMMENDATION" text,
    "REFERENCES" text,
    "SEVERITY" severity,
    "SOURCE" character varying(255) NOT NULL,
    "SUBTITLE" character varying(255),
    "TITLE" character varying(255),
    "UPDATED" timestamp with time zone,
    "UUID" uuid NOT NULL,
    "VULNID" character varying(255) NOT NULL,
    "VULNERABLEVERSIONS" character varying(255),
    "CVSSV4SCORE" numeric,
    "CVSSV4VECTOR" character varying(255)
);

CREATE TABLE "VULNERABILITYMETRICS" (
    "ID" bigint NOT NULL,
    "COUNT" integer NOT NULL,
    "MEASURED_AT" timestamp with time zone NOT NULL,
    "MONTH" integer,
    "YEAR" integer NOT NULL
);

ALTER TABLE "VULNERABILITYMETRICS" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "VULNERABILITYMETRICS_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "VULNERABILITY_ALIAS" (
    "GROUP_ID" uuid NOT NULL,
    "SOURCE" text NOT NULL,
    "VULN_ID" text NOT NULL
);

CREATE TABLE "VULNERABILITY_ALIAS_ASSERTION" (
    "ASSERTER" text NOT NULL,
    "VULN_SOURCE" text NOT NULL,
    "VULN_ID" text NOT NULL,
    "ALIAS_SOURCE" text NOT NULL,
    "ALIAS_ID" text NOT NULL,
    "CREATED_AT" timestamp(3) with time zone DEFAULT now() NOT NULL
);

ALTER TABLE "VULNERABILITY" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "VULNERABILITY_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "VULNERABILITY_POLICY" (
    "ID" bigint NOT NULL,
    "ANALYSIS" jsonb NOT NULL,
    "AUTHOR" character varying(255),
    "CREATED" timestamp with time zone,
    "DESCRIPTION" character varying(512),
    "NAME" character varying(255) NOT NULL,
    "RATINGS" jsonb,
    "UPDATED" timestamp with time zone,
    "VALID_FROM" timestamp with time zone,
    "VALID_UNTIL" timestamp with time zone,
    "OPERATION_MODE" character varying(255) DEFAULT 'APPLY'::character varying NOT NULL,
    "UUID" uuid DEFAULT gen_random_uuid() NOT NULL,
    "PRIORITY" smallint DEFAULT 0 NOT NULL,
    "VULNERABILITY_POLICY_BUNDLE_ID" bigint,
    "CONDITION" text NOT NULL,
    CONSTRAINT "VULNERABILITY_POLICY_PRIORITY_check" CHECK ((("PRIORITY" >= 0) AND ("PRIORITY" <= 100)))
);

CREATE TABLE "VULNERABILITY_POLICY_BUNDLE" (
    "ID" bigint NOT NULL,
    "URL" character varying(2048) NOT NULL,
    "HASH" character varying(255),
    "LAST_SUCCESSFUL_SYNC" timestamp with time zone,
    "CREATED" timestamp with time zone,
    "UPDATED" timestamp with time zone,
    "UUID" uuid DEFAULT gen_random_uuid() NOT NULL
);

ALTER TABLE "VULNERABILITY_POLICY_BUNDLE" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "VULNERABILITY_POLICY_BUNDLE_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

ALTER TABLE "VULNERABILITY_POLICY" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "VULNERABILITY_POLICY_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "VULNERABLESOFTWARE" (
    "ID" bigint NOT NULL,
    "CPE22" character varying(255),
    "CPE23" character varying(255),
    "EDITION" character varying(255),
    "LANGUAGE" character varying(255),
    "OTHER" character varying(255),
    "PART" character varying(255),
    "PRODUCT" character varying(255),
    "PURL" character varying(1024),
    "PURL_NAME" character varying(255),
    "PURL_NAMESPACE" character varying(255),
    "PURL_QUALIFIERS" character varying(255),
    "PURL_SUBPATH" character varying(255),
    "PURL_TYPE" character varying(255),
    "PURL_VERSION" character varying(255),
    "SWEDITION" character varying(255),
    "TARGETHW" character varying(255),
    "TARGETSW" character varying(255),
    "UPDATE" character varying(255),
    "UUID" uuid NOT NULL,
    "VENDOR" character varying(255),
    "VERSION" character varying(255),
    "VERSIONENDEXCLUDING" character varying(255),
    "VERSIONENDINCLUDING" character varying(255),
    "VERSIONSTARTEXCLUDING" character varying(255),
    "VERSIONSTARTINCLUDING" character varying(255),
    "VULNERABLE" boolean NOT NULL
);

ALTER TABLE "VULNERABLESOFTWARE" ALTER COLUMN "ID" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "VULNERABLESOFTWARE_ID_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE "VULNERABLESOFTWARE_VULNERABILITIES" (
    "VULNERABILITY_ID" bigint NOT NULL,
    "VULNERABLESOFTWARE_ID" bigint NOT NULL
);

CREATE TABLE shedlock (
    name character varying(64) NOT NULL,
    lock_until timestamp without time zone NOT NULL,
    locked_at timestamp without time zone NOT NULL,
    locked_by character varying(255) NOT NULL
);

ALTER TABLE ONLY "AFFECTEDVERSIONATTRIBUTION"
    ADD CONSTRAINT "AFFECTEDVERSIONATTRIBUTION_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "AFFECTEDVERSIONATTRIBUTION"
    ADD CONSTRAINT "AFFECTEDVERSIONATTRIBUTION_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY "ANALYSISCOMMENT"
    ADD CONSTRAINT "ANALYSISCOMMENT_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "ANALYSIS"
    ADD CONSTRAINT "ANALYSIS_COMPOSITE_IDX" UNIQUE ("PROJECT_ID", "COMPONENT_ID", "VULNERABILITY_ID");

ALTER TABLE ONLY "ANALYSIS"
    ADD CONSTRAINT "ANALYSIS_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "APIKEYS_TEAMS"
    ADD CONSTRAINT "APIKEYS_TEAMS_PK" PRIMARY KEY ("TEAM_ID", "APIKEY_ID");

ALTER TABLE ONLY "APIKEY"
    ADD CONSTRAINT "APIKEY_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "BOM"
    ADD CONSTRAINT "BOM_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "BOM"
    ADD CONSTRAINT "BOM_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY "CACHE_ENTRY"
    ADD CONSTRAINT "CACHE_ENTRY_PK" PRIMARY KEY ("CACHE_NAME", "KEY");

ALTER TABLE ONLY "COMPONENT_OCCURRENCE"
    ADD CONSTRAINT "COMPONENT_OCCURRENCE_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "COMPONENT"
    ADD CONSTRAINT "COMPONENT_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "COMPONENT_PROPERTY"
    ADD CONSTRAINT "COMPONENT_PROPERTY_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "COMPONENT"
    ADD CONSTRAINT "COMPONENT_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY "CONFIGPROPERTY"
    ADD CONSTRAINT "CONFIGPROPERTY_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "CONFIGPROPERTY"
    ADD CONSTRAINT "CONFIGPROPERTY_U1" UNIQUE ("GROUPNAME", "PROPERTYNAME");

ALTER TABLE ONLY "DEPENDENCYMETRICS"
    ADD CONSTRAINT "DEPENDENCYMETRICS_PK" PRIMARY KEY ("COMPONENT_ID", "LAST_OCCURRENCE");

ALTER TABLE ONLY "EPSS"
    ADD CONSTRAINT "EPSS_CVE_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "EPSS"
    ADD CONSTRAINT "EPSS_CVE_key" UNIQUE ("CVE");

ALTER TABLE ONLY "EXTENSION_KV_STORE"
    ADD CONSTRAINT "EXTENSION_KV_STORE_PK" PRIMARY KEY ("EXTENSION_POINT", "EXTENSION", "KEY");

ALTER TABLE ONLY "EXTENSION_RUNTIME_CONFIG"
    ADD CONSTRAINT "EXTENSION_RUNTIME_CONFIG_PK" PRIMARY KEY ("EXTENSION_POINT", "EXTENSION");

ALTER TABLE ONLY "FINDINGATTRIBUTION"
    ADD CONSTRAINT "FINDINGATTRIBUTION_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "LICENSEGROUP"
    ADD CONSTRAINT "LICENSEGROUP_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "LICENSEGROUP"
    ADD CONSTRAINT "LICENSEGROUP_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY "LICENSE"
    ADD CONSTRAINT "LICENSE_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "LICENSE"
    ADD CONSTRAINT "LICENSE_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY "MAPPEDLDAPGROUP"
    ADD CONSTRAINT "MAPPEDLDAPGROUP_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "MAPPEDLDAPGROUP"
    ADD CONSTRAINT "MAPPEDLDAPGROUP_U1" UNIQUE ("TEAM_ID", "DN");

ALTER TABLE ONLY "MAPPEDLDAPGROUP"
    ADD CONSTRAINT "MAPPEDLDAPGROUP_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY "MAPPEDOIDCGROUP"
    ADD CONSTRAINT "MAPPEDOIDCGROUP_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "MAPPEDOIDCGROUP"
    ADD CONSTRAINT "MAPPEDOIDCGROUP_U1" UNIQUE ("TEAM_ID", "GROUP_ID");

ALTER TABLE ONLY "MAPPEDOIDCGROUP"
    ADD CONSTRAINT "MAPPEDOIDCGROUP_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY "NOTIFICATIONPUBLISHER"
    ADD CONSTRAINT "NOTIFICATIONPUBLISHER_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "NOTIFICATIONPUBLISHER"
    ADD CONSTRAINT "NOTIFICATIONPUBLISHER_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY "NOTIFICATIONRULE"
    ADD CONSTRAINT "NOTIFICATIONRULE_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "NOTIFICATIONRULE_TAGS"
    ADD CONSTRAINT "NOTIFICATIONRULE_TAGS_PK" PRIMARY KEY ("NOTIFICATIONRULE_ID", "TAG_ID");

ALTER TABLE ONLY "NOTIFICATIONRULE_TEAMS"
    ADD CONSTRAINT "NOTIFICATIONRULE_TEAMS_PK" PRIMARY KEY ("NOTIFICATIONRULE_ID", "TEAM_ID");

ALTER TABLE ONLY "NOTIFICATIONRULE"
    ADD CONSTRAINT "NOTIFICATIONRULE_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY "NOTIFICATION_OUTBOX"
    ADD CONSTRAINT "NOTIFICATION_OUTBOX_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "OIDCGROUP"
    ADD CONSTRAINT "OIDCGROUP_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "OIDCGROUP"
    ADD CONSTRAINT "OIDCGROUP_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY "PACKAGE_ARTIFACT_METADATA"
    ADD CONSTRAINT "PACKAGE_ARTIFACT_METADATA_PK" PRIMARY KEY ("PURL");

ALTER TABLE ONLY "PACKAGE_METADATA"
    ADD CONSTRAINT "PACKAGE_METADATA_PK" PRIMARY KEY ("PURL");

ALTER TABLE ONLY "PERMISSION"
    ADD CONSTRAINT "PERMISSION_IDX" UNIQUE ("NAME");

ALTER TABLE ONLY "PERMISSION"
    ADD CONSTRAINT "PERMISSION_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "POLICYCONDITION"
    ADD CONSTRAINT "POLICYCONDITION_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "POLICYCONDITION"
    ADD CONSTRAINT "POLICYCONDITION_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY "POLICYVIOLATION"
    ADD CONSTRAINT "POLICYVIOLATION_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "POLICYVIOLATION"
    ADD CONSTRAINT "POLICYVIOLATION_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY "POLICY"
    ADD CONSTRAINT "POLICY_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "POLICY_TAGS"
    ADD CONSTRAINT "POLICY_TAGS_PK" PRIMARY KEY ("POLICY_ID", "TAG_ID");

ALTER TABLE ONLY "POLICY"
    ADD CONSTRAINT "POLICY_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY "PROJECTMETRICS"
    ADD CONSTRAINT "PROJECTMETRICS_PK" PRIMARY KEY ("PROJECT_ID", "LAST_OCCURRENCE");

ALTER TABLE ONLY "PROJECTS_TAGS"
    ADD CONSTRAINT "PROJECTS_TAGS_PK" PRIMARY KEY ("PROJECT_ID", "TAG_ID");

ALTER TABLE ONLY "PROJECT_ACCESS_TEAMS"
    ADD CONSTRAINT "PROJECT_ACCESS_TEAMS_PK" PRIMARY KEY ("PROJECT_ID", "TEAM_ID");

ALTER TABLE ONLY "PROJECT_ACCESS_USERS"
    ADD CONSTRAINT "PROJECT_ACCESS_USERS_PK" PRIMARY KEY ("PROJECT_ID", "USER_ID");

ALTER TABLE ONLY "PROJECT_HIERARCHY"
    ADD CONSTRAINT "PROJECT_HIERARCHY_PK" PRIMARY KEY ("PARENT_PROJECT_ID", "CHILD_PROJECT_ID");

ALTER TABLE ONLY "PROJECT_METADATA"
    ADD CONSTRAINT "PROJECT_METADATA_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "PROJECT"
    ADD CONSTRAINT "PROJECT_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "PROJECT_PROPERTY"
    ADD CONSTRAINT "PROJECT_PROPERTY_KEYS_IDX" UNIQUE ("PROJECT_ID", "GROUPNAME", "PROPERTYNAME");

ALTER TABLE ONLY "PROJECT_PROPERTY"
    ADD CONSTRAINT "PROJECT_PROPERTY_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "PROJECT"
    ADD CONSTRAINT "PROJECT_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY "REPOSITORY"
    ADD CONSTRAINT "REPOSITORY_COMPOUND_IDX" UNIQUE ("TYPE", "IDENTIFIER");

ALTER TABLE ONLY "REPOSITORY"
    ADD CONSTRAINT "REPOSITORY_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "SCHEDULED_TASK_EXECUTION"
    ADD CONSTRAINT "SCHEDULED_TASK_EXECUTION_PK" PRIMARY KEY ("TASK_ID");

ALTER TABLE ONLY "SECRET"
    ADD CONSTRAINT "SECRET_PK" PRIMARY KEY ("NAME");

ALTER TABLE ONLY "SERVICECOMPONENT"
    ADD CONSTRAINT "SERVICECOMPONENT_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "SERVICECOMPONENT"
    ADD CONSTRAINT "SERVICECOMPONENT_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY "TAG"
    ADD CONSTRAINT "TAG_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "TEAMS_PERMISSIONS"
    ADD CONSTRAINT "TEAMS_PERMISSIONS_PK" PRIMARY KEY ("TEAM_ID", "PERMISSION_ID");

ALTER TABLE ONLY "TEAM"
    ADD CONSTRAINT "TEAM_NAME_IDX" UNIQUE ("NAME");

ALTER TABLE ONLY "TEAM"
    ADD CONSTRAINT "TEAM_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "TEAM"
    ADD CONSTRAINT "TEAM_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY "USERS_PERMISSIONS"
    ADD CONSTRAINT "USERS_PERMISSIONS_PK" PRIMARY KEY ("USER_ID", "PERMISSION_ID");

ALTER TABLE ONLY "USERS_TEAMS"
    ADD CONSTRAINT "USERS_TEAMS_PK" PRIMARY KEY ("USER_ID", "TEAM_ID");

ALTER TABLE ONLY "USER"
    ADD CONSTRAINT "USER_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "USER_SESSION"
    ADD CONSTRAINT "USER_SESSION_PK" PRIMARY KEY ("TOKEN_HASH");

ALTER TABLE ONLY "VEX"
    ADD CONSTRAINT "VEX_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "VEX"
    ADD CONSTRAINT "VEX_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY "VIOLATIONANALYSISCOMMENT"
    ADD CONSTRAINT "VIOLATIONANALYSISCOMMENT_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "VIOLATIONANALYSIS"
    ADD CONSTRAINT "VIOLATIONANALYSIS_COMPOSITE_IDX" UNIQUE ("PROJECT_ID", "COMPONENT_ID", "POLICYVIOLATION_ID");

ALTER TABLE ONLY "VIOLATIONANALYSIS"
    ADD CONSTRAINT "VIOLATIONANALYSIS_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "VULNERABILITIES_TAGS"
    ADD CONSTRAINT "VULNERABILITIES_TAGS_PK" PRIMARY KEY ("VULNERABILITY_ID", "TAG_ID");

ALTER TABLE ONLY "VULNERABILITYMETRICS"
    ADD CONSTRAINT "VULNERABILITYMETRICS_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "VULNERABILITY_POLICY"
    ADD CONSTRAINT "VULNERABILITYPOLICY_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "VULNERABILITY_ALIAS_ASSERTION"
    ADD CONSTRAINT "VULNERABILITY_ALIAS_ASSERTION_PK" PRIMARY KEY ("ASSERTER", "VULN_SOURCE", "VULN_ID", "ALIAS_SOURCE", "ALIAS_ID");

ALTER TABLE ONLY "VULNERABILITY_ALIAS"
    ADD CONSTRAINT "VULNERABILITY_ALIAS_PK" PRIMARY KEY ("SOURCE", "VULN_ID");

ALTER TABLE ONLY "VULNERABILITY"
    ADD CONSTRAINT "VULNERABILITY_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "VULNERABILITY_POLICY_BUNDLE"
    ADD CONSTRAINT "VULNERABILITY_POLICY_BUNDLE_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "VULNERABILITY"
    ADD CONSTRAINT "VULNERABILITY_U1" UNIQUE ("VULNID", "SOURCE");

ALTER TABLE ONLY "VULNERABILITY"
    ADD CONSTRAINT "VULNERABILITY_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY "VULNERABLESOFTWARE"
    ADD CONSTRAINT "VULNERABLESOFTWARE_PK" PRIMARY KEY ("ID");

ALTER TABLE ONLY "VULNERABLESOFTWARE"
    ADD CONSTRAINT "VULNERABLESOFTWARE_UUID_IDX" UNIQUE ("UUID");

ALTER TABLE ONLY shedlock
    ADD CONSTRAINT shedlock_pk PRIMARY KEY (name);

CREATE INDEX "AFFECTEDVERSIONATTRIBUTION_KEYS_IDX" ON "AFFECTEDVERSIONATTRIBUTION" USING btree ("VULNERABILITY", "VULNERABLE_SOFTWARE");

CREATE INDEX "ANALYSISCOMMENT_ANALYSIS_ID_IDX" ON "ANALYSISCOMMENT" USING btree ("ANALYSIS_ID");

CREATE INDEX "ANALYSIS_COMPONENT_ID_IDX" ON "ANALYSIS" USING btree ("COMPONENT_ID");

CREATE INDEX "ANALYSIS_VULNERABILITY_ID_IDX" ON "ANALYSIS" USING btree ("VULNERABILITY_ID");

CREATE UNIQUE INDEX "APIKEY_PUBLIC_ID_IDX" ON "APIKEY" USING btree ("PUBLIC_ID");

CREATE INDEX "BOM_PROJECT_ID_IDX" ON "BOM" USING btree ("PROJECT_ID");

CREATE INDEX "CACHE_ENTRY_EXPIRES_AT_IDX" ON "CACHE_ENTRY" USING btree ("EXPIRES_AT");

CREATE UNIQUE INDEX "COMPONENTS_VULNERABILITIES_COMPOSITE_IDX" ON "COMPONENTS_VULNERABILITIES" USING btree ("COMPONENT_ID", "VULNERABILITY_ID");

CREATE INDEX "COMPONENTS_VULNERABILITIES_VULNERABILITY_ID_IDX" ON "COMPONENTS_VULNERABILITIES" USING btree ("VULNERABILITY_ID");

CREATE INDEX "COMPONENT_BLAKE2B_256_IDX" ON "COMPONENT" USING btree ("BLAKE2B_256") WHERE ("BLAKE2B_256" IS NOT NULL);

CREATE INDEX "COMPONENT_BLAKE2B_384_IDX" ON "COMPONENT" USING btree ("BLAKE2B_384") WHERE ("BLAKE2B_384" IS NOT NULL);

CREATE INDEX "COMPONENT_BLAKE2B_512_IDX" ON "COMPONENT" USING btree ("BLAKE2B_512") WHERE ("BLAKE2B_512" IS NOT NULL);

CREATE INDEX "COMPONENT_BLAKE3_IDX" ON "COMPONENT" USING btree ("BLAKE3") WHERE ("BLAKE3" IS NOT NULL);

CREATE INDEX "COMPONENT_CLASSIFIER_IDX" ON "COMPONENT" USING btree ("CLASSIFIER");

CREATE INDEX "COMPONENT_COORDINATES_SEARCH_IDX" ON "COMPONENT" USING gin (lower(("NAME")::text) gin_trgm_ops, lower(("VERSION")::text) gin_trgm_ops, lower(("GROUP")::text) gin_trgm_ops);

CREATE INDEX "COMPONENT_CPE_IDX" ON "COMPONENT" USING btree ("CPE");

CREATE INDEX "COMPONENT_DIRECT_DEPENDENCIES_JSONB_IDX" ON "COMPONENT" USING gin ("DIRECT_DEPENDENCIES" jsonb_path_ops);

CREATE INDEX "COMPONENT_GROUP_IDX" ON "COMPONENT" USING btree ("GROUP");

CREATE INDEX "COMPONENT_LAST_RISKSCORE_IDX" ON "COMPONENT" USING btree ("LAST_RISKSCORE");

CREATE INDEX "COMPONENT_LICENSE_ID_IDX" ON "COMPONENT" USING btree ("LICENSE_ID");

CREATE INDEX "COMPONENT_MD5_IDX" ON "COMPONENT" USING btree ("MD5") WHERE ("MD5" IS NOT NULL);

CREATE INDEX "COMPONENT_NAME_IDX" ON "COMPONENT" USING btree ("NAME");

CREATE UNIQUE INDEX "COMPONENT_NAME_VERSION_ID_IDX" ON "COMPONENT" USING btree ("NAME", "VERSION" DESC, "ID");

CREATE INDEX "COMPONENT_OCCURRENCE_COMPONENT_ID_IDX" ON "COMPONENT_OCCURRENCE" USING btree ("COMPONENT_ID");

CREATE INDEX "COMPONENT_PARENT_COMPONENT_ID_IDX" ON "COMPONENT" USING btree ("PARENT_COMPONENT_ID");

CREATE INDEX "COMPONENT_PROJECT_ID_IDX" ON "COMPONENT" USING btree ("PROJECT_ID");

CREATE INDEX "COMPONENT_PROPERTY_COMPONENT_ID_IDX" ON "COMPONENT_PROPERTY" USING btree ("COMPONENT_ID");

CREATE INDEX "COMPONENT_PURL_COORDINATES_IDX" ON "COMPONENT" USING btree ("PURLCOORDINATES");

CREATE INDEX "COMPONENT_PURL_IDX" ON "COMPONENT" USING btree ("PURL");

CREATE INDEX "COMPONENT_PURL_SEARCH_IDX" ON "COMPONENT" USING btree (lower(("PURL")::text) text_pattern_ops) WHERE ("PURL" IS NOT NULL);

CREATE INDEX "COMPONENT_SHA1_IDX" ON "COMPONENT" USING btree ("SHA1") WHERE ("SHA1" IS NOT NULL);

CREATE INDEX "COMPONENT_SHA3_256_IDX" ON "COMPONENT" USING btree ("SHA3_256") WHERE ("SHA3_256" IS NOT NULL);

CREATE INDEX "COMPONENT_SHA3_384_IDX" ON "COMPONENT" USING btree ("SHA3_384") WHERE ("SHA3_384" IS NOT NULL);

CREATE INDEX "COMPONENT_SHA3_512_IDX" ON "COMPONENT" USING btree ("SHA3_512") WHERE ("SHA3_512" IS NOT NULL);

CREATE INDEX "COMPONENT_SHA_256_IDX" ON "COMPONENT" USING btree ("SHA_256") WHERE ("SHA_256" IS NOT NULL);

CREATE INDEX "COMPONENT_SHA_384_IDX" ON "COMPONENT" USING btree ("SHA_384") WHERE ("SHA_384" IS NOT NULL);

CREATE INDEX "COMPONENT_SHA_512_IDX" ON "COMPONENT" USING btree ("SHA_512") WHERE ("SHA_512" IS NOT NULL);

CREATE INDEX "COMPONENT_SWID_TAGID_IDX" ON "COMPONENT" USING btree ("SWIDTAGID");

CREATE INDEX "DEPENDENCYMETRICS_PROJECT_ID_IDX" ON ONLY "DEPENDENCYMETRICS" USING btree ("PROJECT_ID");

CREATE UNIQUE INDEX "EPSS_CVE_IDX" ON "EPSS" USING btree ("CVE");

CREATE INDEX "FINDINGATTRIBUTION_COMPONENT_VULN_IDX" ON "FINDINGATTRIBUTION" USING btree ("COMPONENT_ID", "VULNERABILITY_ID", "DELETED_AT" DESC, "ID");

CREATE UNIQUE INDEX "FINDINGATTRIBUTION_COMPOUND_IDX" ON "FINDINGATTRIBUTION" USING btree ("COMPONENT_ID", "VULNERABILITY_ID", "ANALYZERIDENTITY");

CREATE INDEX "FINDINGATTRIBUTION_PROJECT_ID_IDX" ON "FINDINGATTRIBUTION" USING btree ("PROJECT_ID");

CREATE INDEX "FINDINGATTRIBUTION_VULNERABILITY_ID_IDX" ON "FINDINGATTRIBUTION" USING btree ("VULNERABILITY_ID");

CREATE INDEX "LICENSEGROUP_LICENSE_LICENSEGROUP_ID_IDX" ON "LICENSEGROUP_LICENSE" USING btree ("LICENSEGROUP_ID");

CREATE INDEX "LICENSEGROUP_LICENSE_LICENSE_ID_IDX" ON "LICENSEGROUP_LICENSE" USING btree ("LICENSE_ID");

CREATE INDEX "LICENSEGROUP_NAME_IDX" ON "LICENSEGROUP" USING btree ("NAME");

CREATE UNIQUE INDEX "LICENSE_LICENSEID_IDX" ON "LICENSE" USING btree ("LICENSEID");

CREATE INDEX "LICENSE_NAME_IDX" ON "LICENSE" USING btree ("NAME");

CREATE INDEX "MAPPEDOIDCGROUP_GROUP_ID_IDX" ON "MAPPEDOIDCGROUP" USING btree ("GROUP_ID");

CREATE UNIQUE INDEX "NOTIFICATIONPUBLISHER_NAME_IDX" ON "NOTIFICATIONPUBLISHER" USING btree ("NAME");

CREATE UNIQUE INDEX "NOTIFICATIONRULE_NAME_IDX" ON "NOTIFICATIONRULE" USING btree ("NAME");

CREATE INDEX "NOTIFICATIONRULE_PROJECTS_NOTIFICATIONRULE_ID_IDX" ON "NOTIFICATIONRULE_PROJECTS" USING btree ("NOTIFICATIONRULE_ID");

CREATE INDEX "NOTIFICATIONRULE_PROJECTS_PROJECT_ID_IDX" ON "NOTIFICATIONRULE_PROJECTS" USING btree ("PROJECT_ID");

CREATE INDEX "NOTIFICATIONRULE_PUBLISHER_IDX" ON "NOTIFICATIONRULE" USING btree ("PUBLISHER");

CREATE UNIQUE INDEX "OIDCGROUP_NAME_IDX" ON "OIDCGROUP" USING btree ("NAME");

CREATE INDEX "PACKAGE_ARTIFACT_METADATA_PACKAGE_PURL_IDX" ON "PACKAGE_ARTIFACT_METADATA" USING btree ("PACKAGE_PURL");

CREATE INDEX "PACKAGE_ARTIFACT_METADATA_RESOLVED_AT_IDX" ON "PACKAGE_ARTIFACT_METADATA" USING btree ("RESOLVED_AT");

CREATE INDEX "PACKAGE_METADATA_RESOLVED_AT_IDX" ON "PACKAGE_METADATA" USING btree ("RESOLVED_AT");

CREATE INDEX "POLICYCONDITION_POLICY_ID_IDX" ON "POLICYCONDITION" USING btree ("POLICY_ID");

CREATE UNIQUE INDEX "POLICYVIOLATION_IDENTITY_IDX" ON "POLICYVIOLATION" USING btree ("COMPONENT_ID", "PROJECT_ID", "POLICYCONDITION_ID");

CREATE INDEX "POLICYVIOLATION_POLICYCONDITION_ID_IDX" ON "POLICYVIOLATION" USING btree ("POLICYCONDITION_ID");

CREATE INDEX "POLICYVIOLATION_PROJECT_IDX" ON "POLICYVIOLATION" USING btree ("PROJECT_ID");

CREATE INDEX "POLICY_NAME_IDX" ON "POLICY" USING btree ("NAME");

CREATE INDEX "POLICY_PROJECTS_POLICY_ID_IDX" ON "POLICY_PROJECTS" USING btree ("POLICY_ID");

CREATE INDEX "POLICY_PROJECTS_PROJECT_ID_IDX" ON "POLICY_PROJECTS" USING btree ("PROJECT_ID");

CREATE UNIQUE INDEX "PORTFOLIOMETRICS_GLOBAL_LAST_OCCURRENCE_IDX" ON "PORTFOLIOMETRICS_GLOBAL" USING btree ("LAST_OCCURRENCE");

CREATE INDEX "PROJECTMETRICS_PROJECT_ID_LAST_OCCURRENCE_DESC_IDX" ON ONLY "PROJECTMETRICS" USING btree ("PROJECT_ID", "LAST_OCCURRENCE" DESC);

CREATE INDEX "PROJECT_ACCESS_TEAMS_TEAM_IDX" ON "PROJECT_ACCESS_TEAMS" USING btree ("TEAM_ID");

CREATE INDEX "PROJECT_ACCESS_USERS_USER_IDX" ON "PROJECT_ACCESS_USERS" USING btree ("USER_ID");

CREATE INDEX "PROJECT_CLASSIFIER_IDX" ON "PROJECT" USING btree ("CLASSIFIER");

CREATE INDEX "PROJECT_COLLECTION_TAG_ID_IDX" ON "PROJECT" USING btree ("COLLECTION_TAG_ID") WHERE ("COLLECTION_TAG_ID" IS NOT NULL);

CREATE INDEX "PROJECT_CPE_IDX" ON "PROJECT" USING btree ("CPE");

CREATE INDEX "PROJECT_GROUP_IDX" ON "PROJECT" USING btree ("GROUP");

CREATE INDEX "PROJECT_INACTIVE_SINCE_IDX" ON "PROJECT" USING btree ("INACTIVE_SINCE");

CREATE UNIQUE INDEX "PROJECT_IS_LATEST_IDX" ON "PROJECT" USING btree ("NAME", "IS_LATEST") WHERE "IS_LATEST";

CREATE INDEX "PROJECT_LASTBOMIMPORT_FORMAT_IDX" ON "PROJECT" USING btree ("LAST_BOM_IMPORTED_FORMAT");

CREATE INDEX "PROJECT_LASTBOMIMPORT_IDX" ON "PROJECT" USING btree ("LAST_BOM_IMPORTED");

CREATE INDEX "PROJECT_LAST_RISKSCORE_IDX" ON "PROJECT" USING btree ("LAST_RISKSCORE");

CREATE UNIQUE INDEX "PROJECT_METADATA_PROJECT_ID_IDX" ON "PROJECT_METADATA" USING btree ("PROJECT_ID");

CREATE INDEX "PROJECT_NAME_IDX" ON "PROJECT" USING btree ("NAME");

CREATE UNIQUE INDEX "PROJECT_NAME_VERSION_IDX" ON "PROJECT" USING btree ("NAME", "VERSION") WHERE ("VERSION" IS NOT NULL);

CREATE UNIQUE INDEX "PROJECT_NAME_VERSION_NULL_IDX" ON "PROJECT" USING btree ("NAME") WHERE ("VERSION" IS NULL);

CREATE INDEX "PROJECT_PARENT_PROJECT_ID_IDX" ON "PROJECT" USING btree ("PARENT_PROJECT_ID");

CREATE INDEX "PROJECT_PURL_IDX" ON "PROJECT" USING btree ("PURL");

CREATE INDEX "PROJECT_SWID_TAGID_IDX" ON "PROJECT" USING btree ("SWIDTAGID");

CREATE INDEX "PROJECT_VERSION_IDX" ON "PROJECT" USING btree ("VERSION");

CREATE INDEX "REPOSITORY_UUID_IDX" ON "REPOSITORY" USING btree ("UUID");

CREATE INDEX "SERVICECOMPONENTS_VULNERABILITIES_SERVICECOMPONENT_ID_IDX" ON "SERVICECOMPONENTS_VULNERABILITIES" USING btree ("SERVICECOMPONENT_ID");

CREATE INDEX "SERVICECOMPONENTS_VULNERABILITIES_VULNERABILITY_ID_IDX" ON "SERVICECOMPONENTS_VULNERABILITIES" USING btree ("VULNERABILITY_ID");

CREATE INDEX "SERVICECOMPONENT_LAST_RISKSCORE_IDX" ON "SERVICECOMPONENT" USING btree ("LAST_RISKSCORE");

CREATE INDEX "SERVICECOMPONENT_PARENT_SERVICECOMPONENT_ID_IDX" ON "SERVICECOMPONENT" USING btree ("PARENT_SERVICECOMPONENT_ID");

CREATE INDEX "SERVICECOMPONENT_PROJECT_ID_IDX" ON "SERVICECOMPONENT" USING btree ("PROJECT_ID");

CREATE UNIQUE INDEX "TAG_NAME_IDX" ON "TAG" USING btree ("NAME");

CREATE INDEX "USERS_TEAMS_TEAM_IDX" ON "USERS_TEAMS" USING btree ("TEAM_ID");

CREATE INDEX "USER_SESSION_EXPIRES_AT_IDX" ON "USER_SESSION" USING btree ("EXPIRES_AT");

CREATE INDEX "USER_SESSION_USER_ID_IDX" ON "USER_SESSION" USING btree ("USER_ID");

CREATE UNIQUE INDEX "USER_USERNAME_IDX" ON "USER" USING btree ("USERNAME");

CREATE INDEX "VEX_PROJECT_ID_IDX" ON "VEX" USING btree ("PROJECT_ID");

CREATE INDEX "VIOLATIONANALYSISCOMMENT_VIOLATIONANALYSIS_ID_IDX" ON "VIOLATIONANALYSISCOMMENT" USING btree ("VIOLATIONANALYSIS_ID");

CREATE INDEX "VIOLATIONANALYSIS_COMPONENT_ID_IDX" ON "VIOLATIONANALYSIS" USING btree ("COMPONENT_ID");

CREATE INDEX "VIOLATIONANALYSIS_POLICYVIOLATION_ID_IDX" ON "VIOLATIONANALYSIS" USING btree ("POLICYVIOLATION_ID");

CREATE INDEX "VULNERABILITY_ALIAS_GROUP_IDX" ON "VULNERABILITY_ALIAS" USING btree ("GROUP_ID");

CREATE INDEX "VULNERABILITY_CREATED_IDX" ON "VULNERABILITY" USING btree ("CREATED");

CREATE INDEX "VULNERABILITY_POLICY_BUNDLE_ID_IDX" ON "VULNERABILITY_POLICY" USING btree ("VULNERABILITY_POLICY_BUNDLE_ID");

CREATE UNIQUE INDEX "VULNERABILITY_POLICY_BUNDLE_UUID_IDX" ON "VULNERABILITY_POLICY_BUNDLE" USING btree ("UUID");

CREATE UNIQUE INDEX "VULNERABILITY_POLICY_NAME_IDX" ON "VULNERABILITY_POLICY" USING btree ("NAME");

CREATE UNIQUE INDEX "VULNERABILITY_POLICY_UUID_IDX" ON "VULNERABILITY_POLICY" USING btree ("UUID");

CREATE INDEX "VULNERABILITY_PUBLISHED_IDX" ON "VULNERABILITY" USING btree ("PUBLISHED");

CREATE INDEX "VULNERABILITY_UPDATED_IDX" ON "VULNERABILITY" USING btree ("UPDATED");

CREATE INDEX "VULNERABLESOFTWARE_CPE23_VERSION_RANGE_IDX" ON "VULNERABLESOFTWARE" USING btree ("CPE23", "VERSIONENDEXCLUDING", "VERSIONENDINCLUDING", "VERSIONSTARTEXCLUDING", "VERSIONSTARTINCLUDING");

CREATE INDEX "VULNERABLESOFTWARE_CPE_PURL_PARTS_IDX" ON "VULNERABLESOFTWARE" USING btree ("PART", "VENDOR", "PRODUCT", "PURL_TYPE", "PURL_NAMESPACE", "PURL_NAME");

CREATE INDEX "VULNERABLESOFTWARE_PURL_TYPE_NS_NAME_IDX" ON "VULNERABLESOFTWARE" USING btree ("PURL_TYPE", "PURL_NAMESPACE", "PURL_NAME");

CREATE INDEX "VULNERABLESOFTWARE_PURL_VERSION_RANGE_IDX" ON "VULNERABLESOFTWARE" USING btree ("PURL", "VERSIONENDEXCLUDING", "VERSIONENDINCLUDING", "VERSIONSTARTEXCLUDING", "VERSIONSTARTINCLUDING");

CREATE INDEX "VULNERABLESOFTWARE_VULNERABILITIES_VULNERABILITY_ID_IDX" ON "VULNERABLESOFTWARE_VULNERABILITIES" USING btree ("VULNERABILITY_ID");

CREATE INDEX "VULNERABLESOFTWARE_VULNERABILITIES_VULNERABLESOFTWARE_ID_IDX" ON "VULNERABLESOFTWARE_VULNERABILITIES" USING btree ("VULNERABLESOFTWARE_ID");

CREATE INDEX "VULN_ALIAS_ASSERTION_ALIAS_IDX" ON "VULNERABILITY_ALIAS_ASSERTION" USING btree ("ALIAS_SOURCE", "ALIAS_ID");

CREATE INDEX "VULN_ALIAS_ASSERTION_VULN_IDX" ON "VULNERABILITY_ALIAS_ASSERTION" USING btree ("VULN_SOURCE", "VULN_ID");

CREATE STATISTICS "COMPONENT_PURL_LOWER_STATS" ON lower("PURL"::text) FROM "COMPONENT";

CREATE TRIGGER trigger_prevent_direct_project_access_users_writes BEFORE INSERT OR DELETE OR UPDATE ON "PROJECT_ACCESS_USERS" FOR EACH STATEMENT EXECUTE FUNCTION prevent_direct_project_access_users_writes();

CREATE TRIGGER trigger_project_access_users_on_pat_delete AFTER DELETE ON "PROJECT_ACCESS_TEAMS" REFERENCING OLD TABLE AS old_table FOR EACH STATEMENT EXECUTE FUNCTION project_access_users_on_pat_delete();

CREATE TRIGGER trigger_project_access_users_on_pat_insert AFTER INSERT ON "PROJECT_ACCESS_TEAMS" REFERENCING NEW TABLE AS new_table FOR EACH STATEMENT EXECUTE FUNCTION project_access_users_on_pat_insert();

CREATE TRIGGER trigger_project_access_users_on_pat_update AFTER UPDATE ON "PROJECT_ACCESS_TEAMS" REFERENCING OLD TABLE AS old_table NEW TABLE AS new_table FOR EACH STATEMENT EXECUTE FUNCTION project_access_users_on_pat_update();

CREATE TRIGGER trigger_project_access_users_on_ut_delete AFTER DELETE ON "USERS_TEAMS" REFERENCING OLD TABLE AS old_table FOR EACH STATEMENT EXECUTE FUNCTION project_access_users_on_ut_delete();

CREATE TRIGGER trigger_project_access_users_on_ut_insert AFTER INSERT ON "USERS_TEAMS" REFERENCING NEW TABLE AS new_table FOR EACH STATEMENT EXECUTE FUNCTION project_access_users_on_ut_insert();

CREATE TRIGGER trigger_project_access_users_on_ut_update AFTER UPDATE ON "USERS_TEAMS" REFERENCING OLD TABLE AS old_table NEW TABLE AS new_table FOR EACH STATEMENT EXECUTE FUNCTION project_access_users_on_ut_update();

CREATE TRIGGER trigger_project_hierarchy_maintenance_on_project_delete AFTER DELETE ON "PROJECT" REFERENCING OLD TABLE AS old_table FOR EACH STATEMENT EXECUTE FUNCTION project_hierarchy_maintenance_on_project_delete();

CREATE TRIGGER trigger_project_hierarchy_maintenance_on_project_insert AFTER INSERT ON "PROJECT" FOR EACH ROW EXECUTE FUNCTION project_hierarchy_maintenance_on_project_insert();

CREATE TRIGGER trigger_project_hierarchy_maintenance_on_project_update AFTER UPDATE OF "PARENT_PROJECT_ID" ON "PROJECT" FOR EACH ROW WHEN ((old."PARENT_PROJECT_ID" IS DISTINCT FROM new."PARENT_PROJECT_ID")) EXECUTE FUNCTION project_hierarchy_maintenance_on_project_update();

ALTER TABLE ONLY "AFFECTEDVERSIONATTRIBUTION"
    ADD CONSTRAINT "AFFECTEDVERSIONATTRIBUTION_VULNERABILITY_FK" FOREIGN KEY ("VULNERABILITY") REFERENCES "VULNERABILITY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "AFFECTEDVERSIONATTRIBUTION"
    ADD CONSTRAINT "AFFECTEDVERSIONATTRIBUTION_VULNERABLESOFTWARE_FK" FOREIGN KEY ("VULNERABLE_SOFTWARE") REFERENCES "VULNERABLESOFTWARE"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "ANALYSISCOMMENT"
    ADD CONSTRAINT "ANALYSISCOMMENT_ANALYSIS_FK" FOREIGN KEY ("ANALYSIS_ID") REFERENCES "ANALYSIS"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "ANALYSIS"
    ADD CONSTRAINT "ANALYSIS_COMPONENT_FK" FOREIGN KEY ("COMPONENT_ID") REFERENCES "COMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "ANALYSIS"
    ADD CONSTRAINT "ANALYSIS_PROJECT_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "ANALYSIS"
    ADD CONSTRAINT "ANALYSIS_VULNERABILITY_FK" FOREIGN KEY ("VULNERABILITY_ID") REFERENCES "VULNERABILITY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "ANALYSIS"
    ADD CONSTRAINT "ANALYSIS_VULNERABILITY_POLICY_ID_FK" FOREIGN KEY ("VULNERABILITY_POLICY_ID") REFERENCES "VULNERABILITY_POLICY"("ID");

ALTER TABLE ONLY "APIKEYS_TEAMS"
    ADD CONSTRAINT "APIKEYS_TEAMS_APIKEY_FK" FOREIGN KEY ("APIKEY_ID") REFERENCES "APIKEY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "APIKEYS_TEAMS"
    ADD CONSTRAINT "APIKEYS_TEAMS_TEAM_FK" FOREIGN KEY ("TEAM_ID") REFERENCES "TEAM"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "BOM"
    ADD CONSTRAINT "BOM_PROJECT_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "COMPONENTS_VULNERABILITIES"
    ADD CONSTRAINT "COMPONENTS_VULNERABILITIES_COMPONENT_FK" FOREIGN KEY ("COMPONENT_ID") REFERENCES "COMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "COMPONENTS_VULNERABILITIES"
    ADD CONSTRAINT "COMPONENTS_VULNERABILITIES_VULNERABILITY_FK" FOREIGN KEY ("VULNERABILITY_ID") REFERENCES "VULNERABILITY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "COMPONENT"
    ADD CONSTRAINT "COMPONENT_COMPONENT_FK" FOREIGN KEY ("PARENT_COMPONENT_ID") REFERENCES "COMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "COMPONENT"
    ADD CONSTRAINT "COMPONENT_LICENSE_FK" FOREIGN KEY ("LICENSE_ID") REFERENCES "LICENSE"("ID") DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "COMPONENT_OCCURRENCE"
    ADD CONSTRAINT "COMPONENT_OCCURRENCE_COMPONENT_FK" FOREIGN KEY ("COMPONENT_ID") REFERENCES "COMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "COMPONENT"
    ADD CONSTRAINT "COMPONENT_PROJECT_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "COMPONENT_PROPERTY"
    ADD CONSTRAINT "COMPONENT_PROPERTY_COMPONENT_ID_FK" FOREIGN KEY ("COMPONENT_ID") REFERENCES "COMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE "DEPENDENCYMETRICS"
    ADD CONSTRAINT "DEPENDENCYMETRICS_COMPONENT_FK" FOREIGN KEY ("COMPONENT_ID") REFERENCES "COMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE "DEPENDENCYMETRICS"
    ADD CONSTRAINT "DEPENDENCYMETRICS_PROJECT_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "FINDINGATTRIBUTION"
    ADD CONSTRAINT "FINDINGATTRIBUTION_COMPONENT_FK" FOREIGN KEY ("COMPONENT_ID") REFERENCES "COMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "FINDINGATTRIBUTION"
    ADD CONSTRAINT "FINDINGATTRIBUTION_PROJECT_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "FINDINGATTRIBUTION"
    ADD CONSTRAINT "FINDINGATTRIBUTION_VULNERABILITY_FK" FOREIGN KEY ("VULNERABILITY_ID") REFERENCES "VULNERABILITY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "LICENSEGROUP_LICENSE"
    ADD CONSTRAINT "LICENSEGROUP_LICENSE_LICENSEGROUP_FK" FOREIGN KEY ("LICENSEGROUP_ID") REFERENCES "LICENSEGROUP"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "LICENSEGROUP_LICENSE"
    ADD CONSTRAINT "LICENSEGROUP_LICENSE_LICENSE_FK" FOREIGN KEY ("LICENSE_ID") REFERENCES "LICENSE"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "MAPPEDLDAPGROUP"
    ADD CONSTRAINT "MAPPEDLDAPGROUP_TEAM_FK" FOREIGN KEY ("TEAM_ID") REFERENCES "TEAM"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "MAPPEDOIDCGROUP"
    ADD CONSTRAINT "MAPPEDOIDCGROUP_OIDCGROUP_FK" FOREIGN KEY ("GROUP_ID") REFERENCES "OIDCGROUP"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "MAPPEDOIDCGROUP"
    ADD CONSTRAINT "MAPPEDOIDCGROUP_TEAM_FK" FOREIGN KEY ("TEAM_ID") REFERENCES "TEAM"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "NOTIFICATIONRULE"
    ADD CONSTRAINT "NOTIFICATIONRULE_NOTIFICATIONPUBLISHER_FK" FOREIGN KEY ("PUBLISHER") REFERENCES "NOTIFICATIONPUBLISHER"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "NOTIFICATIONRULE_PROJECTS"
    ADD CONSTRAINT "NOTIFICATIONRULE_PROJECTS_NOTIFICATIONRULE_FK" FOREIGN KEY ("NOTIFICATIONRULE_ID") REFERENCES "NOTIFICATIONRULE"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "NOTIFICATIONRULE_PROJECTS"
    ADD CONSTRAINT "NOTIFICATIONRULE_PROJECTS_PROJECT_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "NOTIFICATIONRULE_TAGS"
    ADD CONSTRAINT "NOTIFICATIONRULE_TAGS_NOTIFICATIONRULE_FK" FOREIGN KEY ("NOTIFICATIONRULE_ID") REFERENCES "NOTIFICATIONRULE"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "NOTIFICATIONRULE_TAGS"
    ADD CONSTRAINT "NOTIFICATIONRULE_TAGS_TAG_FK" FOREIGN KEY ("TAG_ID") REFERENCES "TAG"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "NOTIFICATIONRULE_TEAMS"
    ADD CONSTRAINT "NOTIFICATIONRULE_TEAMS_NOTIFICATIONRULE_FK" FOREIGN KEY ("NOTIFICATIONRULE_ID") REFERENCES "NOTIFICATIONRULE"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "NOTIFICATIONRULE_TEAMS"
    ADD CONSTRAINT "NOTIFICATIONRULE_TEAMS_TEAM_FK" FOREIGN KEY ("TEAM_ID") REFERENCES "TEAM"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "PACKAGE_ARTIFACT_METADATA"
    ADD CONSTRAINT "PACKAGE_ARTIFACT_METADATA_PACKAGE_PURL_FK" FOREIGN KEY ("PACKAGE_PURL") REFERENCES "PACKAGE_METADATA"("PURL") ON DELETE CASCADE;

ALTER TABLE ONLY "POLICYCONDITION"
    ADD CONSTRAINT "POLICYCONDITION_POLICY_FK" FOREIGN KEY ("POLICY_ID") REFERENCES "POLICY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "POLICYVIOLATION"
    ADD CONSTRAINT "POLICYVIOLATION_COMPONENT_FK" FOREIGN KEY ("COMPONENT_ID") REFERENCES "COMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "POLICYVIOLATION"
    ADD CONSTRAINT "POLICYVIOLATION_POLICYCONDITION_FK" FOREIGN KEY ("POLICYCONDITION_ID") REFERENCES "POLICYCONDITION"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "POLICYVIOLATION"
    ADD CONSTRAINT "POLICYVIOLATION_PROJECT_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "POLICY_PROJECTS"
    ADD CONSTRAINT "POLICY_PROJECTS_POLICY_FK" FOREIGN KEY ("POLICY_ID") REFERENCES "POLICY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "POLICY_PROJECTS"
    ADD CONSTRAINT "POLICY_PROJECTS_PROJECT_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "POLICY_TAGS"
    ADD CONSTRAINT "POLICY_TAGS_POLICY_FK" FOREIGN KEY ("POLICY_ID") REFERENCES "POLICY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "POLICY_TAGS"
    ADD CONSTRAINT "POLICY_TAGS_TAG_FK" FOREIGN KEY ("TAG_ID") REFERENCES "TAG"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE "PROJECTMETRICS"
    ADD CONSTRAINT "PROJECTMETRICS_PROJECT_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "PROJECTS_TAGS"
    ADD CONSTRAINT "PROJECTS_TAGS_PROJECT_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "PROJECTS_TAGS"
    ADD CONSTRAINT "PROJECTS_TAGS_TAG_FK" FOREIGN KEY ("TAG_ID") REFERENCES "TAG"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "PROJECT_ACCESS_TEAMS"
    ADD CONSTRAINT "PROJECT_ACCESS_TEAMS_PROJECT_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "PROJECT_ACCESS_TEAMS"
    ADD CONSTRAINT "PROJECT_ACCESS_TEAMS_TEAM_FK" FOREIGN KEY ("TEAM_ID") REFERENCES "TEAM"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "PROJECT_ACCESS_USERS"
    ADD CONSTRAINT "PROJECT_ACCESS_USERS_PROJECT_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE;

ALTER TABLE ONLY "PROJECT_ACCESS_USERS"
    ADD CONSTRAINT "PROJECT_ACCESS_USERS_USER_FK" FOREIGN KEY ("USER_ID") REFERENCES "USER"("ID") ON DELETE CASCADE;

ALTER TABLE ONLY "PROJECT"
    ADD CONSTRAINT "PROJECT_COLLECTION_TAG_FK" FOREIGN KEY ("COLLECTION_TAG_ID") REFERENCES "TAG"("ID") ON DELETE RESTRICT;

ALTER TABLE ONLY "PROJECT_HIERARCHY"
    ADD CONSTRAINT "PROJECT_HIERARCHY_CHILD_PROJECT_FK" FOREIGN KEY ("CHILD_PROJECT_ID") REFERENCES "PROJECT"("ID") DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "PROJECT_HIERARCHY"
    ADD CONSTRAINT "PROJECT_HIERARCHY_PARENT_PROJECT_FK" FOREIGN KEY ("PARENT_PROJECT_ID") REFERENCES "PROJECT"("ID") DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "PROJECT_METADATA"
    ADD CONSTRAINT "PROJECT_METADATA_PROJECT_ID_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "PROJECT"
    ADD CONSTRAINT "PROJECT_PROJECT_FK" FOREIGN KEY ("PARENT_PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "PROJECT_PROPERTY"
    ADD CONSTRAINT "PROJECT_PROPERTY_PROJECT_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "SERVICECOMPONENTS_VULNERABILITIES"
    ADD CONSTRAINT "SERVICECOMPONENTS_VULNERABILITIES_SERVICECOMPONENT_FK" FOREIGN KEY ("SERVICECOMPONENT_ID") REFERENCES "SERVICECOMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "SERVICECOMPONENTS_VULNERABILITIES"
    ADD CONSTRAINT "SERVICECOMPONENTS_VULNERABILITIES_VULNERABILITY_FK" FOREIGN KEY ("VULNERABILITY_ID") REFERENCES "VULNERABILITY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "SERVICECOMPONENT"
    ADD CONSTRAINT "SERVICECOMPONENT_PROJECT_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "SERVICECOMPONENT"
    ADD CONSTRAINT "SERVICECOMPONENT_SERVICECOMPONENT_FK" FOREIGN KEY ("PARENT_SERVICECOMPONENT_ID") REFERENCES "SERVICECOMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "TEAMS_PERMISSIONS"
    ADD CONSTRAINT "TEAMS_PERMISSIONS_PERMISSION_FK" FOREIGN KEY ("PERMISSION_ID") REFERENCES "PERMISSION"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "TEAMS_PERMISSIONS"
    ADD CONSTRAINT "TEAMS_PERMISSIONS_TEAM_FK" FOREIGN KEY ("TEAM_ID") REFERENCES "TEAM"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "USERS_PERMISSIONS"
    ADD CONSTRAINT "USERS_PERMISSIONS_PERMISSION_FK" FOREIGN KEY ("PERMISSION_ID") REFERENCES "PERMISSION"("ID") ON DELETE CASCADE;

ALTER TABLE ONLY "USERS_PERMISSIONS"
    ADD CONSTRAINT "USERS_PERMISSIONS_USER_FK" FOREIGN KEY ("USER_ID") REFERENCES "USER"("ID") ON DELETE CASCADE;

ALTER TABLE ONLY "USERS_TEAMS"
    ADD CONSTRAINT "USERS_TEAMS_TEAM_FK" FOREIGN KEY ("TEAM_ID") REFERENCES "TEAM"("ID") ON DELETE CASCADE;

ALTER TABLE ONLY "USERS_TEAMS"
    ADD CONSTRAINT "USERS_TEAMS_USER_FK" FOREIGN KEY ("USER_ID") REFERENCES "USER"("ID") ON DELETE CASCADE;

ALTER TABLE ONLY "USER_SESSION"
    ADD CONSTRAINT "USER_SESSION_USER_FK" FOREIGN KEY ("USER_ID") REFERENCES "USER"("ID") ON DELETE CASCADE;

ALTER TABLE ONLY "VEX"
    ADD CONSTRAINT "VEX_PROJECT_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "VIOLATIONANALYSISCOMMENT"
    ADD CONSTRAINT "VIOLATIONANALYSISCOMMENT_VIOLATIONANALYSIS_FK" FOREIGN KEY ("VIOLATIONANALYSIS_ID") REFERENCES "VIOLATIONANALYSIS"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "VIOLATIONANALYSIS"
    ADD CONSTRAINT "VIOLATIONANALYSIS_COMPONENT_FK" FOREIGN KEY ("COMPONENT_ID") REFERENCES "COMPONENT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "VIOLATIONANALYSIS"
    ADD CONSTRAINT "VIOLATIONANALYSIS_POLICYVIOLATION_FK" FOREIGN KEY ("POLICYVIOLATION_ID") REFERENCES "POLICYVIOLATION"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "VIOLATIONANALYSIS"
    ADD CONSTRAINT "VIOLATIONANALYSIS_PROJECT_FK" FOREIGN KEY ("PROJECT_ID") REFERENCES "PROJECT"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "VULNERABILITIES_TAGS"
    ADD CONSTRAINT "VULNERABILITIES_TAGS_TAG_FK" FOREIGN KEY ("TAG_ID") REFERENCES "TAG"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "VULNERABILITIES_TAGS"
    ADD CONSTRAINT "VULNERABILITIES_TAGS_VULNERABILITY_FK" FOREIGN KEY ("VULNERABILITY_ID") REFERENCES "VULNERABILITY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "VULNERABILITY_POLICY"
    ADD CONSTRAINT "VULNERABILITY_POLICY_BUNDLE_FK" FOREIGN KEY ("VULNERABILITY_POLICY_BUNDLE_ID") REFERENCES "VULNERABILITY_POLICY_BUNDLE"("ID");

ALTER TABLE ONLY "VULNERABLESOFTWARE_VULNERABILITIES"
    ADD CONSTRAINT "VULNERABLESOFTWARE_VULNERABILITIES_VULNERABILITY_FK" FOREIGN KEY ("VULNERABILITY_ID") REFERENCES "VULNERABILITY"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY "VULNERABLESOFTWARE_VULNERABILITIES"
    ADD CONSTRAINT "VULNERABLESOFTWARE_VULNERABILITIES_VULNERABLESOFTWARE_FK" FOREIGN KEY ("VULNERABLESOFTWARE_ID") REFERENCES "VULNERABLESOFTWARE"("ID") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;

-- Populate materialized view so subsequent REFRESH MATERIALIZED VIEW CONCURRENTLY can succeed.
REFRESH MATERIALIZED VIEW "PORTFOLIOMETRICS_GLOBAL";
