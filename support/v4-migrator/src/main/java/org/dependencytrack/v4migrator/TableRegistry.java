/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.v4migrator;

import java.util.List;

/**
 * Ordered list of tables the migrator handles end-to-end. Order respects v5 FK dependencies
 * per pipeline design §9.
 */
public final class TableRegistry {

    private static final TableMigration LICENSE = new TableMigration(
        "LICENSE",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_license (
            "ID"               bigint NOT NULL
          , "COMMENT"          text
          , "ISCUSTOMLICENSE"  boolean
          , "ISDEPRECATED"     boolean NOT NULL
          , "FSFLIBRE"         boolean
          , "HEADER"           text
          , "LICENSEID"        varchar(255)
          , "ISOSIAPPROVED"    boolean NOT NULL
          , "NAME"             varchar(255) NOT NULL
          , "SEEALSO"          bytea
          , "TEMPLATE"         text
          , "TEXT"             text
          , "UUID"             varchar(36) NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "COMMENT"
             , "ISCUSTOMLICENSE"
             , "ISDEPRECATED"
             , "FSFLIBRE"
             , "HEADER"
             , "LICENSEID"
             , "ISOSIAPPROVED"
             , "NAME"
             , "SEEALSO"
             , "TEMPLATE"
             , "TEXT"
             , "UUID"
          FROM "%s"."LICENSE"
         ORDER BY "ID"
        """,
        List.of("ID", "COMMENT", "ISCUSTOMLICENSE", "ISDEPRECATED", "FSFLIBRE",
            "HEADER", "LICENSEID", "ISOSIAPPROVED", "NAME", "SEEALSO",
            "TEMPLATE", "TEXT", "UUID"),
        """
        -- Capture rows with malformed UUIDs into the probe so they surface in verify,
        -- and exclude them from the target tier (the ::uuid cast below would otherwise fail).
        INSERT INTO "%1$s".probe_invalid_uuids (table_name, orig_id, bad_uuid)
        SELECT 'LICENSE', "ID", "UUID"
          FROM "%1$s".src_license
         WHERE "UUID" !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ON CONFLICT DO NOTHING;

        DROP TABLE IF EXISTS "%1$s".tgt_license;
        CREATE UNLOGGED TABLE "%1$s".tgt_license (
            "ID"               bigint NOT NULL
          , "COMMENT"          text
          , "ISCUSTOMLICENSE"  boolean
          , "ISDEPRECATED"     boolean NOT NULL
          , "FSFLIBRE"         boolean
          , "HEADER"           text
          , "LICENSEID"        varchar(255)
          , "ISOSIAPPROVED"    boolean NOT NULL
          , "NAME"             varchar(255) NOT NULL
          , "SEEALSO"          bytea
          , "TEMPLATE"         text
          , "TEXT"             text
          , "UUID"             uuid NOT NULL
        );
        INSERT INTO "%1$s".tgt_license
        SELECT "ID"
             , "COMMENT"
             , "ISCUSTOMLICENSE"
             , "ISDEPRECATED"
             , "FSFLIBRE"
             , "HEADER"
             , "LICENSEID"
             , "ISOSIAPPROVED"
             , "NAME"
             , "SEEALSO"
             , "TEMPLATE"
             , "TEXT"
             , "UUID"::uuid
          FROM "%1$s".src_license
         WHERE "UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        """,
        """
        INSERT INTO "LICENSE" (
            "ID"
          , "COMMENT"
          , "ISCUSTOMLICENSE"
          , "ISDEPRECATED"
          , "FSFLIBRE"
          , "HEADER"
          , "LICENSEID"
          , "ISOSIAPPROVED"
          , "NAME"
          , "SEEALSO"
          , "TEMPLATE"
          , "TEXT"
          , "UUID"
        )
        SELECT "ID"
             , "COMMENT"
             , "ISCUSTOMLICENSE"
             , "ISDEPRECATED"
             , "FSFLIBRE"
             , "HEADER"
             , "LICENSEID"
             , "ISOSIAPPROVED"
             , "NAME"
             , "SEEALSO"
             , "TEMPLATE"
             , "TEXT"
             , "UUID"
          FROM "%1$s".tgt_license
        """
    );

    /**
     * 1:1 migration of {@code TEAM} with dedup-by-NAME (canonical = MIN(ID)) per
     * schema-changes §4. Also produces a {@code team_canonical_id_map} that downstream
     * transforms (USERS_TEAMS, eventually NOTIFICATIONRULE_TEAMS, etc.) use to rewrite
     * v4 TEAM_IDs to the canonical value.
     */
    private static final TableMigration TEAM = new TableMigration(
        "TEAM",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_team (
            "ID"   bigint NOT NULL
          , "NAME" varchar(255) NOT NULL
          , "UUID" varchar(36) NOT NULL
        )
        """,
        """
        SELECT "ID", "NAME", "UUID"
          FROM "%s"."TEAM"
         ORDER BY "ID"
        """,
        List.of("ID", "NAME", "UUID"),
        """
        DROP TABLE IF EXISTS "%1$s".team_canonical_id_map;
        CREATE UNLOGGED TABLE "%1$s".team_canonical_id_map AS
        SELECT t."ID" AS orig_id, c.canonical_id
          FROM "%1$s".src_team t
          JOIN (
              SELECT "NAME", MIN("ID") AS canonical_id
                FROM "%1$s".src_team
               GROUP BY "NAME"
          ) c ON c."NAME" = t."NAME";
        ALTER TABLE "%1$s".team_canonical_id_map ADD PRIMARY KEY (orig_id);

        DROP TABLE IF EXISTS "%1$s".tgt_team;
        CREATE UNLOGGED TABLE "%1$s".tgt_team (
            "ID"   bigint NOT NULL PRIMARY KEY
          , "NAME" varchar(255) NOT NULL
          , "UUID" varchar(36) NOT NULL
        );
        INSERT INTO "%1$s".tgt_team
        SELECT "ID", "NAME", "UUID"
          FROM "%1$s".src_team
         WHERE "ID" IN (SELECT canonical_id FROM "%1$s".team_canonical_id_map)
        """,
        """
        INSERT INTO "TEAM" ("ID", "NAME", "UUID")
        SELECT "ID", "NAME", "UUID" FROM "%1$s".tgt_team
        """
    );

    /**
     * 1:1 migration of {@code TAG} with dedup-by-NAME (canonical = MIN(ID)) per
     * schema-changes §4. v4 already enforces UNIQUE(NAME) so the dedup is a no-op by
     * construction; the {@code tag_canonical_id_map} is still produced for downstream
     * join-table transforms (NOTIFICATIONRULE_TAGS, POLICY_TAGS, PROJECTS_TAGS,
     * VULNERABILITIES_TAGS) and PROJECT.COLLECTION_TAG rewrites.
     */
    private static final TableMigration TAG = new TableMigration(
        "TAG",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_tag (
            "ID"   bigint NOT NULL
          , "NAME" varchar(255) NOT NULL
        )
        """,
        """
        SELECT "ID", "NAME"
          FROM "%s"."TAG"
         ORDER BY "ID"
        """,
        List.of("ID", "NAME"),
        """
        DROP TABLE IF EXISTS "%1$s".tag_canonical_id_map;
        CREATE UNLOGGED TABLE "%1$s".tag_canonical_id_map AS
        SELECT t."ID" AS orig_id, c.canonical_id
          FROM "%1$s".src_tag t
          JOIN (
              SELECT "NAME", MIN("ID") AS canonical_id
                FROM "%1$s".src_tag
               GROUP BY "NAME"
          ) c ON c."NAME" = t."NAME";
        ALTER TABLE "%1$s".tag_canonical_id_map ADD PRIMARY KEY (orig_id);

        DROP TABLE IF EXISTS "%1$s".tgt_tag;
        CREATE UNLOGGED TABLE "%1$s".tgt_tag (
            "ID"   bigint NOT NULL PRIMARY KEY
          , "NAME" varchar(255) NOT NULL
        );
        INSERT INTO "%1$s".tgt_tag
        SELECT "ID", "NAME"
          FROM "%1$s".src_tag
         WHERE "ID" IN (SELECT canonical_id FROM "%1$s".tag_canonical_id_map)
        """,
        """
        INSERT INTO "TAG" ("ID", "NAME")
        SELECT "ID", "NAME" FROM "%1$s".tgt_tag
        """
    );

    // Source-only legacy user tables. No transform / load: they feed USER consolidation.

    private static final TableMigration LDAPUSER = new TableMigration(
        "LDAPUSER",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_ldapuser (
            "ID"       bigint NOT NULL
          , "USERNAME" varchar(255)
          , "DN"       varchar(1024) NOT NULL
          , "EMAIL"    varchar(255)
        )
        """,
        """
        SELECT "ID"
             , "USERNAME"
             , "DN"
             , "EMAIL"
          FROM "%s"."LDAPUSER"
         ORDER BY "ID"
        """,
        List.of("ID", "USERNAME", "DN", "EMAIL"),
        null,
        null
    );

    private static final TableMigration MANAGEDUSER = new TableMigration(
        "MANAGEDUSER",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_manageduser (
            "ID"                     bigint NOT NULL
          , "USERNAME"               varchar(255)
          , "PASSWORD"               varchar(255) NOT NULL
          , "FULLNAME"               varchar(255)
          , "EMAIL"                  varchar(255)
          , "FORCE_PASSWORD_CHANGE"  boolean NOT NULL
          , "LAST_PASSWORD_CHANGE"   timestamptz NOT NULL
          , "NON_EXPIRY_PASSWORD"    boolean NOT NULL
          , "SUSPENDED"              boolean NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "USERNAME"
             , "PASSWORD"
             , "FULLNAME"
             , "EMAIL"
             , "FORCE_PASSWORD_CHANGE"
             , "LAST_PASSWORD_CHANGE"
             , "NON_EXPIRY_PASSWORD"
             , "SUSPENDED"
          FROM "%s"."MANAGEDUSER"
         ORDER BY "ID"
        """,
        List.of("ID", "USERNAME", "PASSWORD", "FULLNAME", "EMAIL",
            "FORCE_PASSWORD_CHANGE", "LAST_PASSWORD_CHANGE",
            "NON_EXPIRY_PASSWORD", "SUSPENDED"),
        null,
        null
    );

    private static final TableMigration OIDCUSER = new TableMigration(
        "OIDCUSER",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_oidcuser (
            "ID"                  bigint NOT NULL
          , "USERNAME"            varchar(255) NOT NULL
          , "SUBJECT_IDENTIFIER"  varchar(255)
          , "EMAIL"               varchar(255)
        )
        """,
        """
        SELECT "ID"
             , "USERNAME"
             , "SUBJECT_IDENTIFIER"
             , "EMAIL"
          FROM "%s"."OIDCUSER"
         ORDER BY "ID"
        """,
        List.of("ID", "USERNAME", "SUBJECT_IDENTIFIER", "EMAIL"),
        null,
        null
    );

    private static final TableMigration LDAPUSERS_TEAMS = new TableMigration(
        "LDAPUSERS_TEAMS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_ldapusers_teams (
            "TEAM_ID"     bigint NOT NULL
          , "LDAPUSER_ID" bigint NOT NULL
        )
        """,
        """
        SELECT "TEAM_ID", "LDAPUSER_ID"
          FROM "%s"."LDAPUSERS_TEAMS"
        """,
        List.of("TEAM_ID", "LDAPUSER_ID"),
        null,
        null
    );

    private static final TableMigration MANAGEDUSERS_TEAMS = new TableMigration(
        "MANAGEDUSERS_TEAMS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_managedusers_teams (
            "TEAM_ID"        bigint NOT NULL
          , "MANAGEDUSER_ID" bigint NOT NULL
        )
        """,
        """
        SELECT "TEAM_ID", "MANAGEDUSER_ID"
          FROM "%s"."MANAGEDUSERS_TEAMS"
        """,
        List.of("TEAM_ID", "MANAGEDUSER_ID"),
        null,
        null
    );

    private static final TableMigration OIDCUSERS_TEAMS = new TableMigration(
        "OIDCUSERS_TEAMS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_oidcusers_teams (
            "TEAM_ID"        bigint NOT NULL
          , "OIDCUSERS_ID"   bigint NOT NULL
        )
        """,
        """
        SELECT "TEAM_ID", "OIDCUSERS_ID"
          FROM "%s"."OIDCUSERS_TEAMS"
        """,
        List.of("TEAM_ID", "OIDCUSERS_ID"),
        null,
        null
    );

    /**
     * Derived USER consolidation per pipeline §7.1 and schema-changes §7.1. v4 user rows with
     * {@code USERNAME IS NULL} are skipped silently. Username conflicts across LDAP/OIDC vs
     * already-inserted users get the {@code -CONFLICT-LDAP} / {@code -CONFLICT-OIDC} suffix.
     */
    private static final TableMigration USER_CONSOLIDATED = new TableMigration(
        "USER",
        null, null, null,
        """
        -- Record v4 user rows we are about to drop because of NULL USERNAME.
        INSERT INTO "%1$s".probe_skipped_users (table_name, orig_id, reason)
        SELECT 'LDAPUSER', "ID", 'USERNAME IS NULL' FROM "%1$s".src_ldapuser WHERE "USERNAME" IS NULL
        ON CONFLICT DO NOTHING;
        INSERT INTO "%1$s".probe_skipped_users (table_name, orig_id, reason)
        SELECT 'MANAGEDUSER', "ID", 'USERNAME IS NULL' FROM "%1$s".src_manageduser WHERE "USERNAME" IS NULL
        ON CONFLICT DO NOTHING;

        DROP TABLE IF EXISTS "%1$s".tgt_user;
        CREATE UNLOGGED TABLE "%1$s".tgt_user (
            "ID"                      bigserial PRIMARY KEY
          , "TYPE"                    text NOT NULL
          , "USERNAME"                varchar(255) NOT NULL UNIQUE
          , "EMAIL"                   varchar(255)
          , "PASSWORD"                varchar(255)
          , "FULLNAME"                varchar(255)
          , "FORCE_PASSWORD_CHANGE"   boolean
          , "LAST_PASSWORD_CHANGE"    timestamptz
          , "NON_EXPIRY_PASSWORD"     boolean
          , "SUSPENDED"               boolean
          , "DN"                      varchar(1024)
          , "SUBJECT_IDENTIFIER"      varchar(255)
            -- Bookkeeping: original v4 id + source type, used by USERS_TEAMS lookup.
          , "ORIG_ID"                 bigint NOT NULL
          , "ORIG_TYPE"               text NOT NULL
          , UNIQUE ("ORIG_ID", "ORIG_TYPE")
        );

        -- 1) MANAGED users (USERNAME guaranteed non-null after pre-filter).
        INSERT INTO "%1$s".tgt_user (
            "TYPE"
          , "USERNAME"
          , "EMAIL"
          , "PASSWORD"
          , "FULLNAME"
          , "FORCE_PASSWORD_CHANGE"
          , "LAST_PASSWORD_CHANGE"
          , "NON_EXPIRY_PASSWORD"
          , "SUSPENDED"
          , "ORIG_ID"
          , "ORIG_TYPE"
        )
        SELECT 'MANAGED'
             , "USERNAME"
             , "EMAIL"
             , "PASSWORD"
             , "FULLNAME"
             , "FORCE_PASSWORD_CHANGE"
             , "LAST_PASSWORD_CHANGE"
             , "NON_EXPIRY_PASSWORD"
             , "SUSPENDED"
             , "ID"
             , 'MANAGED'
          FROM "%1$s".src_manageduser
         WHERE "USERNAME" IS NOT NULL
        ON CONFLICT ("USERNAME") DO NOTHING;

        -- 2) LDAP users. First try the natural USERNAME; conflicts go through the suffix retry.
        WITH inserted AS (
            INSERT INTO "%1$s".tgt_user (
                "TYPE"
              , "USERNAME"
              , "EMAIL"
              , "DN"
              , "ORIG_ID"
              , "ORIG_TYPE"
            )
            SELECT 'LDAP'
                 , "USERNAME"
                 , "EMAIL"
                 , "DN"
                 , "ID"
                 , 'LDAP'
              FROM "%1$s".src_ldapuser
             WHERE "USERNAME" IS NOT NULL
            ON CONFLICT ("USERNAME") DO NOTHING
            RETURNING "ORIG_ID"
        )
        INSERT INTO "%1$s".tgt_user (
            "TYPE"
          , "USERNAME"
          , "EMAIL"
          , "DN"
          , "ORIG_ID"
          , "ORIG_TYPE"
        )
        SELECT 'LDAP'
             , l."USERNAME" || '-CONFLICT-LDAP'
             , l."EMAIL"
             , l."DN"
             , l."ID"
             , 'LDAP'
          FROM "%1$s".src_ldapuser l
         WHERE l."USERNAME" IS NOT NULL
           AND l."ID" NOT IN (SELECT "ORIG_ID" FROM inserted);

        -- 3) OIDC users, same pattern.
        WITH inserted AS (
            INSERT INTO "%1$s".tgt_user (
                "TYPE"
              , "USERNAME"
              , "EMAIL"
              , "SUBJECT_IDENTIFIER"
              , "ORIG_ID"
              , "ORIG_TYPE"
            )
            SELECT 'OIDC'
                 , "USERNAME"
                 , "EMAIL"
                 , "SUBJECT_IDENTIFIER"
                 , "ID"
                 , 'OIDC'
              FROM "%1$s".src_oidcuser
             WHERE "USERNAME" IS NOT NULL
            ON CONFLICT ("USERNAME") DO NOTHING
            RETURNING "ORIG_ID"
        )
        INSERT INTO "%1$s".tgt_user (
            "TYPE"
          , "USERNAME"
          , "EMAIL"
          , "SUBJECT_IDENTIFIER"
          , "ORIG_ID"
          , "ORIG_TYPE"
        )
        SELECT 'OIDC'
             , o."USERNAME" || '-CONFLICT-OIDC'
             , o."EMAIL"
             , o."SUBJECT_IDENTIFIER"
             , o."ID"
             , 'OIDC'
          FROM "%1$s".src_oidcuser o
         WHERE o."USERNAME" IS NOT NULL
           AND o."ID" NOT IN (SELECT "ORIG_ID" FROM inserted)
        """,
        """
        INSERT INTO "USER" (
            "ID"
          , "TYPE"
          , "USERNAME"
          , "EMAIL"
          , "PASSWORD"
          , "FULLNAME"
          , "FORCE_PASSWORD_CHANGE"
          , "LAST_PASSWORD_CHANGE"
          , "NON_EXPIRY_PASSWORD"
          , "SUSPENDED"
          , "DN"
          , "SUBJECT_IDENTIFIER"
        )
        SELECT "ID"
             , "TYPE"
             , "USERNAME"
             , "EMAIL"
             , "PASSWORD"
             , "FULLNAME"
             , "FORCE_PASSWORD_CHANGE"
             , "LAST_PASSWORD_CHANGE"
             , "NON_EXPIRY_PASSWORD"
             , "SUSPENDED"
             , "DN"
             , "SUBJECT_IDENTIFIER"
          FROM "%1$s".tgt_user
         ORDER BY "ID"
        """
    );

    /**
     * Derived USERS_TEAMS, joining the three legacy join tables to tgt_user via {@code ORIG_ID}
     * + {@code ORIG_TYPE} (preserves the suffix mapping for conflicts).
     */
    private static final TableMigration USERS_TEAMS = new TableMigration(
        "USERS_TEAMS",
        null, null, null,
        """
        DROP TABLE IF EXISTS "%1$s".tgt_users_teams;
        CREATE UNLOGGED TABLE "%1$s".tgt_users_teams (
            "USER_ID"  bigint NOT NULL
          , "TEAM_ID"  bigint NOT NULL
          , PRIMARY KEY ("USER_ID", "TEAM_ID")
        );

        INSERT INTO "%1$s".tgt_users_teams ("USER_ID", "TEAM_ID")
        SELECT DISTINCT u."ID", m.canonical_id
          FROM "%1$s".src_ldapusers_teams j
          JOIN "%1$s".tgt_user u
            ON u."ORIG_ID" = j."LDAPUSER_ID" AND u."ORIG_TYPE" = 'LDAP'
          JOIN "%1$s".team_canonical_id_map m ON m.orig_id = j."TEAM_ID"
        ON CONFLICT DO NOTHING;

        INSERT INTO "%1$s".tgt_users_teams ("USER_ID", "TEAM_ID")
        SELECT DISTINCT u."ID", m.canonical_id
          FROM "%1$s".src_managedusers_teams j
          JOIN "%1$s".tgt_user u
            ON u."ORIG_ID" = j."MANAGEDUSER_ID" AND u."ORIG_TYPE" = 'MANAGED'
          JOIN "%1$s".team_canonical_id_map m ON m.orig_id = j."TEAM_ID"
        ON CONFLICT DO NOTHING;

        INSERT INTO "%1$s".tgt_users_teams ("USER_ID", "TEAM_ID")
        SELECT DISTINCT u."ID", m.canonical_id
          FROM "%1$s".src_oidcusers_teams j
          JOIN "%1$s".tgt_user u
            ON u."ORIG_ID" = j."OIDCUSERS_ID" AND u."ORIG_TYPE" = 'OIDC'
          JOIN "%1$s".team_canonical_id_map m ON m.orig_id = j."TEAM_ID"
        ON CONFLICT DO NOTHING
        """,
        """
        INSERT INTO "USERS_TEAMS" ("USER_ID", "TEAM_ID")
        SELECT "USER_ID", "TEAM_ID" FROM "%1$s".tgt_users_teams
        """
    );

    /**
     * Source-only mirror of v4 {@code PERMISSION}. The v5 {@code PERMISSION} catalog is
     * seeded during {@code bootstrap} (see {@link PermissionCatalog}); transform here
     * just builds {@code permission_name_map} by inner-joining v4 NAME against the
     * already-seeded v5 PERMISSION table. v4 permission names that no longer exist in
     * v5 (e.g. {@code VIEW_BADGES}) drop out of the map. Implication fan-out (v4
     * {@code ACCESS_MANAGEMENT} -> v5 {@code PORTFOLIO_ACCESS_CONTROL_BYPASS}) is
     * applied on the join-table {@code tgt_*} tables. See {@code TEAMS_PERMISSIONS} and
     * the consolidated {@code USERS_PERMISSIONS} transforms.
     */
    private static final TableMigration PERMISSION = new TableMigration(
        "PERMISSION",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_permission (
            "ID"          bigint NOT NULL
          , "DESCRIPTION" text
          , "NAME"        varchar(255) NOT NULL
        )
        """,
        """
        SELECT "ID", "DESCRIPTION", "NAME"
          FROM "%s"."PERMISSION"
         ORDER BY "ID"
        """,
        List.of("ID", "DESCRIPTION", "NAME"),
        """
        DROP TABLE IF EXISTS "%1$s".permission_name_map;
        CREATE UNLOGGED TABLE "%1$s".permission_name_map (
            orig_id BIGINT NOT NULL PRIMARY KEY
          , new_id  BIGINT NOT NULL
          , name    TEXT   NOT NULL
        );
        INSERT INTO "%1$s".permission_name_map (orig_id, new_id, name)
        SELECT s."ID", p."ID", s."NAME"
          FROM "%1$s".src_permission s
          JOIN "PERMISSION" p ON p."NAME" = s."NAME"
        """,
        null
    );

    private static final TableMigration LDAPUSERS_PERMISSIONS = new TableMigration(
        "LDAPUSERS_PERMISSIONS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_ldapusers_permissions (
            "LDAPUSER_ID"   bigint NOT NULL
          , "PERMISSION_ID" bigint NOT NULL
        )
        """,
        """
        SELECT "LDAPUSER_ID", "PERMISSION_ID"
          FROM "%s"."LDAPUSERS_PERMISSIONS"
        """,
        List.of("LDAPUSER_ID", "PERMISSION_ID"),
        null,
        null
    );

    private static final TableMigration MANAGEDUSERS_PERMISSIONS = new TableMigration(
        "MANAGEDUSERS_PERMISSIONS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_managedusers_permissions (
            "MANAGEDUSER_ID" bigint NOT NULL
          , "PERMISSION_ID"  bigint NOT NULL
        )
        """,
        """
        SELECT "MANAGEDUSER_ID", "PERMISSION_ID"
          FROM "%s"."MANAGEDUSERS_PERMISSIONS"
        """,
        List.of("MANAGEDUSER_ID", "PERMISSION_ID"),
        null,
        null
    );

    private static final TableMigration OIDCUSERS_PERMISSIONS = new TableMigration(
        "OIDCUSERS_PERMISSIONS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_oidcusers_permissions (
            "OIDCUSER_ID"   bigint NOT NULL
          , "PERMISSION_ID" bigint NOT NULL
        )
        """,
        """
        SELECT "OIDCUSER_ID", "PERMISSION_ID"
          FROM "%s"."OIDCUSERS_PERMISSIONS"
        """,
        List.of("OIDCUSER_ID", "PERMISSION_ID"),
        null,
        null
    );

    /**
     * Derived USERS_PERMISSIONS, joining the three legacy join tables to tgt_user via
     * {@code ORIG_ID} + {@code ORIG_TYPE} and rewriting the v4 PERMISSION_ID through
     * {@code permission_name_map}. Rows whose v4 permission NAME has no v5 counterpart are
     * dropped silently by the inner join.
     */
    private static final TableMigration USERS_PERMISSIONS = new TableMigration(
        "USERS_PERMISSIONS",
        null, null, null,
        """
        DROP TABLE IF EXISTS "%1$s".tgt_users_permissions;
        CREATE UNLOGGED TABLE "%1$s".tgt_users_permissions (
            "USER_ID"       bigint NOT NULL
          , "PERMISSION_ID" bigint NOT NULL
          , PRIMARY KEY ("USER_ID", "PERMISSION_ID")
        );

        INSERT INTO "%1$s".tgt_users_permissions ("USER_ID", "PERMISSION_ID")
        SELECT DISTINCT u."ID", m.new_id
          FROM "%1$s".src_ldapusers_permissions j
          JOIN "%1$s".tgt_user u
            ON u."ORIG_ID" = j."LDAPUSER_ID" AND u."ORIG_TYPE" = 'LDAP'
          JOIN "%1$s".permission_name_map m ON m.orig_id = j."PERMISSION_ID"
        ON CONFLICT DO NOTHING;

        INSERT INTO "%1$s".tgt_users_permissions ("USER_ID", "PERMISSION_ID")
        SELECT DISTINCT u."ID", m.new_id
          FROM "%1$s".src_managedusers_permissions j
          JOIN "%1$s".tgt_user u
            ON u."ORIG_ID" = j."MANAGEDUSER_ID" AND u."ORIG_TYPE" = 'MANAGED'
          JOIN "%1$s".permission_name_map m ON m.orig_id = j."PERMISSION_ID"
        ON CONFLICT DO NOTHING;

        INSERT INTO "%1$s".tgt_users_permissions ("USER_ID", "PERMISSION_ID")
        SELECT DISTINCT u."ID", m.new_id
          FROM "%1$s".src_oidcusers_permissions j
          JOIN "%1$s".tgt_user u
            ON u."ORIG_ID" = j."OIDCUSER_ID" AND u."ORIG_TYPE" = 'OIDC'
          JOIN "%1$s".permission_name_map m ON m.orig_id = j."PERMISSION_ID"
        ON CONFLICT DO NOTHING;

        -- Implication fan-out: v4 ACCESS_MANAGEMENT carried implicit portfolio-access-control
        -- bypass. v5 split that into the explicit PORTFOLIO_ACCESS_CONTROL_BYPASS permission
        -- (v5.6.0-31). Grant it to every user that holds ACCESS_MANAGEMENT in v4. The v5.6.0-31
        -- changeset also matched ACCESS_MANAGEMENT_CREATE, but that permission did not exist
        -- in v4, so the v4-to-v5 path filters on the umbrella only.
        INSERT INTO "%1$s".tgt_users_permissions ("USER_ID", "PERMISSION_ID")
        SELECT DISTINCT up."USER_ID", (SELECT "ID" FROM "PERMISSION" WHERE "NAME" = 'PORTFOLIO_ACCESS_CONTROL_BYPASS')
          FROM "%1$s".tgt_users_permissions up
          JOIN "PERMISSION" p ON p."ID" = up."PERMISSION_ID"
         WHERE p."NAME" = 'ACCESS_MANAGEMENT'
        ON CONFLICT DO NOTHING
        """,
        """
        INSERT INTO "USERS_PERMISSIONS" ("USER_ID", "PERMISSION_ID")
        SELECT "USER_ID", "PERMISSION_ID" FROM "%1$s".tgt_users_permissions
        """
    );

    /**
     * 1:1 migration of {@code OIDCGROUP} with dedup-by-NAME (canonical = MIN(ID)) per
     * schema-changes §4. v4 has no UNIQUE on OIDCGROUP.NAME but v5 adds one; the
     * {@code oidcgroup_canonical_id_map} is produced for the future MAPPEDOIDCGROUP join-table
     * transform, which is not yet in the registry.
     */
    private static final TableMigration OIDCGROUP = new TableMigration(
        "OIDCGROUP",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_oidcgroup (
            "ID"   bigint NOT NULL
          , "NAME" varchar(1024) NOT NULL
          , "UUID" varchar(36) NOT NULL
        )
        """,
        """
        SELECT "ID", "NAME", "UUID"
          FROM "%s"."OIDCGROUP"
         ORDER BY "ID"
        """,
        List.of("ID", "NAME", "UUID"),
        """
        DROP TABLE IF EXISTS "%1$s".oidcgroup_canonical_id_map;
        CREATE UNLOGGED TABLE "%1$s".oidcgroup_canonical_id_map AS
        SELECT g."ID" AS orig_id, c.canonical_id
          FROM "%1$s".src_oidcgroup g
          JOIN (
              SELECT "NAME", MIN("ID") AS canonical_id
                FROM "%1$s".src_oidcgroup
               GROUP BY "NAME"
          ) c ON c."NAME" = g."NAME";
        ALTER TABLE "%1$s".oidcgroup_canonical_id_map ADD PRIMARY KEY (orig_id);

        DROP TABLE IF EXISTS "%1$s".tgt_oidcgroup;
        CREATE UNLOGGED TABLE "%1$s".tgt_oidcgroup (
            "ID"   bigint NOT NULL PRIMARY KEY
          , "NAME" varchar(1024) NOT NULL
          , "UUID" varchar(36) NOT NULL
        );
        INSERT INTO "%1$s".tgt_oidcgroup
        SELECT "ID", "NAME", "UUID"
          FROM "%1$s".src_oidcgroup
         WHERE "ID" IN (SELECT canonical_id FROM "%1$s".oidcgroup_canonical_id_map)
        """,
        """
        INSERT INTO "OIDCGROUP" ("ID", "NAME", "UUID")
        SELECT "ID", "NAME", "UUID" FROM "%1$s".tgt_oidcgroup
        """
    );

    /**
     * 1:1 migration of {@code LICENSEGROUP}. UUID converts from {@code varchar(36)} to native
     * {@code uuid}; malformed values are captured by the probe and excluded from the target.
     */
    private static final TableMigration LICENSEGROUP = new TableMigration(
        "LICENSEGROUP",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_licensegroup (
            "ID"         bigint NOT NULL
          , "NAME"       varchar(255) NOT NULL
          , "RISKWEIGHT" integer NOT NULL
          , "UUID"       varchar(36) NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "NAME"
             , "RISKWEIGHT"
             , "UUID"
          FROM "%s"."LICENSEGROUP"
         ORDER BY "ID"
        """,
        List.of("ID", "NAME", "RISKWEIGHT", "UUID"),
        """
        INSERT INTO "%1$s".probe_invalid_uuids (table_name, orig_id, bad_uuid)
        SELECT 'LICENSEGROUP', "ID", "UUID"
          FROM "%1$s".src_licensegroup
         WHERE "UUID" !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ON CONFLICT DO NOTHING;

        DROP TABLE IF EXISTS "%1$s".tgt_licensegroup;
        CREATE UNLOGGED TABLE "%1$s".tgt_licensegroup (
            "ID"         bigint NOT NULL
          , "NAME"       varchar(255) NOT NULL
          , "RISKWEIGHT" integer NOT NULL
          , "UUID"       uuid NOT NULL
        );
        INSERT INTO "%1$s".tgt_licensegroup
        SELECT "ID"
             , "NAME"
             , "RISKWEIGHT"
             , "UUID"::uuid
          FROM "%1$s".src_licensegroup
         WHERE "UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        """,
        """
        INSERT INTO "LICENSEGROUP" (
            "ID"
          , "NAME"
          , "RISKWEIGHT"
          , "UUID"
        )
        SELECT "ID"
             , "NAME"
             , "RISKWEIGHT"
             , "UUID"
          FROM "%1$s".tgt_licensegroup
        """
    );

    /**
     * 1:1 migration of the {@code LICENSEGROUP_LICENSE} join table. Both parents (LICENSE
     * and LICENSEGROUP) can drop rows whose UUID is malformed, so join rows referencing a
     * dropped parent are filtered out here via INNER JOINs against {@code tgt_license} and
     * {@code tgt_licensegroup}. Sampling can also leave orphan join rows; the same filter
     * covers that case.
     */
    private static final TableMigration LICENSEGROUP_LICENSE = new TableMigration(
        "LICENSEGROUP_LICENSE",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_licensegroup_license (
            "LICENSEGROUP_ID" bigint NOT NULL
          , "LICENSE_ID"      bigint NOT NULL
        )
        """,
        """
        SELECT "LICENSEGROUP_ID", "LICENSE_ID"
          FROM "%s"."LICENSEGROUP_LICENSE"
        """,
        List.of("LICENSEGROUP_ID", "LICENSE_ID"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_licensegroup_license;
        CREATE UNLOGGED TABLE "%1$s".tgt_licensegroup_license (
            "LICENSEGROUP_ID" bigint NOT NULL
          , "LICENSE_ID"      bigint NOT NULL
          , PRIMARY KEY ("LICENSEGROUP_ID", "LICENSE_ID")
        );
        INSERT INTO "%1$s".tgt_licensegroup_license ("LICENSEGROUP_ID", "LICENSE_ID")
        SELECT j."LICENSEGROUP_ID", j."LICENSE_ID"
          FROM "%1$s".src_licensegroup_license j
          JOIN "%1$s".tgt_licensegroup lg ON lg."ID" = j."LICENSEGROUP_ID"
          JOIN "%1$s".tgt_license      l  ON l."ID"  = j."LICENSE_ID"
        """,
        """
        INSERT INTO "LICENSEGROUP_LICENSE" ("LICENSEGROUP_ID", "LICENSE_ID")
        SELECT "LICENSEGROUP_ID", "LICENSE_ID"
          FROM "%1$s".tgt_licensegroup_license
        """
    );

    /**
     * 1:1 migration of {@code REPOSITORY} with PASSWORD purge per schema-changes §7.8: any
     * row carrying a non-null PASSWORD has it nulled and ENABLED forced to FALSE so an admin
     * has to re-enter the secret before the repository becomes usable again. UUID is converted
     * from {@code varchar(36)} to native {@code uuid}; malformed values are captured by the
     * probe and excluded from the target.
     */
    private static final TableMigration REPOSITORY = new TableMigration(
        "REPOSITORY",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_repository (
            "ID"                     bigint NOT NULL
          , "AUTHENTICATIONREQUIRED" boolean
          , "ENABLED"                boolean NOT NULL
          , "IDENTIFIER"             varchar(255) NOT NULL
          , "INTERNAL"               boolean
          , "PASSWORD"               varchar(255)
          , "RESOLUTION_ORDER"       integer NOT NULL
          , "TYPE"                   varchar(255) NOT NULL
          , "URL"                    varchar(255)
          , "USERNAME"               varchar(255)
          , "UUID"                   varchar(36)
        )
        """,
        """
        SELECT "ID"
             , "AUTHENTICATIONREQUIRED"
             , "ENABLED"
             , "IDENTIFIER"
             , "INTERNAL"
             , "PASSWORD"
             , "RESOLUTION_ORDER"
             , "TYPE"
             , "URL"
             , "USERNAME"
             , "UUID"
          FROM "%s"."REPOSITORY"
         ORDER BY "ID"
        """,
        List.of("ID", "AUTHENTICATIONREQUIRED", "ENABLED", "IDENTIFIER", "INTERNAL",
            "PASSWORD", "RESOLUTION_ORDER", "TYPE", "URL", "USERNAME", "UUID"),
        """
        INSERT INTO "%1$s".probe_invalid_uuids (table_name, orig_id, bad_uuid)
        SELECT 'REPOSITORY', "ID", "UUID"
          FROM "%1$s".src_repository
         WHERE "UUID" IS NOT NULL
           AND "UUID" !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ON CONFLICT DO NOTHING;

        DROP TABLE IF EXISTS "%1$s".tgt_repository;
        CREATE UNLOGGED TABLE "%1$s".tgt_repository (
            "ID"                     bigint NOT NULL
          , "AUTHENTICATIONREQUIRED" boolean
          , "ENABLED"                boolean NOT NULL
          , "IDENTIFIER"             varchar(255) NOT NULL
          , "INTERNAL"               boolean
          , "PASSWORD"               varchar(255)
          , "RESOLUTION_ORDER"       integer NOT NULL
          , "TYPE"                   varchar(255) NOT NULL
          , "URL"                    varchar(255)
          , "USERNAME"               varchar(255)
          , "UUID"                   uuid
        );
        INSERT INTO "%1$s".tgt_repository
        SELECT "ID"
             , "AUTHENTICATIONREQUIRED"
             , CASE WHEN "PASSWORD" IS NOT NULL THEN FALSE ELSE "ENABLED" END
             , "IDENTIFIER"
             , "INTERNAL"
             , NULL::varchar(255)
             , "RESOLUTION_ORDER"
             , "TYPE"
             , "URL"
             , "USERNAME"
             , CASE WHEN "UUID" IS NULL THEN NULL ELSE "UUID"::uuid END
          FROM "%1$s".src_repository
         WHERE "UUID" IS NULL
            OR "UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        """,
        """
        INSERT INTO "REPOSITORY" (
            "ID"
          , "AUTHENTICATIONREQUIRED"
          , "ENABLED"
          , "IDENTIFIER"
          , "INTERNAL"
          , "PASSWORD"
          , "RESOLUTION_ORDER"
          , "TYPE"
          , "URL"
          , "USERNAME"
          , "UUID"
        )
        SELECT "ID"
             , "AUTHENTICATIONREQUIRED"
             , "ENABLED"
             , "IDENTIFIER"
             , "INTERNAL"
             , "PASSWORD"
             , "RESOLUTION_ORDER"
             , "TYPE"
             , "URL"
             , "USERNAME"
             , "UUID"
          FROM "%1$s".tgt_repository
        """
    );

    /**
     * PROJECT migration. Per schema-changes:
     * §4.8 dedup on {@code (NAME, COALESCE(VERSION, ''))} with {@code LAST_BOM_IMPORTED}
     * desc (NULLs last) + {@code ID} desc as tiebreaker; the surviving canonical id is
     * exposed via {@code project_canonical_id_map} (also rewires {@code PARENT_PROJECT_ID}).
     * §4.9 {@code IS_LATEST}: at most one TRUE per NAME, chosen by the same order;
     * tracked in {@code project_is_latest_winner}.
     * §5.1 {@code CLASSIFIER}: {@code NONE} and any value outside the v5 enum set become NULL.
     * §5.2 {@code COLLECTION_LOGIC}: {@code NONE} becomes NULL; column reference renamed
     * to {@code COLLECTION_TAG_ID} (rewritten through {@code tag_canonical_id_map}).
     * §5.3 mutual exclusivity: if both CLASSIFIER and COLLECTION_LOGIC survive, NULL the
     * CLASSIFIER and keep COLLECTION_LOGIC.
     * §5.4 {@code ACTIVE} → {@code INACTIVE_SINCE}: {@code FALSE} → epoch, else NULL.
     * §6.2 {@code DIRECT_DEPENDENCIES}: text → JSONB via {@code try_jsonb}; NULL on parse
     * failure (rows are kept).
     * §6.7 PURL pass-through (v5 widens to varchar(1024)).
     * Rows with malformed UUIDs are captured by {@code probe_invalid_uuids} and excluded
     * from {@code tgt_project} (matches the LICENSE pattern).
     */
    private static final TableMigration PROJECT = new TableMigration(
        "PROJECT",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_project (
            "ID"                          bigint NOT NULL
          , "ACTIVE"                      boolean
          , "AUTHORS"                     text
          , "CLASSIFIER"                  varchar(255)
          , "COLLECTION_LOGIC"            varchar(255)
          , "COLLECTION_TAG"              bigint
          , "CPE"                         varchar(255)
          , "DESCRIPTION"                 varchar(255)
          , "DIRECT_DEPENDENCIES"         text
          , "EXTERNAL_REFERENCES"         bytea
          , "GROUP"                       varchar(255)
          , "IS_LATEST"                   boolean NOT NULL DEFAULT FALSE
          , "LAST_BOM_IMPORTED"           timestamptz
          , "LAST_BOM_IMPORTED_FORMAT"    varchar(255)
          , "LAST_RISKSCORE"              double precision
          , "LAST_VULNERABILITY_ANALYSIS" timestamptz
          , "MANUFACTURER"                text
          , "NAME"                        varchar(255) NOT NULL
          , "PARENT_PROJECT_ID"           bigint
          , "PUBLISHER"                   varchar(255)
          , "PURL"                        varchar(786)
          , "SUPPLIER"                    text
          , "SWIDTAGID"                   varchar(255)
          , "UUID"                        varchar(36) NOT NULL
          , "VERSION"                     varchar(255)
        )
        """,
        """
        SELECT "ID"
             , "ACTIVE"
             , "AUTHORS"
             , "CLASSIFIER"
             , "COLLECTION_LOGIC"
             , "COLLECTION_TAG"
             , "CPE"
             , "DESCRIPTION"
             , "DIRECT_DEPENDENCIES"
             , "EXTERNAL_REFERENCES"
             , "GROUP"
             , "IS_LATEST"
             , "LAST_BOM_IMPORTED"
             , "LAST_BOM_IMPORTED_FORMAT"
             , "LAST_RISKSCORE"
             , "LAST_VULNERABILITY_ANALYSIS"
             , "MANUFACTURER"
             , "NAME"
             , "PARENT_PROJECT_ID"
             , "PUBLISHER"
             , "PURL"
             , "SUPPLIER"
             , "SWIDTAGID"
             , "UUID"
             , "VERSION"
          FROM "%s"."PROJECT"
         ORDER BY "ID"
        """,
        List.of("ID", "ACTIVE", "AUTHORS", "CLASSIFIER", "COLLECTION_LOGIC", "COLLECTION_TAG",
            "CPE", "DESCRIPTION", "DIRECT_DEPENDENCIES", "EXTERNAL_REFERENCES", "GROUP",
            "IS_LATEST", "LAST_BOM_IMPORTED", "LAST_BOM_IMPORTED_FORMAT", "LAST_RISKSCORE",
            "LAST_VULNERABILITY_ANALYSIS", "MANUFACTURER", "NAME", "PARENT_PROJECT_ID",
            "PUBLISHER", "PURL", "SUPPLIER", "SWIDTAGID", "UUID", "VERSION"),
        """
        INSERT INTO "%1$s".probe_invalid_uuids (table_name, orig_id, bad_uuid)
        SELECT 'PROJECT', "ID", "UUID"
          FROM "%1$s".src_project
         WHERE "UUID" !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ON CONFLICT DO NOTHING;

        DROP TABLE IF EXISTS "%1$s".project_canonical_id_map;
        CREATE UNLOGGED TABLE "%1$s".project_canonical_id_map (
            orig_id      bigint NOT NULL PRIMARY KEY
          , canonical_id bigint NOT NULL
        );
        WITH ranked AS (
            SELECT "ID",
                   FIRST_VALUE("ID") OVER (
                       PARTITION BY "NAME", COALESCE("VERSION", '')
                       ORDER BY "LAST_BOM_IMPORTED" DESC NULLS LAST, "ID" DESC
                   ) AS canonical_id
              FROM "%1$s".src_project
             WHERE "UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        )
        INSERT INTO "%1$s".project_canonical_id_map (orig_id, canonical_id)
        SELECT "ID", canonical_id FROM ranked;

        DROP TABLE IF EXISTS "%1$s".project_is_latest_winner;
        CREATE UNLOGGED TABLE "%1$s".project_is_latest_winner (
            canonical_id bigint NOT NULL PRIMARY KEY
        );
        WITH canonicals AS (
            SELECT p."ID"
                 , p."NAME"
                 , p."LAST_BOM_IMPORTED"
                 , p."IS_LATEST"
              FROM "%1$s".src_project p
              JOIN "%1$s".project_canonical_id_map m
                ON m.orig_id = p."ID" AND m.canonical_id = p."ID"
        ), ranked AS (
            SELECT "ID",
                   ROW_NUMBER() OVER (
                       PARTITION BY "NAME"
                       ORDER BY "LAST_BOM_IMPORTED" DESC NULLS LAST, "ID" DESC
                   ) AS rn
              FROM canonicals
             WHERE "IS_LATEST" IS TRUE
        )
        INSERT INTO "%1$s".project_is_latest_winner (canonical_id)
        SELECT "ID" FROM ranked WHERE rn = 1;

        DROP TABLE IF EXISTS "%1$s".tgt_project;
        CREATE UNLOGGED TABLE "%1$s".tgt_project (
            "ID"                          bigint NOT NULL PRIMARY KEY
          , "AUTHORS"                     text
          , "CLASSIFIER"                  varchar(255)
          , "COLLECTION_LOGIC"            text
          , "COLLECTION_TAG_ID"           bigint
          , "CPE"                         varchar(255)
          , "DESCRIPTION"                 varchar(255)
          , "DIRECT_DEPENDENCIES"         jsonb
          , "EXTERNAL_REFERENCES"         bytea
          , "GROUP"                       varchar(255)
          , "IS_LATEST"                   boolean NOT NULL
          , "LAST_BOM_IMPORTED"           timestamptz
          , "LAST_BOM_IMPORTED_FORMAT"    varchar(255)
          , "LAST_RISKSCORE"              double precision
          , "LAST_VULNERABILITY_ANALYSIS" timestamptz
          , "MANUFACTURER"                text
          , "NAME"                        varchar(255) NOT NULL
          , "PARENT_PROJECT_ID"           bigint
          , "PUBLISHER"                   varchar(255)
          , "PURL"                        varchar(1024)
          , "SUPPLIER"                    text
          , "SWIDTAGID"                   varchar(255)
          , "UUID"                        uuid NOT NULL
          , "VERSION"                     varchar(255)
          , "INACTIVE_SINCE"              timestamptz
        );
        WITH coerced AS (
            SELECT p."ID",
                   p."AUTHORS",
                   CASE
                       WHEN p."CLASSIFIER" IN (
                           'APPLICATION','CONTAINER','CRYPTOGRAPHIC_ASSET','DATA','DEVICE',
                           'DEVICE_DRIVER','FILE','FIRMWARE','FRAMEWORK','LIBRARY',
                           'MACHINE_LEARNING_MODEL','OPERATING_SYSTEM','PLATFORM'
                       ) THEN p."CLASSIFIER"
                       ELSE NULL
                   END AS "CLASSIFIER",
                   CASE WHEN p."COLLECTION_LOGIC" = 'NONE' THEN NULL ELSE p."COLLECTION_LOGIC" END AS "COLLECTION_LOGIC",
                   tag_map.canonical_id AS "COLLECTION_TAG_ID",
                   p."CPE",
                   p."DESCRIPTION",
                   "%1$s".try_jsonb(p."DIRECT_DEPENDENCIES") AS "DIRECT_DEPENDENCIES",
                   p."EXTERNAL_REFERENCES",
                   p."GROUP",
                   (winner.canonical_id IS NOT NULL) AS "IS_LATEST",
                   p."LAST_BOM_IMPORTED",
                   p."LAST_BOM_IMPORTED_FORMAT",
                   p."LAST_RISKSCORE",
                   p."LAST_VULNERABILITY_ANALYSIS",
                   p."MANUFACTURER",
                   p."NAME",
                   parent_map.canonical_id AS "PARENT_PROJECT_ID",
                   p."PUBLISHER",
                   p."PURL",
                   p."SUPPLIER",
                   p."SWIDTAGID",
                   p."UUID"::uuid AS "UUID",
                   p."VERSION",
                   CASE WHEN p."ACTIVE" IS FALSE THEN 'epoch'::timestamptz ELSE NULL END AS "INACTIVE_SINCE"
              FROM "%1$s".src_project p
              JOIN "%1$s".project_canonical_id_map m
                ON m.orig_id = p."ID" AND m.canonical_id = p."ID"
              LEFT JOIN "%1$s".project_canonical_id_map parent_map
                ON parent_map.orig_id = p."PARENT_PROJECT_ID"
              LEFT JOIN "%1$s".tag_canonical_id_map tag_map
                ON tag_map.orig_id = p."COLLECTION_TAG"
              LEFT JOIN "%1$s".project_is_latest_winner winner
                ON winner.canonical_id = p."ID"
             WHERE p."UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        )
        INSERT INTO "%1$s".tgt_project (
            "ID"
          , "AUTHORS"
          , "CLASSIFIER"
          , "COLLECTION_LOGIC"
          , "COLLECTION_TAG_ID"
          , "CPE"
          , "DESCRIPTION"
          , "DIRECT_DEPENDENCIES"
          , "EXTERNAL_REFERENCES"
          , "GROUP"
          , "IS_LATEST"
          , "LAST_BOM_IMPORTED"
          , "LAST_BOM_IMPORTED_FORMAT"
          , "LAST_RISKSCORE"
          , "LAST_VULNERABILITY_ANALYSIS"
          , "MANUFACTURER"
          , "NAME"
          , "PARENT_PROJECT_ID"
          , "PUBLISHER"
          , "PURL"
          , "SUPPLIER"
          , "SWIDTAGID"
          , "UUID"
          , "VERSION"
          , "INACTIVE_SINCE"
        )
        SELECT "ID"
             , "AUTHORS"
             , CASE WHEN "COLLECTION_LOGIC" IS NOT NULL THEN NULL ELSE "CLASSIFIER" END
             , "COLLECTION_LOGIC"
             , "COLLECTION_TAG_ID"
             , "CPE"
             , "DESCRIPTION"
             , "DIRECT_DEPENDENCIES"
             , "EXTERNAL_REFERENCES"
             , "GROUP"
             , "IS_LATEST"
             , "LAST_BOM_IMPORTED"
             , "LAST_BOM_IMPORTED_FORMAT"
             , "LAST_RISKSCORE"
             , "LAST_VULNERABILITY_ANALYSIS"
             , "MANUFACTURER"
             , "NAME"
             , "PARENT_PROJECT_ID"
             , "PUBLISHER"
             , "PURL"
             , "SUPPLIER"
             , "SWIDTAGID"
             , "UUID"
             , "VERSION"
             , "INACTIVE_SINCE"
          FROM coerced
        """,
        """
        INSERT INTO "PROJECT" (
            "ID"
          , "AUTHORS"
          , "CLASSIFIER"
          , "COLLECTION_LOGIC"
          , "COLLECTION_TAG_ID"
          , "CPE"
          , "DESCRIPTION"
          , "DIRECT_DEPENDENCIES"
          , "EXTERNAL_REFERENCES"
          , "GROUP"
          , "IS_LATEST"
          , "LAST_BOM_IMPORTED"
          , "LAST_BOM_IMPORTED_FORMAT"
          , "LAST_RISKSCORE"
          , "LAST_VULNERABILITY_ANALYSIS"
          , "MANUFACTURER"
          , "NAME"
          , "PARENT_PROJECT_ID"
          , "PUBLISHER"
          , "PURL"
          , "SUPPLIER"
          , "SWIDTAGID"
          , "UUID"
          , "VERSION"
          , "INACTIVE_SINCE"
        )
        SELECT "ID"
             , "AUTHORS"
             , "CLASSIFIER"
             , "COLLECTION_LOGIC"
             , "COLLECTION_TAG_ID"
             , "CPE"
             , "DESCRIPTION"
             , "DIRECT_DEPENDENCIES"
             , "EXTERNAL_REFERENCES"
             , "GROUP"
             , "IS_LATEST"
             , "LAST_BOM_IMPORTED"
             , "LAST_BOM_IMPORTED_FORMAT"
             , "LAST_RISKSCORE"
             , "LAST_VULNERABILITY_ANALYSIS"
             , "MANUFACTURER"
             , "NAME"
             , "PARENT_PROJECT_ID"
             , "PUBLISHER"
             , "PURL"
             , "SUPPLIER"
             , "SWIDTAGID"
             , "UUID"
             , "VERSION"
             , "INACTIVE_SINCE"
          FROM "%1$s".tgt_project
        """
    );

    /**
     * PROJECT_HIERARCHY closure per pipeline §7.2 and schema-changes §7.2. Built via recursive
     * CTE from PROJECT.PARENT_PROJECT_ID. Includes a self-row at depth 0 for every project.
     */
    private static final TableMigration PROJECT_HIERARCHY = new TableMigration(
        "PROJECT_HIERARCHY",
        null, null, null,
        """
        DROP TABLE IF EXISTS "%1$s".tgt_project_hierarchy;
        CREATE UNLOGGED TABLE "%1$s".tgt_project_hierarchy (
            "PARENT_PROJECT_ID" bigint NOT NULL
          , "CHILD_PROJECT_ID"  bigint NOT NULL
          , "DEPTH"             integer NOT NULL
          , PRIMARY KEY ("PARENT_PROJECT_ID", "CHILD_PROJECT_ID")
        );

        WITH RECURSIVE walk AS (
            -- self-row at depth 0
            SELECT "ID" AS root_id, "ID" AS child_id, 0 AS depth
              FROM "%1$s".tgt_project
            UNION ALL
            -- walk children: for each (root, child), find children of child
            SELECT w.root_id, c."ID", w.depth + 1
              FROM walk w
              JOIN "%1$s".tgt_project c ON c."PARENT_PROJECT_ID" = w.child_id
        )
        INSERT INTO "%1$s".tgt_project_hierarchy ("PARENT_PROJECT_ID", "CHILD_PROJECT_ID", "DEPTH")
        SELECT root_id, child_id, depth FROM walk
        """,
        // The maintenance triggers on PROJECT_HIERARCHY's parent table fire on PROJECT inserts.
        // To avoid double-population the migrator disables the trigger pack around the PROJECT
        // load and re-populates PROJECT_HIERARCHY directly from tgt.
        """
        INSERT INTO "PROJECT_HIERARCHY" ("PARENT_PROJECT_ID", "CHILD_PROJECT_ID", "DEPTH")
        SELECT "PARENT_PROJECT_ID", "CHILD_PROJECT_ID", "DEPTH"
          FROM "%1$s".tgt_project_hierarchy
        """
    );

    /**
     * 1:1 migration of {@code NOTIFICATIONPUBLISHER} with dedup-by-NAME (canonical = MIN(ID))
     * per schema-changes §4. {@code PUBLISHER_CLASS} is renamed to {@code EXTENSION_NAME} and
     * mapped from the v4 Java class name (with package prefix stripped) to the v5 extension id
     * per schema-changes §5.5. Unknown class names pass through unchanged. UUID is converted
     * from {@code varchar(36)} to native {@code uuid}; malformed values are captured by the
     * probe and excluded from the target. The {@code notificationpublisher_canonical_id_map}
     * is consumed by NOTIFICATIONRULE to rewrite the {@code PUBLISHER} FK.
     */
    private static final TableMigration NOTIFICATIONPUBLISHER = new TableMigration(
        "NOTIFICATIONPUBLISHER",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_notificationpublisher (
            "ID"                 bigint NOT NULL
          , "DEFAULT_PUBLISHER"  boolean NOT NULL
          , "DESCRIPTION"        varchar(255)
          , "NAME"               varchar(255) NOT NULL
          , "PUBLISHER_CLASS"    varchar(1024) NOT NULL
          , "TEMPLATE"           text
          , "TEMPLATE_MIME_TYPE" varchar(255) NOT NULL
          , "UUID"               varchar(36) NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "DEFAULT_PUBLISHER"
             , "DESCRIPTION"
             , "NAME"
             , "PUBLISHER_CLASS"
             , "TEMPLATE"
             , "TEMPLATE_MIME_TYPE"
             , "UUID"
          FROM "%s"."NOTIFICATIONPUBLISHER"
         ORDER BY "ID"
        """,
        List.of("ID", "DEFAULT_PUBLISHER", "DESCRIPTION", "NAME", "PUBLISHER_CLASS",
            "TEMPLATE", "TEMPLATE_MIME_TYPE", "UUID"),
        """
        INSERT INTO "%1$s".probe_invalid_uuids (table_name, orig_id, bad_uuid)
        SELECT 'NOTIFICATIONPUBLISHER', "ID", "UUID"
          FROM "%1$s".src_notificationpublisher
         WHERE "UUID" !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ON CONFLICT DO NOTHING;

        DROP TABLE IF EXISTS "%1$s".notificationpublisher_canonical_id_map;
        CREATE UNLOGGED TABLE "%1$s".notificationpublisher_canonical_id_map AS
        SELECT p."ID" AS orig_id, c.canonical_id
          FROM "%1$s".src_notificationpublisher p
          JOIN (
              SELECT "NAME", MIN("ID") AS canonical_id
                FROM "%1$s".src_notificationpublisher
               GROUP BY "NAME"
          ) c ON c."NAME" = p."NAME";
        ALTER TABLE "%1$s".notificationpublisher_canonical_id_map ADD PRIMARY KEY (orig_id);

        DROP TABLE IF EXISTS "%1$s".tgt_notificationpublisher;
        CREATE UNLOGGED TABLE "%1$s".tgt_notificationpublisher (
            "ID"                 bigint NOT NULL PRIMARY KEY
          , "DEFAULT_PUBLISHER"  boolean NOT NULL
          , "DESCRIPTION"        varchar(255)
          , "NAME"               varchar(255) NOT NULL
          , "EXTENSION_NAME"     varchar(1024) NOT NULL
          , "TEMPLATE"           text
          , "TEMPLATE_MIME_TYPE" varchar(255)
          , "UUID"               uuid NOT NULL
        );
        INSERT INTO "%1$s".tgt_notificationpublisher
        SELECT "ID"
             , "DEFAULT_PUBLISHER"
             , "DESCRIPTION"
             , "NAME"
             , CASE regexp_replace("PUBLISHER_CLASS", '^.*\\.', '') WHEN 'ConsolePublisher'    THEN 'console' WHEN 'CsWebexPublisher'    THEN 'webex' WHEN 'JiraPublisher'       THEN 'jira' WHEN 'MattermostPublisher' THEN 'mattermost' WHEN 'MsTeamsPublisher'    THEN 'msteams' WHEN 'SendMailPublisher'   THEN 'email' WHEN 'SlackPublisher'      THEN 'slack' WHEN 'WebhookPublisher'    THEN 'webhook' ELSE regexp_replace("PUBLISHER_CLASS", '^.*\\.', '') END
             , "TEMPLATE"
             , "TEMPLATE_MIME_TYPE"
             , "UUID"::uuid
          FROM "%1$s".src_notificationpublisher
         WHERE "ID" IN (SELECT canonical_id FROM "%1$s".notificationpublisher_canonical_id_map)
           AND "UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        """,
        """
        INSERT INTO "NOTIFICATIONPUBLISHER" (
            "ID"
          , "NAME"
          , "DESCRIPTION"
          , "DEFAULT_PUBLISHER"
          , "EXTENSION_NAME"
          , "TEMPLATE"
          , "TEMPLATE_MIME_TYPE"
          , "UUID"
        )
        SELECT "ID"
             , "NAME"
             , "DESCRIPTION"
             , "DEFAULT_PUBLISHER"
             , "EXTENSION_NAME"
             , "TEMPLATE"
             , "TEMPLATE_MIME_TYPE"
             , "UUID"
          FROM "%1$s".tgt_notificationpublisher
        """
    );

    /**
     * 1:1 migration of {@code NOTIFICATIONRULE} with dedup-by-NAME (canonical = MIN(ID)) per
     * schema-changes §4 and several value transforms per §6.4 (NOTIFICATION_LEVEL → enum),
     * §6.5 (NOTIFY_ON CSV → text[]) and §7.6 (PUBLISHER_CONFIG rebuild). {@code PUBLISHER} is
     * rewritten through {@code notificationpublisher_canonical_id_map}; rules whose publisher
     * cannot be mapped are dropped by the inner join. All rules are loaded with
     * {@code ENABLED=FALSE} (operators re-enable post-migration after reviewing the
     * regenerated config). {@code TRIGGER_TYPE} hard-set to {@code 'EVENT'}; schedule columns
     * and {@code FILTER_EXPRESSION} NULL on import (v4 has no equivalent).
     */
    private static final TableMigration NOTIFICATIONRULE = new TableMigration(
        "NOTIFICATIONRULE",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_notificationrule (
            "ID"                          bigint NOT NULL
          , "ENABLED"                     boolean NOT NULL
          , "LOG_SUCCESSFUL_PUBLISH"      boolean
          , "MESSAGE"                     varchar(1024)
          , "NAME"                        varchar(255) NOT NULL
          , "NOTIFICATION_LEVEL"          varchar(255)
          , "NOTIFY_CHILDREN"             boolean
          , "NOTIFY_ON"                   varchar(1024)
          , "PUBLISHER"                   bigint
          , "PUBLISHER_CONFIG"            text
          , "SCOPE"                       varchar(255) NOT NULL
          , "UUID"                        varchar(36) NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "ENABLED"
             , "LOG_SUCCESSFUL_PUBLISH"
             , "MESSAGE"
             , "NAME"
             , "NOTIFICATION_LEVEL"
             , "NOTIFY_CHILDREN"
             , "NOTIFY_ON"
             , "PUBLISHER"
             , "PUBLISHER_CONFIG"
             , "SCOPE"
             , "UUID"
          FROM "%s"."NOTIFICATIONRULE"
         ORDER BY "ID"
        """,
        List.of("ID", "ENABLED", "LOG_SUCCESSFUL_PUBLISH", "MESSAGE", "NAME",
            "NOTIFICATION_LEVEL", "NOTIFY_CHILDREN", "NOTIFY_ON", "PUBLISHER",
            "PUBLISHER_CONFIG", "SCOPE", "UUID"),
        """
        INSERT INTO "%1$s".probe_invalid_uuids (table_name, orig_id, bad_uuid)
        SELECT 'NOTIFICATIONRULE', "ID", "UUID"
          FROM "%1$s".src_notificationrule
         WHERE "UUID" !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ON CONFLICT DO NOTHING;

        DROP TABLE IF EXISTS "%1$s".notificationrule_canonical_id_map;
        CREATE UNLOGGED TABLE "%1$s".notificationrule_canonical_id_map AS
        SELECT r."ID" AS orig_id, c.canonical_id
          FROM "%1$s".src_notificationrule r
          JOIN (
              SELECT "NAME", MIN("ID") AS canonical_id
                FROM "%1$s".src_notificationrule
               GROUP BY "NAME"
          ) c ON c."NAME" = r."NAME";
        ALTER TABLE "%1$s".notificationrule_canonical_id_map ADD PRIMARY KEY (orig_id);

        DROP TABLE IF EXISTS "%1$s".tgt_notificationrule;
        CREATE UNLOGGED TABLE "%1$s".tgt_notificationrule (
            "ID"                          bigint NOT NULL PRIMARY KEY
          , "ENABLED"                     boolean NOT NULL
          , "LOG_SUCCESSFUL_PUBLISH"      boolean
          , "MESSAGE"                     varchar(1024)
          , "NAME"                        varchar(255) NOT NULL
          -- Stored as text + CHECK rather than the native "notification_level" enum so a
          -- target-side DROP SCHEMA public CASCADE does not transitively drop this column.
          -- Keep the value list in sync with migration/.../V202605022031__init.sql.
          , "NOTIFICATION_LEVEL"          varchar(255) CHECK ("NOTIFICATION_LEVEL" IN ('INFORMATIONAL', 'WARNING', 'ERROR'))
          , "NOTIFY_CHILDREN"             boolean
          , "NOTIFY_ON"                   text[]
          , "PUBLISHER"                   bigint
          , "PUBLISHER_CONFIG"            jsonb
          , "SCOPE"                       varchar(255) NOT NULL
          , "UUID"                        uuid NOT NULL
          , "TRIGGER_TYPE"                text NOT NULL
          , "SCHEDULE_CRON"               text
          , "SCHEDULE_LAST_TRIGGERED_AT"  timestamptz
          , "SCHEDULE_NEXT_TRIGGER_AT"    timestamptz
          , "SCHEDULE_SKIP_UNCHANGED"     boolean
          , "FILTER_EXPRESSION"           text
        );
        INSERT INTO "%1$s".tgt_notificationrule
        SELECT r."ID"
             , FALSE
             , r."LOG_SUCCESSFUL_PUBLISH"
             , r."MESSAGE"
             , r."NAME"
             , r."NOTIFICATION_LEVEL"
             , r."NOTIFY_CHILDREN"
             , CASE WHEN r."NOTIFY_ON" IS NULL THEN NULL ELSE string_to_array(r."NOTIFY_ON", ',') END
             , m.canonical_id
             , CASE p."EXTENSION_NAME" WHEN 'console' THEN NULL::jsonb WHEN 'email' THEN CASE WHEN COALESCE("%1$s".try_jsonb(r."PUBLISHER_CONFIG") ->> 'destination', '') = '' THEN jsonb_build_object('recipientAddresses', jsonb_build_array()) ELSE jsonb_build_object('recipientAddresses', jsonb_build_array("%1$s".try_jsonb(r."PUBLISHER_CONFIG") ->> 'destination')) END WHEN 'jira' THEN jsonb_build_object( 'projectKey', COALESCE("%1$s".try_jsonb(r."PUBLISHER_CONFIG") ->> 'destination', 'EXAMPLE'), 'issueType',  COALESCE("%1$s".try_jsonb(r."PUBLISHER_CONFIG") ->> 'jiraTicketType', 'TASK')) WHEN 'mattermost' THEN jsonb_build_object( 'destinationUrl', COALESCE("%1$s".try_jsonb(r."PUBLISHER_CONFIG") ->> 'destination', 'https://example.com')) WHEN 'msteams' THEN jsonb_build_object( 'destinationUrl', COALESCE("%1$s".try_jsonb(r."PUBLISHER_CONFIG") ->> 'destination', 'https://example.com')) WHEN 'slack' THEN jsonb_build_object( 'destinationUrl', COALESCE("%1$s".try_jsonb(r."PUBLISHER_CONFIG") ->> 'destination', 'https://example.com')) WHEN 'webex' THEN jsonb_build_object( 'destinationUrl', COALESCE("%1$s".try_jsonb(r."PUBLISHER_CONFIG") ->> 'destination', 'https://example.com')) WHEN 'webhook' THEN jsonb_build_object( 'destinationUrl', COALESCE("%1$s".try_jsonb(r."PUBLISHER_CONFIG") ->> 'destination', 'https://example.com')) ELSE NULL::jsonb END
             , r."SCOPE"
             , r."UUID"::uuid
             , 'EVENT'
             , NULL
             , NULL
             , NULL
             , NULL
             , NULL
          FROM "%1$s".src_notificationrule r
          JOIN "%1$s".notificationpublisher_canonical_id_map m ON m.orig_id = r."PUBLISHER"
          JOIN "%1$s".tgt_notificationpublisher p ON p."ID" = m.canonical_id
         WHERE r."ID" IN (SELECT canonical_id FROM "%1$s".notificationrule_canonical_id_map)
           AND r."UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        """,
        """
        INSERT INTO "NOTIFICATIONRULE" (
            "ID"
          , "ENABLED"
          , "LOG_SUCCESSFUL_PUBLISH"
          , "MESSAGE"
          , "NAME"
          , "NOTIFICATION_LEVEL"
          , "NOTIFY_CHILDREN"
          , "NOTIFY_ON"
          , "PUBLISHER"
          , "PUBLISHER_CONFIG"
          , "SCOPE"
          , "UUID"
          , "TRIGGER_TYPE"
          , "SCHEDULE_CRON"
          , "SCHEDULE_LAST_TRIGGERED_AT"
          , "SCHEDULE_NEXT_TRIGGER_AT"
          , "SCHEDULE_SKIP_UNCHANGED"
          , "FILTER_EXPRESSION"
        )
        SELECT "ID"
             , "ENABLED"
             , "LOG_SUCCESSFUL_PUBLISH"
             , "MESSAGE"
             , "NAME"
             , CASE WHEN "NOTIFICATION_LEVEL" IS NULL THEN NULL ELSE "NOTIFICATION_LEVEL"::notification_level END
             , "NOTIFY_CHILDREN"
             , "NOTIFY_ON"
             , "PUBLISHER"
             , "PUBLISHER_CONFIG"
             , "SCOPE"
             , "UUID"
             , "TRIGGER_TYPE"
             , "SCHEDULE_CRON"
             , "SCHEDULE_LAST_TRIGGERED_AT"
             , "SCHEDULE_NEXT_TRIGGER_AT"
             , "SCHEDULE_SKIP_UNCHANGED"
             , "FILTER_EXPRESSION"
          FROM "%1$s".tgt_notificationrule
        """
    );

    /**
     * 1:1 migration of {@code NOTIFICATIONRULE_TAGS}. Rewrites both columns through the
     * NOTIFICATIONRULE and TAG canonical-id maps. Dedup on the composite key.
     */
    private static final TableMigration NOTIFICATIONRULE_TAGS = new TableMigration(
        "NOTIFICATIONRULE_TAGS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_notificationrule_tags (
            "NOTIFICATIONRULE_ID" bigint NOT NULL
          , "TAG_ID"              bigint NOT NULL
        )
        """,
        """
        SELECT "NOTIFICATIONRULE_ID", "TAG_ID"
          FROM "%s"."NOTIFICATIONRULE_TAGS"
        """,
        List.of("NOTIFICATIONRULE_ID", "TAG_ID"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_notificationrule_tags;
        CREATE UNLOGGED TABLE "%1$s".tgt_notificationrule_tags (
            "NOTIFICATIONRULE_ID" bigint NOT NULL
          , "TAG_ID"              bigint NOT NULL
          , PRIMARY KEY ("NOTIFICATIONRULE_ID", "TAG_ID")
        );
        INSERT INTO "%1$s".tgt_notificationrule_tags ("NOTIFICATIONRULE_ID", "TAG_ID")
        SELECT DISTINCT rm.canonical_id, tm.canonical_id
          FROM "%1$s".src_notificationrule_tags j
          JOIN "%1$s".notificationrule_canonical_id_map rm ON rm.orig_id = j."NOTIFICATIONRULE_ID"
          JOIN "%1$s".tag_canonical_id_map tm ON tm.orig_id = j."TAG_ID"
        ON CONFLICT DO NOTHING
        """,
        """
        INSERT INTO "NOTIFICATIONRULE_TAGS" ("NOTIFICATIONRULE_ID", "TAG_ID")
        SELECT "NOTIFICATIONRULE_ID", "TAG_ID" FROM "%1$s".tgt_notificationrule_tags
        """
    );

    /**
     * 1:1 migration of {@code NOTIFICATIONRULE_TEAMS}. v4 allows NULL {@code TEAM_ID}; v5
     * tightens it to NOT NULL, so NULL rows are dropped. Rewrites both columns through the
     * NOTIFICATIONRULE and TEAM canonical-id maps. Dedup on the composite key.
     */
    private static final TableMigration NOTIFICATIONRULE_TEAMS = new TableMigration(
        "NOTIFICATIONRULE_TEAMS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_notificationrule_teams (
            "NOTIFICATIONRULE_ID" bigint NOT NULL
          , "TEAM_ID"             bigint
        )
        """,
        """
        SELECT "NOTIFICATIONRULE_ID", "TEAM_ID"
          FROM "%s"."NOTIFICATIONRULE_TEAMS"
        """,
        List.of("NOTIFICATIONRULE_ID", "TEAM_ID"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_notificationrule_teams;
        CREATE UNLOGGED TABLE "%1$s".tgt_notificationrule_teams (
            "NOTIFICATIONRULE_ID" bigint NOT NULL
          , "TEAM_ID"             bigint NOT NULL
          , PRIMARY KEY ("NOTIFICATIONRULE_ID", "TEAM_ID")
        );
        INSERT INTO "%1$s".tgt_notificationrule_teams ("NOTIFICATIONRULE_ID", "TEAM_ID")
        SELECT DISTINCT rm.canonical_id, tm.canonical_id
          FROM "%1$s".src_notificationrule_teams j
          JOIN "%1$s".notificationrule_canonical_id_map rm ON rm.orig_id = j."NOTIFICATIONRULE_ID"
          JOIN "%1$s".team_canonical_id_map tm ON tm.orig_id = j."TEAM_ID"
         WHERE j."TEAM_ID" IS NOT NULL
        ON CONFLICT DO NOTHING
        """,
        """
        INSERT INTO "NOTIFICATIONRULE_TEAMS" ("NOTIFICATIONRULE_ID", "TEAM_ID")
        SELECT "NOTIFICATIONRULE_ID", "TEAM_ID" FROM "%1$s".tgt_notificationrule_teams
        """
    );

    /**
     * 1:1 migration of {@code POLICY}. v4 already enforces UNIQUE(NAME) so no dedup is needed.
     * UUID is converted from {@code varchar(36)} to native {@code uuid}; malformed values are
     * captured by the probe and excluded from the target.
     */
    private static final TableMigration POLICY = new TableMigration(
        "POLICY",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_policy (
            "ID"                          bigint NOT NULL
          , "INCLUDE_CHILDREN"            boolean
          , "NAME"                        varchar(255) NOT NULL
          , "ONLY_LATEST_PROJECT_VERSION" boolean NOT NULL
          , "OPERATOR"                    varchar(255) NOT NULL
          , "UUID"                        varchar(36) NOT NULL
          , "VIOLATIONSTATE"              varchar(255) NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "INCLUDE_CHILDREN"
             , "NAME"
             , "ONLY_LATEST_PROJECT_VERSION"
             , "OPERATOR"
             , "UUID"
             , "VIOLATIONSTATE"
          FROM "%s"."POLICY"
         ORDER BY "ID"
        """,
        List.of("ID", "INCLUDE_CHILDREN", "NAME", "ONLY_LATEST_PROJECT_VERSION",
            "OPERATOR", "UUID", "VIOLATIONSTATE"),
        """
        INSERT INTO "%1$s".probe_invalid_uuids (table_name, orig_id, bad_uuid)
        SELECT 'POLICY', "ID", "UUID"
          FROM "%1$s".src_policy
         WHERE "UUID" !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ON CONFLICT DO NOTHING;

        DROP TABLE IF EXISTS "%1$s".tgt_policy;
        CREATE UNLOGGED TABLE "%1$s".tgt_policy (
            "ID"                          bigint NOT NULL PRIMARY KEY
          , "INCLUDE_CHILDREN"            boolean
          , "NAME"                        varchar(255) NOT NULL
          , "ONLY_LATEST_PROJECT_VERSION" boolean NOT NULL
          , "OPERATOR"                    varchar(255) NOT NULL
          , "UUID"                        uuid NOT NULL
          , "VIOLATIONSTATE"              varchar(255) NOT NULL
        );
        INSERT INTO "%1$s".tgt_policy
        SELECT "ID"
             , "INCLUDE_CHILDREN"
             , "NAME"
             , "ONLY_LATEST_PROJECT_VERSION"
             , "OPERATOR"
             , "UUID"::uuid
             , "VIOLATIONSTATE"
          FROM "%1$s".src_policy
         WHERE "UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        """,
        """
        INSERT INTO "POLICY" (
            "ID"
          , "INCLUDE_CHILDREN"
          , "NAME"
          , "ONLY_LATEST_PROJECT_VERSION"
          , "OPERATOR"
          , "UUID"
          , "VIOLATIONSTATE"
        )
        SELECT "ID"
             , "INCLUDE_CHILDREN"
             , "NAME"
             , "ONLY_LATEST_PROJECT_VERSION"
             , "OPERATOR"
             , "UUID"
             , "VIOLATIONSTATE"
          FROM "%1$s".tgt_policy
        """
    );

    /**
     * 1:1 migration of {@code POLICYCONDITION}. UUID is converted from {@code varchar(36)} to
     * native {@code uuid}; malformed values are captured by the probe and excluded from the
     * target. {@code VALUE} widens from {@code varchar(255)} to {@code text} (implicit cast).
     * The new {@code VIOLATIONTYPE} column has no v4 equivalent and is NULL on load.
     */
    private static final TableMigration POLICYCONDITION = new TableMigration(
        "POLICYCONDITION",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_policycondition (
            "ID"        bigint NOT NULL
          , "OPERATOR"  varchar(255) NOT NULL
          , "POLICY_ID" bigint NOT NULL
          , "SUBJECT"   varchar(255) NOT NULL
          , "UUID"      varchar(36) NOT NULL
          , "VALUE"     varchar(255) NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "OPERATOR"
             , "POLICY_ID"
             , "SUBJECT"
             , "UUID"
             , "VALUE"
          FROM "%s"."POLICYCONDITION"
         ORDER BY "ID"
        """,
        List.of("ID", "OPERATOR", "POLICY_ID", "SUBJECT", "UUID", "VALUE"),
        """
        INSERT INTO "%1$s".probe_invalid_uuids (table_name, orig_id, bad_uuid)
        SELECT 'POLICYCONDITION', "ID", "UUID"
          FROM "%1$s".src_policycondition
         WHERE "UUID" !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ON CONFLICT DO NOTHING;

        DROP TABLE IF EXISTS "%1$s".tgt_policycondition;
        CREATE UNLOGGED TABLE "%1$s".tgt_policycondition (
            "ID"            bigint NOT NULL PRIMARY KEY
          , "OPERATOR"      varchar(255) NOT NULL
          , "POLICY_ID"     bigint NOT NULL
          , "SUBJECT"       varchar(255) NOT NULL
          , "UUID"          uuid NOT NULL
          , "VALUE"         text NOT NULL
          , "VIOLATIONTYPE" varchar(255)
        );
        INSERT INTO "%1$s".tgt_policycondition
        SELECT c."ID"
             , c."OPERATOR"
             , c."POLICY_ID"
             , c."SUBJECT"
             , c."UUID"::uuid
             , c."VALUE"
             , NULL
          FROM "%1$s".src_policycondition c
          JOIN "%1$s".tgt_policy p ON p."ID" = c."POLICY_ID"
         WHERE c."UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        """,
        """
        INSERT INTO "POLICYCONDITION" (
            "ID"
          , "OPERATOR"
          , "POLICY_ID"
          , "SUBJECT"
          , "UUID"
          , "VALUE"
          , "VIOLATIONTYPE"
        )
        SELECT "ID"
             , "OPERATOR"
             , "POLICY_ID"
             , "SUBJECT"
             , "UUID"
             , "VALUE"
             , "VIOLATIONTYPE"
          FROM "%1$s".tgt_policycondition
        """
    );

    /**
     * 1:1 migration of {@code POLICY_TAGS}. POLICY_ID needs no rewrite (POLICY preserves v4 IDs);
     * TAG_ID is rewritten through {@code tag_canonical_id_map}. Dedup on the composite key.
     */
    private static final TableMigration POLICY_TAGS = new TableMigration(
        "POLICY_TAGS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_policy_tags (
            "POLICY_ID" bigint NOT NULL
          , "TAG_ID"    bigint NOT NULL
        )
        """,
        """
        SELECT "POLICY_ID", "TAG_ID"
          FROM "%s"."POLICY_TAGS"
        """,
        List.of("POLICY_ID", "TAG_ID"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_policy_tags;
        CREATE UNLOGGED TABLE "%1$s".tgt_policy_tags (
            "POLICY_ID" bigint NOT NULL
          , "TAG_ID"    bigint NOT NULL
          , PRIMARY KEY ("POLICY_ID", "TAG_ID")
        );
        INSERT INTO "%1$s".tgt_policy_tags ("POLICY_ID", "TAG_ID")
        SELECT DISTINCT j."POLICY_ID", tm.canonical_id
          FROM "%1$s".src_policy_tags j
          JOIN "%1$s".tgt_policy p ON p."ID" = j."POLICY_ID"
          JOIN "%1$s".tag_canonical_id_map tm ON tm.orig_id = j."TAG_ID"
        ON CONFLICT DO NOTHING
        """,
        """
        INSERT INTO "POLICY_TAGS" ("POLICY_ID", "TAG_ID")
        SELECT "POLICY_ID", "TAG_ID" FROM "%1$s".tgt_policy_tags
        """
    );

    /**
     * 1:1 migration of {@code POLICY_PROJECTS}. POLICY_ID passes through (POLICY preserves
     * v4 IDs); PROJECT_ID is rewritten through {@code project_canonical_id_map}. v4 allows
     * NULL PROJECT_ID; v5 keeps it nullable but a NULL row has no semantic meaning here
     * (POLICY scope is governed by INCLUDE_CHILDREN / tag membership, not NULL rows), so
     * NULL PROJECT_ID rows are dropped via INNER JOIN. Dedup on the composite key.
     */
    private static final TableMigration POLICY_PROJECTS = new TableMigration(
        "POLICY_PROJECTS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_policy_projects (
            "POLICY_ID"  bigint NOT NULL
          , "PROJECT_ID" bigint
        )
        """,
        """
        SELECT "POLICY_ID", "PROJECT_ID"
          FROM "%s"."POLICY_PROJECTS"
        """,
        List.of("POLICY_ID", "PROJECT_ID"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_policy_projects;
        CREATE UNLOGGED TABLE "%1$s".tgt_policy_projects (
            "POLICY_ID"  bigint NOT NULL
          , "PROJECT_ID" bigint NOT NULL
          , PRIMARY KEY ("POLICY_ID", "PROJECT_ID")
        );
        INSERT INTO "%1$s".tgt_policy_projects ("POLICY_ID", "PROJECT_ID")
        SELECT DISTINCT j."POLICY_ID", pm.canonical_id
          FROM "%1$s".src_policy_projects j
          JOIN "%1$s".tgt_policy p ON p."ID" = j."POLICY_ID"
          JOIN "%1$s".project_canonical_id_map pm ON pm.orig_id = j."PROJECT_ID"
        ON CONFLICT DO NOTHING
        """,
        """
        INSERT INTO "POLICY_PROJECTS" ("POLICY_ID", "PROJECT_ID")
        SELECT "POLICY_ID", "PROJECT_ID" FROM "%1$s".tgt_policy_projects
        """
    );

    /**
     * 1:1 migration of {@code NOTIFICATIONRULE_PROJECTS}. Rewrites NOTIFICATIONRULE_ID
     * through {@code notificationrule_canonical_id_map} and PROJECT_ID through
     * {@code project_canonical_id_map}. v4 allows NULL PROJECT_ID (semantic: rule matches
     * all projects); v5 preserves that. NULL PROJECT_ID rows are kept via LEFT JOIN.
     * v5 has no PK / unique index on this table, so dedup is on (rule, project) with
     * NULLs treated distinct via {@code DISTINCT} which already collapses identical NULL
     * rows.
     */
    private static final TableMigration NOTIFICATIONRULE_PROJECTS = new TableMigration(
        "NOTIFICATIONRULE_PROJECTS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_notificationrule_projects (
            "NOTIFICATIONRULE_ID" bigint NOT NULL
          , "PROJECT_ID"          bigint
        )
        """,
        """
        SELECT "NOTIFICATIONRULE_ID", "PROJECT_ID"
          FROM "%s"."NOTIFICATIONRULE_PROJECTS"
        """,
        List.of("NOTIFICATIONRULE_ID", "PROJECT_ID"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_notificationrule_projects;
        CREATE UNLOGGED TABLE "%1$s".tgt_notificationrule_projects (
            "NOTIFICATIONRULE_ID" bigint NOT NULL
          , "PROJECT_ID"          bigint
        );
        INSERT INTO "%1$s".tgt_notificationrule_projects ("NOTIFICATIONRULE_ID", "PROJECT_ID")
        SELECT DISTINCT rm.canonical_id, pm.canonical_id
          FROM "%1$s".src_notificationrule_projects j
          JOIN "%1$s".notificationrule_canonical_id_map rm ON rm.orig_id = j."NOTIFICATIONRULE_ID"
          LEFT JOIN "%1$s".project_canonical_id_map pm ON pm.orig_id = j."PROJECT_ID"
        """,
        """
        INSERT INTO "NOTIFICATIONRULE_PROJECTS" ("NOTIFICATIONRULE_ID", "PROJECT_ID")
        SELECT "NOTIFICATIONRULE_ID", "PROJECT_ID" FROM "%1$s".tgt_notificationrule_projects
        """
    );

    /**
     * 1:1 migration of {@code PROJECT_METADATA}. PROJECT_ID is rewritten through
     * {@code project_canonical_id_map}. After rewrite, multiple v4 rows may collide on
     * the canonical PROJECT_ID (v5 enforces UNIQUE); keep the newest by v4 {@code ID}
     * via {@code ROW_NUMBER}. The additive v5 {@code TOOLS} column is NULL-filled.
     */
    private static final TableMigration PROJECT_METADATA = new TableMigration(
        "PROJECT_METADATA",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_project_metadata (
            "ID"         bigint NOT NULL
          , "AUTHORS"    text
          , "PROJECT_ID" bigint NOT NULL
          , "SUPPLIER"   text
        )
        """,
        """
        SELECT "ID"
             , "AUTHORS"
             , "PROJECT_ID"
             , "SUPPLIER"
          FROM "%s"."PROJECT_METADATA"
        """,
        List.of("ID", "AUTHORS", "PROJECT_ID", "SUPPLIER"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_project_metadata;
        CREATE UNLOGGED TABLE "%1$s".tgt_project_metadata (
            "ID"         bigint NOT NULL PRIMARY KEY
          , "PROJECT_ID" bigint NOT NULL UNIQUE
          , "SUPPLIER"   text
          , "AUTHORS"    text
          , "TOOLS"      text
        );
        WITH rewritten AS (
            SELECT m."ID"
                 , pm.canonical_id AS "PROJECT_ID"
                 , m."SUPPLIER"
                 , m."AUTHORS"
              FROM "%1$s".src_project_metadata m
              JOIN "%1$s".project_canonical_id_map pm ON pm.orig_id = m."PROJECT_ID"
        ), ranked AS (
            SELECT "ID"
                 , "PROJECT_ID"
                 , "SUPPLIER"
                 , "AUTHORS"
                 , ROW_NUMBER() OVER (PARTITION BY "PROJECT_ID" ORDER BY "ID" DESC) AS rn
              FROM rewritten
        )
        INSERT INTO "%1$s".tgt_project_metadata (
            "ID"
          , "PROJECT_ID"
          , "SUPPLIER"
          , "AUTHORS"
          , "TOOLS"
        )
        SELECT "ID"
             , "PROJECT_ID"
             , "SUPPLIER"
             , "AUTHORS"
             , NULL
          FROM ranked
         WHERE rn = 1
        """,
        """
        INSERT INTO "PROJECT_METADATA" (
            "ID"
          , "PROJECT_ID"
          , "SUPPLIER"
          , "AUTHORS"
          , "TOOLS"
        )
        SELECT "ID"
             , "PROJECT_ID"
             , "SUPPLIER"
             , "AUTHORS"
             , "TOOLS"
          FROM "%1$s".tgt_project_metadata
        """
    );

    /**
     * 1:1 migration of {@code PROJECT_ACCESS_TEAMS}. Rewrites PROJECT_ID through
     * {@code project_canonical_id_map} and TEAM_ID through {@code team_canonical_id_map}.
     * v4 allows NULL TEAM_ID; v5 tightens to NOT NULL, so those rows are dropped via
     * INNER JOIN. Dedup on the composite key.
     */
    private static final TableMigration PROJECT_ACCESS_TEAMS = new TableMigration(
        "PROJECT_ACCESS_TEAMS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_project_access_teams (
            "PROJECT_ID" bigint NOT NULL
          , "TEAM_ID"    bigint
        )
        """,
        """
        SELECT "PROJECT_ID", "TEAM_ID"
          FROM "%s"."PROJECT_ACCESS_TEAMS"
        """,
        List.of("PROJECT_ID", "TEAM_ID"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_project_access_teams;
        CREATE UNLOGGED TABLE "%1$s".tgt_project_access_teams (
            "PROJECT_ID" bigint NOT NULL
          , "TEAM_ID"    bigint NOT NULL
          , PRIMARY KEY ("PROJECT_ID", "TEAM_ID")
        );
        INSERT INTO "%1$s".tgt_project_access_teams ("PROJECT_ID", "TEAM_ID")
        SELECT DISTINCT pm.canonical_id, tm.canonical_id
          FROM "%1$s".src_project_access_teams j
          JOIN "%1$s".project_canonical_id_map pm ON pm.orig_id = j."PROJECT_ID"
          JOIN "%1$s".team_canonical_id_map tm ON tm.orig_id = j."TEAM_ID"
         WHERE j."TEAM_ID" IS NOT NULL
        ON CONFLICT DO NOTHING
        """,
        """
        INSERT INTO "PROJECT_ACCESS_TEAMS" ("PROJECT_ID", "TEAM_ID")
        SELECT "PROJECT_ID", "TEAM_ID" FROM "%1$s".tgt_project_access_teams
        """
    );

    /**
     * Derived {@code PROJECT_ACCESS_USERS} per pipeline §7.5 / schema-changes §7.5. Built
     * from {@code tgt_project_access_teams ⋈ tgt_users_teams} on {@code TEAM_ID}. v4 has no
     * source table for this; v5 maintains it via triggers, which the load phase disables to
     * allow the direct backfill.
     */
    private static final TableMigration PROJECT_ACCESS_USERS = new TableMigration(
        "PROJECT_ACCESS_USERS",
        null, null, null,
        """
        DROP TABLE IF EXISTS "%1$s".tgt_project_access_users;
        CREATE UNLOGGED TABLE "%1$s".tgt_project_access_users (
            "PROJECT_ID" bigint NOT NULL
          , "USER_ID"    bigint NOT NULL
          , PRIMARY KEY ("PROJECT_ID", "USER_ID")
        );
        INSERT INTO "%1$s".tgt_project_access_users ("PROJECT_ID", "USER_ID")
        SELECT DISTINCT pat."PROJECT_ID", ut."USER_ID"
          FROM "%1$s".tgt_project_access_teams pat
          JOIN "%1$s".tgt_users_teams ut ON ut."TEAM_ID" = pat."TEAM_ID"
        ON CONFLICT DO NOTHING
        """,
        """
        INSERT INTO "PROJECT_ACCESS_USERS" ("PROJECT_ID", "USER_ID")
        SELECT "PROJECT_ID", "USER_ID" FROM "%1$s".tgt_project_access_users
        ON CONFLICT DO NOTHING
        """
    );

    /**
     * 1:1 migration of {@code PROJECTS_TAGS}. Rewrites PROJECT_ID through
     * {@code project_canonical_id_map} and TAG_ID through {@code tag_canonical_id_map}.
     * v4 PK is {@code (TAG_ID, PROJECT_ID)}; v5 reorders to {@code (PROJECT_ID, TAG_ID)}.
     * Dedup on the composite key.
     */
    private static final TableMigration PROJECTS_TAGS = new TableMigration(
        "PROJECTS_TAGS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_projects_tags (
            "PROJECT_ID" bigint NOT NULL
          , "TAG_ID"     bigint NOT NULL
        )
        """,
        """
        SELECT "PROJECT_ID", "TAG_ID"
          FROM "%s"."PROJECTS_TAGS"
        """,
        List.of("PROJECT_ID", "TAG_ID"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_projects_tags;
        CREATE UNLOGGED TABLE "%1$s".tgt_projects_tags (
            "PROJECT_ID" bigint NOT NULL
          , "TAG_ID"     bigint NOT NULL
          , PRIMARY KEY ("PROJECT_ID", "TAG_ID")
        );
        INSERT INTO "%1$s".tgt_projects_tags ("PROJECT_ID", "TAG_ID")
        SELECT DISTINCT pm.canonical_id, tm.canonical_id
          FROM "%1$s".src_projects_tags j
          JOIN "%1$s".project_canonical_id_map pm ON pm.orig_id = j."PROJECT_ID"
          JOIN "%1$s".tag_canonical_id_map tm ON tm.orig_id = j."TAG_ID"
        ON CONFLICT DO NOTHING
        """,
        """
        INSERT INTO "PROJECTS_TAGS" ("PROJECT_ID", "TAG_ID")
        SELECT "PROJECT_ID", "TAG_ID" FROM "%1$s".tgt_projects_tags
        """
    );

    /**
     * COMPONENT migration. Per schema-changes:
     * §5.1 {@code CLASSIFIER}: {@code NONE} and any value outside the v5 enum set become NULL.
     * §5.8 {@code SCOPE}: v4 column passes through; v5 CHECK allows
     * {@code (NULL, REQUIRED, OPTIONAL, EXCLUDED)}. Values outside that set are mapped to NULL.
     * §6.1 UUID conversion + probe; malformed rows go to {@code probe_invalid_uuids} and are
     * excluded from {@code tgt_component}.
     * §6.2 {@code DIRECT_DEPENDENCIES}: text → JSONB via {@code try_jsonb}; NULL on parse
     * failure (rows are kept).
     * §6.7 PURL / PURLCOORDINATES pass-through (v5 widens to varchar(1024)).
     * Builds an identity {@code component_canonical_id_map} (no data-driven dedup): every
     * valid-UUID row maps to itself. Downstream join tables use this map to drop rows whose
     * COMPONENT was excluded for a malformed UUID. {@code PROJECT_ID} is rewritten through
     * {@code project_canonical_id_map}; {@code PARENT_COMPONENT_ID} is rewritten through
     * {@code component_canonical_id_map} via LEFT JOIN (orphaned parents become NULL).
     */
    private static final TableMigration COMPONENT = new TableMigration(
        "COMPONENT",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_component (
            "ID"                  bigint NOT NULL
          , "AUTHORS"             text
          , "BLAKE2B_256"         varchar(64)
          , "BLAKE2B_384"         varchar(96)
          , "BLAKE2B_512"         varchar(128)
          , "BLAKE3"              varchar(255)
          , "CLASSIFIER"          varchar(255)
          , "COPYRIGHT"           varchar(1024)
          , "CPE"                 varchar(255)
          , "DESCRIPTION"         varchar(1024)
          , "DIRECT_DEPENDENCIES" text
          , "EXTENSION"           varchar(255)
          , "EXTERNAL_REFERENCES" bytea
          , "FILENAME"            varchar(255)
          , "GROUP"               varchar(255)
          , "INTERNAL"            boolean
          , "LAST_RISKSCORE"      double precision
          , "LICENSE"             varchar(255)
          , "LICENSE_EXPRESSION"  text
          , "LICENSE_URL"         varchar(255)
          , "MD5"                 varchar(32)
          , "NAME"                varchar(255) NOT NULL
          , "TEXT"                text
          , "PARENT_COMPONENT_ID" bigint
          , "PROJECT_ID"          bigint NOT NULL
          , "PUBLISHER"           varchar(255)
          , "PURL"                varchar(786)
          , "PURLCOORDINATES"     varchar(786)
          , "LICENSE_ID"          bigint
          , "SCOPE"               varchar(255)
          , "SHA1"                varchar(40)
          , "SHA_256"             varchar(64)
          , "SHA_384"             varchar(96)
          , "SHA3_256"            varchar(64)
          , "SHA3_384"            varchar(96)
          , "SHA3_512"            varchar(128)
          , "SHA_512"             varchar(128)
          , "SUPPLIER"            text
          , "SWIDTAGID"           varchar(255)
          , "UUID"                varchar(36) NOT NULL
          , "VERSION"             varchar(255)
        )
        """,
        """
        SELECT "ID"
             , "AUTHORS"
             , "BLAKE2B_256"
             , "BLAKE2B_384"
             , "BLAKE2B_512"
             , "BLAKE3"
             , "CLASSIFIER"
             , "COPYRIGHT"
             , "CPE"
             , "DESCRIPTION"
             , "DIRECT_DEPENDENCIES"
             , "EXTENSION"
             , "EXTERNAL_REFERENCES"
             , "FILENAME"
             , "GROUP"
             , "INTERNAL"
             , "LAST_RISKSCORE"
             , "LICENSE"
             , "LICENSE_EXPRESSION"
             , "LICENSE_URL"
             , "MD5"
             , "NAME"
             , "TEXT"
             , "PARENT_COMPONENT_ID"
             , "PROJECT_ID"
             , "PUBLISHER"
             , "PURL"
             , "PURLCOORDINATES"
             , "LICENSE_ID"
             , "SCOPE"
             , "SHA1"
             , "SHA_256"
             , "SHA_384"
             , "SHA3_256"
             , "SHA3_384"
             , "SHA3_512"
             , "SHA_512"
             , "SUPPLIER"
             , "SWIDTAGID"
             , "UUID"
             , "VERSION"
          FROM "%s"."COMPONENT"
         ORDER BY "ID"
        """,
        List.of("ID", "AUTHORS", "BLAKE2B_256", "BLAKE2B_384", "BLAKE2B_512", "BLAKE3",
            "CLASSIFIER", "COPYRIGHT", "CPE", "DESCRIPTION", "DIRECT_DEPENDENCIES",
            "EXTENSION", "EXTERNAL_REFERENCES", "FILENAME", "GROUP", "INTERNAL",
            "LAST_RISKSCORE", "LICENSE", "LICENSE_EXPRESSION", "LICENSE_URL", "MD5",
            "NAME", "TEXT", "PARENT_COMPONENT_ID", "PROJECT_ID", "PUBLISHER", "PURL",
            "PURLCOORDINATES", "LICENSE_ID", "SCOPE", "SHA1", "SHA_256", "SHA_384",
            "SHA3_256", "SHA3_384", "SHA3_512", "SHA_512", "SUPPLIER", "SWIDTAGID",
            "UUID", "VERSION"),
        """
        INSERT INTO "%1$s".probe_invalid_uuids (table_name, orig_id, bad_uuid)
        SELECT 'COMPONENT', "ID", "UUID"
          FROM "%1$s".src_component
         WHERE "UUID" !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ON CONFLICT DO NOTHING;

        DROP TABLE IF EXISTS "%1$s".component_canonical_id_map;
        CREATE UNLOGGED TABLE "%1$s".component_canonical_id_map (
            orig_id      bigint NOT NULL PRIMARY KEY
          , canonical_id bigint NOT NULL
        );
        INSERT INTO "%1$s".component_canonical_id_map (orig_id, canonical_id)
        SELECT "ID", "ID"
          FROM "%1$s".src_component
         WHERE "UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';

        DROP TABLE IF EXISTS "%1$s".tgt_component;
        CREATE UNLOGGED TABLE "%1$s".tgt_component (
            "ID"                  bigint NOT NULL PRIMARY KEY
          , "AUTHORS"             text
          , "BLAKE2B_256"         varchar(64)
          , "BLAKE2B_384"         varchar(96)
          , "BLAKE2B_512"         varchar(128)
          , "BLAKE3"              varchar(255)
          , "CLASSIFIER"          varchar(255)
          , "COPYRIGHT"           varchar(1024)
          , "CPE"                 varchar(255)
          , "DESCRIPTION"         varchar(1024)
          , "DIRECT_DEPENDENCIES" jsonb
          , "EXTENSION"           varchar(255)
          , "EXTERNAL_REFERENCES" bytea
          , "FILENAME"            varchar(255)
          , "GROUP"               varchar(255)
          , "INTERNAL"            boolean
          , "LAST_RISKSCORE"      double precision
          , "LICENSE"             varchar(255)
          , "LICENSE_EXPRESSION"  text
          , "LICENSE_URL"         varchar(255)
          , "MD5"                 varchar(32)
          , "NAME"                varchar(255) NOT NULL
          , "TEXT"                text
          , "PARENT_COMPONENT_ID" bigint
          , "PROJECT_ID"          bigint NOT NULL
          , "PUBLISHER"           varchar(255)
          , "PURL"                varchar(1024)
          , "PURLCOORDINATES"     varchar(1024)
          , "LICENSE_ID"          bigint
          , "SCOPE"               varchar(255)
          , "SHA1"                varchar(40)
          , "SHA_256"             varchar(64)
          , "SHA_384"             varchar(96)
          , "SHA3_256"            varchar(64)
          , "SHA3_384"            varchar(96)
          , "SHA3_512"            varchar(128)
          , "SHA_512"             varchar(128)
          , "SUPPLIER"            text
          , "SWIDTAGID"           varchar(255)
          , "UUID"                uuid NOT NULL
          , "VERSION"             varchar(255)
        );
        INSERT INTO "%1$s".tgt_component (
            "ID"
          , "AUTHORS"
          , "BLAKE2B_256"
          , "BLAKE2B_384"
          , "BLAKE2B_512"
          , "BLAKE3"
          , "CLASSIFIER"
          , "COPYRIGHT"
          , "CPE"
          , "DESCRIPTION"
          , "DIRECT_DEPENDENCIES"
          , "EXTENSION"
          , "EXTERNAL_REFERENCES"
          , "FILENAME"
          , "GROUP"
          , "INTERNAL"
          , "LAST_RISKSCORE"
          , "LICENSE"
          , "LICENSE_EXPRESSION"
          , "LICENSE_URL"
          , "MD5"
          , "NAME"
          , "TEXT"
          , "PARENT_COMPONENT_ID"
          , "PROJECT_ID"
          , "PUBLISHER"
          , "PURL"
          , "PURLCOORDINATES"
          , "LICENSE_ID"
          , "SCOPE"
          , "SHA1"
          , "SHA_256"
          , "SHA_384"
          , "SHA3_256"
          , "SHA3_384"
          , "SHA3_512"
          , "SHA_512"
          , "SUPPLIER"
          , "SWIDTAGID"
          , "UUID"
          , "VERSION"
        )
        SELECT c."ID"
             , c."AUTHORS"
             , c."BLAKE2B_256"
             , c."BLAKE2B_384"
             , c."BLAKE2B_512"
             , c."BLAKE3"
             , CASE WHEN c."CLASSIFIER" IN ( 'APPLICATION','CONTAINER','CRYPTOGRAPHIC_ASSET','DATA','DEVICE', 'DEVICE_DRIVER','FILE','FIRMWARE','FRAMEWORK','LIBRARY', 'MACHINE_LEARNING_MODEL','OPERATING_SYSTEM','PLATFORM'
                   ) THEN c."CLASSIFIER"
                   ELSE NULL
               END AS "CLASSIFIER",
               c."COPYRIGHT",
               c."CPE",
               c."DESCRIPTION",
               "%1$s".try_jsonb(c."DIRECT_DEPENDENCIES") AS "DIRECT_DEPENDENCIES",
               c."EXTENSION",
               c."EXTERNAL_REFERENCES",
               c."FILENAME",
               c."GROUP",
               c."INTERNAL",
               c."LAST_RISKSCORE",
               c."LICENSE",
               c."LICENSE_EXPRESSION",
               c."LICENSE_URL",
               c."MD5",
               c."NAME",
               c."TEXT",
               parent_map.canonical_id AS "PARENT_COMPONENT_ID",
               project_map.canonical_id AS "PROJECT_ID",
               c."PUBLISHER",
               c."PURL",
               c."PURLCOORDINATES",
               license_map."ID" AS "LICENSE_ID",
               CASE WHEN c."SCOPE" IN ('REQUIRED','OPTIONAL','EXCLUDED') THEN c."SCOPE" ELSE NULL END AS "SCOPE",
               c."SHA1",
               c."SHA_256",
               c."SHA_384",
               c."SHA3_256",
               c."SHA3_384",
               c."SHA3_512",
               c."SHA_512",
               c."SUPPLIER",
               c."SWIDTAGID",
               c."UUID"::uuid AS "UUID",
               c."VERSION"
          FROM "%1$s".src_component c
          JOIN "%1$s".component_canonical_id_map m
            ON m.orig_id = c."ID"
          JOIN "%1$s".project_canonical_id_map project_map
            ON project_map.orig_id = c."PROJECT_ID"
          LEFT JOIN "%1$s".component_canonical_id_map parent_map
            ON parent_map.orig_id = c."PARENT_COMPONENT_ID"
          LEFT JOIN "%1$s".tgt_license license_map
            ON license_map."ID" = c."LICENSE_ID"
        """,
        """
        INSERT INTO "COMPONENT" (
            "ID"
          , "AUTHORS"
          , "BLAKE2B_256"
          , "BLAKE2B_384"
          , "BLAKE2B_512"
          , "BLAKE3"
          , "CLASSIFIER"
          , "COPYRIGHT"
          , "CPE"
          , "DESCRIPTION"
          , "DIRECT_DEPENDENCIES"
          , "EXTENSION"
          , "EXTERNAL_REFERENCES"
          , "FILENAME"
          , "GROUP"
          , "INTERNAL"
          , "LAST_RISKSCORE"
          , "LICENSE"
          , "LICENSE_EXPRESSION"
          , "LICENSE_URL"
          , "MD5"
          , "NAME"
          , "TEXT"
          , "PARENT_COMPONENT_ID"
          , "PROJECT_ID"
          , "PUBLISHER"
          , "PURL"
          , "PURLCOORDINATES"
          , "LICENSE_ID"
          , "SCOPE"
          , "SHA1"
          , "SHA_256"
          , "SHA_384"
          , "SHA3_256"
          , "SHA3_384"
          , "SHA3_512"
          , "SHA_512"
          , "SUPPLIER"
          , "SWIDTAGID"
          , "UUID"
          , "VERSION"
        )
        SELECT "ID"
             , "AUTHORS"
             , "BLAKE2B_256"
             , "BLAKE2B_384"
             , "BLAKE2B_512"
             , "BLAKE3"
             , "CLASSIFIER"
             , "COPYRIGHT"
             , "CPE"
             , "DESCRIPTION"
             , "DIRECT_DEPENDENCIES"
             , "EXTENSION"
             , "EXTERNAL_REFERENCES"
             , "FILENAME"
             , "GROUP"
             , "INTERNAL"
             , "LAST_RISKSCORE"
             , "LICENSE"
             , "LICENSE_EXPRESSION"
             , "LICENSE_URL"
             , "MD5"
             , "NAME"
             , "TEXT"
             , "PARENT_COMPONENT_ID"
             , "PROJECT_ID"
             , "PUBLISHER"
             , "PURL"
             , "PURLCOORDINATES"
             , "LICENSE_ID"
             , "SCOPE"
             , "SHA1"
             , "SHA_256"
             , "SHA_384"
             , "SHA3_256"
             , "SHA3_384"
             , "SHA3_512"
             , "SHA_512"
             , "SUPPLIER"
             , "SWIDTAGID"
             , "UUID"
             , "VERSION"
          FROM "%1$s".tgt_component
        """
    );

    /**
     * SERVICECOMPONENT migration. v5 keeps the same column set as v4; only UUID widens to
     * native {@code uuid}. The four Java-serialized blob columns
     * ({@code DATA}, {@code ENDPOINTS}, {@code EXTERNAL_REFERENCES}, {@code PROVIDER_ID})
     * are pure byte pass-through.
     * §6.1 UUID conversion + probe; malformed rows go to {@code probe_invalid_uuids} and are
     * excluded from {@code tgt_servicecomponent}. Builds an identity
     * {@code servicecomponent_canonical_id_map} for valid-UUID rows.
     * {@code PROJECT_ID} is rewritten through {@code project_canonical_id_map};
     * {@code PARENT_SERVICECOMPONENT_ID} is rewritten through
     * {@code servicecomponent_canonical_id_map} via LEFT JOIN (orphaned parents become NULL).
     */
    private static final TableMigration SERVICECOMPONENT = new TableMigration(
        "SERVICECOMPONENT",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_servicecomponent (
            "ID"                         bigint NOT NULL
          , "AUTHENTICATED"              boolean
          , "X_TRUST_BOUNDARY"           boolean
          , "DATA"                       bytea
          , "DESCRIPTION"                varchar(1024)
          , "ENDPOINTS"                  bytea
          , "EXTERNAL_REFERENCES"        bytea
          , "GROUP"                      varchar(255)
          , "LAST_RISKSCORE"             double precision NOT NULL
          , "NAME"                       varchar(255) NOT NULL
          , "TEXT"                       text
          , "PARENT_SERVICECOMPONENT_ID" bigint
          , "PROJECT_ID"                 bigint NOT NULL
          , "PROVIDER_ID"                bytea
          , "UUID"                       varchar(36) NOT NULL
          , "VERSION"                    varchar(255)
        )
        """,
        """
        SELECT "ID"
             , "AUTHENTICATED"
             , "X_TRUST_BOUNDARY"
             , "DATA"
             , "DESCRIPTION"
             , "ENDPOINTS"
             , "EXTERNAL_REFERENCES"
             , "GROUP"
             , "LAST_RISKSCORE"
             , "NAME"
             , "TEXT"
             , "PARENT_SERVICECOMPONENT_ID"
             , "PROJECT_ID"
             , "PROVIDER_ID"
             , "UUID"
             , "VERSION"
          FROM "%s"."SERVICECOMPONENT"
         ORDER BY "ID"
        """,
        List.of("ID", "AUTHENTICATED", "X_TRUST_BOUNDARY", "DATA", "DESCRIPTION",
            "ENDPOINTS", "EXTERNAL_REFERENCES", "GROUP", "LAST_RISKSCORE", "NAME",
            "TEXT", "PARENT_SERVICECOMPONENT_ID", "PROJECT_ID", "PROVIDER_ID",
            "UUID", "VERSION"),
        """
        INSERT INTO "%1$s".probe_invalid_uuids (table_name, orig_id, bad_uuid)
        SELECT 'SERVICECOMPONENT', "ID", "UUID"
          FROM "%1$s".src_servicecomponent
         WHERE "UUID" !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ON CONFLICT DO NOTHING;

        DROP TABLE IF EXISTS "%1$s".servicecomponent_canonical_id_map;
        CREATE UNLOGGED TABLE "%1$s".servicecomponent_canonical_id_map (
            orig_id      bigint NOT NULL PRIMARY KEY
          , canonical_id bigint NOT NULL
        );
        INSERT INTO "%1$s".servicecomponent_canonical_id_map (orig_id, canonical_id)
        SELECT "ID", "ID"
          FROM "%1$s".src_servicecomponent
         WHERE "UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';

        DROP TABLE IF EXISTS "%1$s".tgt_servicecomponent;
        CREATE UNLOGGED TABLE "%1$s".tgt_servicecomponent (
            "ID"                         bigint NOT NULL PRIMARY KEY
          , "AUTHENTICATED"              boolean
          , "X_TRUST_BOUNDARY"           boolean
          , "DATA"                       bytea
          , "DESCRIPTION"                varchar(1024)
          , "ENDPOINTS"                  bytea
          , "EXTERNAL_REFERENCES"        bytea
          , "GROUP"                      varchar(255)
          , "LAST_RISKSCORE"             double precision NOT NULL
          , "NAME"                       varchar(255) NOT NULL
          , "TEXT"                       text
          , "PARENT_SERVICECOMPONENT_ID" bigint
          , "PROJECT_ID"                 bigint NOT NULL
          , "PROVIDER_ID"                bytea
          , "UUID"                       uuid NOT NULL
          , "VERSION"                    varchar(255)
        );
        INSERT INTO "%1$s".tgt_servicecomponent (
            "ID"
          , "AUTHENTICATED"
          , "X_TRUST_BOUNDARY"
          , "DATA"
          , "DESCRIPTION"
          , "ENDPOINTS"
          , "EXTERNAL_REFERENCES"
          , "GROUP"
          , "LAST_RISKSCORE"
          , "NAME"
          , "TEXT"
          , "PARENT_SERVICECOMPONENT_ID"
          , "PROJECT_ID"
          , "PROVIDER_ID"
          , "UUID"
          , "VERSION"
        )
        SELECT s."ID"
             , s."AUTHENTICATED"
             , s."X_TRUST_BOUNDARY"
             , s."DATA"
             , s."DESCRIPTION"
             , s."ENDPOINTS"
             , s."EXTERNAL_REFERENCES"
             , s."GROUP"
             , s."LAST_RISKSCORE"
             , s."NAME"
             , s."TEXT"
             , parent_map.canonical_id AS "PARENT_SERVICECOMPONENT_ID"
             , project_map.canonical_id AS "PROJECT_ID"
             , s."PROVIDER_ID"
             , s."UUID"::uuid AS "UUID"
             , s."VERSION"
          FROM "%1$s".src_servicecomponent s
          JOIN "%1$s".servicecomponent_canonical_id_map m
            ON m.orig_id = s."ID"
          JOIN "%1$s".project_canonical_id_map project_map
            ON project_map.orig_id = s."PROJECT_ID"
          LEFT JOIN "%1$s".servicecomponent_canonical_id_map parent_map
            ON parent_map.orig_id = s."PARENT_SERVICECOMPONENT_ID"
        """,
        """
        INSERT INTO "SERVICECOMPONENT" (
            "ID"
          , "AUTHENTICATED"
          , "X_TRUST_BOUNDARY"
          , "DATA"
          , "DESCRIPTION"
          , "ENDPOINTS"
          , "EXTERNAL_REFERENCES"
          , "GROUP"
          , "LAST_RISKSCORE"
          , "NAME"
          , "TEXT"
          , "PARENT_SERVICECOMPONENT_ID"
          , "PROJECT_ID"
          , "PROVIDER_ID"
          , "UUID"
          , "VERSION"
        )
        SELECT "ID"
             , "AUTHENTICATED"
             , "X_TRUST_BOUNDARY"
             , "DATA"
             , "DESCRIPTION"
             , "ENDPOINTS"
             , "EXTERNAL_REFERENCES"
             , "GROUP"
             , "LAST_RISKSCORE"
             , "NAME"
             , "TEXT"
             , "PARENT_SERVICECOMPONENT_ID"
             , "PROJECT_ID"
             , "PROVIDER_ID"
             , "UUID"
             , "VERSION"
          FROM "%1$s".tgt_servicecomponent
        """
    );

    /**
     * Source-only v4 {@code REPOSITORY_META_COMPONENT}. No 1:1 v5 counterpart; consumed by
     * the derived {@code PACKAGE_METADATA} transform per schema-changes §7.7.
     */
    private static final TableMigration REPOSITORY_META_COMPONENT = new TableMigration(
        "REPOSITORY_META_COMPONENT",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_repository_meta_component (
            "ID"              bigint NOT NULL
          , "LAST_CHECK"      timestamptz NOT NULL
          , "LATEST_VERSION"  varchar(255) NOT NULL
          , "NAME"            varchar(255) NOT NULL
          , "NAMESPACE"       varchar(255)
          , "PUBLISHED"       timestamptz
          , "REPOSITORY_TYPE" varchar(255) NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "LAST_CHECK"
             , "LATEST_VERSION"
             , "NAME"
             , "NAMESPACE"
             , "PUBLISHED"
             , "REPOSITORY_TYPE"
          FROM "%s"."REPOSITORY_META_COMPONENT"
         ORDER BY "ID"
        """,
        List.of("ID", "LAST_CHECK", "LATEST_VERSION", "NAME", "NAMESPACE",
            "PUBLISHED", "REPOSITORY_TYPE"),
        null,
        null
    );

    /**
     * Derived {@code PACKAGE_METADATA} per schema-changes §7.7 / Liquibase changeset
     * v5.7.0-52. Joins {@code REPOSITORY_META_COMPONENT} to {@code COMPONENT} on
     * {@code (NAME, NAMESPACE/GROUP)} with symmetric NULL match and a PURL scheme match by
     * repository type. Output {@code PURL} is the PURL coordinates with the {@code @version}
     * suffix stripped. Rows whose resulting PURL contains any of {@code @ ? & #} are skipped
     * to satisfy the v5 {@code PACKAGE_METADATA_PURL_CHECK} constraint. {@code DISTINCT ON
     * (PURL)} keeps the newest {@code LAST_CHECK} per PURL. {@code RESOLVED_BY},
     * {@code RESOLVED_FROM}, {@code LATEST_VERSION_PUBLISHED_AT} have no v4 source and are
     * left NULL, matching the Liquibase changeset which only projects PURL, LATEST_VERSION,
     * and RESOLVED_AT (= LAST_CHECK).
     */
    private static final TableMigration PACKAGE_METADATA = new TableMigration(
        "PACKAGE_METADATA",
        null, null, null,
        """
        DROP TABLE IF EXISTS "%1$s".tgt_package_metadata;
        CREATE UNLOGGED TABLE "%1$s".tgt_package_metadata (
            "PURL"                        text NOT NULL
          , "LATEST_VERSION"              text
          , "LATEST_VERSION_PUBLISHED_AT" timestamptz
          , "RESOLVED_BY"                 text
          , "RESOLVED_FROM"               text
          , "RESOLVED_AT"                 timestamptz NOT NULL
          , PRIMARY KEY ("PURL")
        );

        INSERT INTO "%1$s".tgt_package_metadata (
            "PURL"
          , "LATEST_VERSION"
          , "LATEST_VERSION_PUBLISHED_AT"
          , "RESOLVED_BY"
          , "RESOLVED_FROM"
          , "RESOLVED_AT"
        )
        SELECT DISTINCT ON (t."PURL") t."PURL"
             , t."LATEST_VERSION"
             , NULL
             , NULL
             , NULL
             , t."LAST_CHECK"
          FROM (
            SELECT split_part(c."PURLCOORDINATES", '@', 1) AS "PURL"
                 , rmc."LATEST_VERSION"
                 , rmc."LAST_CHECK"
              FROM "%1$s".src_repository_meta_component rmc
              JOIN "%1$s".src_component c
                ON c."NAME" = rmc."NAME"
               AND (c."GROUP" = rmc."NAMESPACE"
                    OR (c."GROUP" IS NULL AND rmc."NAMESPACE" IS NULL))
               AND LOWER(c."PURL") LIKE ('pkg:' || LOWER(rmc."REPOSITORY_TYPE") || '/%%')
          ) t
         WHERE t."PURL" NOT LIKE '%%@%%'
           AND t."PURL" NOT LIKE '%%?%%'
           AND t."PURL" NOT LIKE '%%&%%'
           AND t."PURL" NOT LIKE '%%#%%'
         ORDER BY t."PURL", t."LAST_CHECK" DESC NULLS LAST
        """,
        """
        INSERT INTO "PACKAGE_METADATA" (
            "PURL"
          , "LATEST_VERSION"
          , "LATEST_VERSION_PUBLISHED_AT"
          , "RESOLVED_BY"
          , "RESOLVED_FROM"
          , "RESOLVED_AT"
        )
        SELECT "PURL"
             , "LATEST_VERSION"
             , "LATEST_VERSION_PUBLISHED_AT"
             , "RESOLVED_BY"
             , "RESOLVED_FROM"
             , "RESOLVED_AT"
          FROM "%1$s".tgt_package_metadata
        """
    );

    /**
     * 1:1 migration of {@code APIKEY}. v4 has already run {@code ApiKeyMigrationChange}, so
     * {@code SECRET_HASH}, {@code PUBLIC_ID}, and {@code IS_LEGACY} are populated; there is
     * no plaintext column. No UUID, no FK rewrites. v5 IDs are preserved.
     */
    private static final TableMigration APIKEY = new TableMigration(
        "APIKEY",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_apikey (
            "ID"          bigint NOT NULL
          , "COMMENT"     varchar(255)
          , "CREATED"     timestamptz
          , "IS_LEGACY"   boolean NOT NULL
          , "LAST_USED"   timestamptz
          , "PUBLIC_ID"   varchar(8) NOT NULL
          , "SECRET_HASH" varchar(64) NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "COMMENT"
             , "CREATED"
             , "IS_LEGACY"
             , "LAST_USED"
             , "PUBLIC_ID"
             , "SECRET_HASH"
          FROM "%s"."APIKEY"
         ORDER BY "ID"
        """,
        List.of("ID", "COMMENT", "CREATED", "IS_LEGACY", "LAST_USED", "PUBLIC_ID", "SECRET_HASH"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_apikey;
        CREATE UNLOGGED TABLE "%1$s".tgt_apikey (
            "ID"          bigint NOT NULL PRIMARY KEY
          , "COMMENT"     varchar(255)
          , "CREATED"     timestamptz
          , "IS_LEGACY"   boolean NOT NULL
          , "LAST_USED"   timestamptz
          , "PUBLIC_ID"   varchar(8) NOT NULL
          , "SECRET_HASH" varchar(64) NOT NULL
        );
        INSERT INTO "%1$s".tgt_apikey (
            "ID"
          , "COMMENT"
          , "CREATED"
          , "IS_LEGACY"
          , "LAST_USED"
          , "PUBLIC_ID"
          , "SECRET_HASH"
        )
        SELECT "ID"
             , "COMMENT"
             , "CREATED"
             , "IS_LEGACY"
             , "LAST_USED"
             , "PUBLIC_ID"
             , "SECRET_HASH"
          FROM "%1$s".src_apikey
        """,
        """
        INSERT INTO "APIKEY" (
            "ID"
          , "COMMENT"
          , "CREATED"
          , "IS_LEGACY"
          , "LAST_USED"
          , "PUBLIC_ID"
          , "SECRET_HASH"
        )
        SELECT "ID"
             , "COMMENT"
             , "CREATED"
             , "IS_LEGACY"
             , "LAST_USED"
             , "PUBLIC_ID"
             , "SECRET_HASH"
          FROM "%1$s".tgt_apikey
        """
    );

    /**
     * Pure join migration of {@code APIKEYS_TEAMS}. {@code TEAM_ID} is rewritten through
     * {@code team_canonical_id_map}; {@code APIKEY_ID} passes through. v4 has no PK; v5 adds
     * composite PK {@code (TEAM_ID, APIKEY_ID)} and the staging tgt enforces it to dedup
     * any v4 duplicates.
     */
    private static final TableMigration APIKEYS_TEAMS = new TableMigration(
        "APIKEYS_TEAMS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_apikeys_teams (
            "TEAM_ID"   bigint NOT NULL
          , "APIKEY_ID" bigint NOT NULL
        )
        """,
        """
        SELECT "TEAM_ID", "APIKEY_ID"
          FROM "%s"."APIKEYS_TEAMS"
        """,
        List.of("TEAM_ID", "APIKEY_ID"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_apikeys_teams;
        CREATE UNLOGGED TABLE "%1$s".tgt_apikeys_teams (
            "TEAM_ID"   bigint NOT NULL
          , "APIKEY_ID" bigint NOT NULL
          , PRIMARY KEY ("TEAM_ID", "APIKEY_ID")
        );
        INSERT INTO "%1$s".tgt_apikeys_teams ("TEAM_ID", "APIKEY_ID")
        SELECT m.canonical_id, j."APIKEY_ID"
          FROM "%1$s".src_apikeys_teams j
          JOIN "%1$s".team_canonical_id_map m ON m.orig_id = j."TEAM_ID"
        ON CONFLICT DO NOTHING
        """,
        """
        INSERT INTO "APIKEYS_TEAMS" ("TEAM_ID", "APIKEY_ID")
        SELECT "TEAM_ID", "APIKEY_ID" FROM "%1$s".tgt_apikeys_teams
        """
    );

    /**
     * Pure join migration of {@code TEAMS_PERMISSIONS}. {@code TEAM_ID} is rewritten through
     * {@code team_canonical_id_map}; {@code PERMISSION_ID} is rewritten through
     * {@code permission_name_map} (rows whose v4 permission NAME has no v5 counterpart drop
     * via the inner join, mirroring {@code USERS_PERMISSIONS}). v4 has no PK; v5 adds
     * composite PK {@code (TEAM_ID, PERMISSION_ID)} and the staging tgt enforces it to dedup
     * any v4 duplicates.
     */
    private static final TableMigration TEAMS_PERMISSIONS = new TableMigration(
        "TEAMS_PERMISSIONS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_teams_permissions (
            "TEAM_ID"       bigint NOT NULL
          , "PERMISSION_ID" bigint NOT NULL
        )
        """,
        """
        SELECT "TEAM_ID", "PERMISSION_ID"
          FROM "%s"."TEAMS_PERMISSIONS"
        """,
        List.of("TEAM_ID", "PERMISSION_ID"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_teams_permissions;
        CREATE UNLOGGED TABLE "%1$s".tgt_teams_permissions (
            "TEAM_ID"       bigint NOT NULL
          , "PERMISSION_ID" bigint NOT NULL
          , PRIMARY KEY ("TEAM_ID", "PERMISSION_ID")
        );
        INSERT INTO "%1$s".tgt_teams_permissions ("TEAM_ID", "PERMISSION_ID")
        SELECT tm.canonical_id, pm.new_id
          FROM "%1$s".src_teams_permissions j
          JOIN "%1$s".team_canonical_id_map tm ON tm.orig_id = j."TEAM_ID"
          JOIN "%1$s".permission_name_map  pm ON pm.orig_id = j."PERMISSION_ID"
        ON CONFLICT DO NOTHING;

        -- Implication fan-out: see the matching USERS_PERMISSIONS step. v4 ACCESS_MANAGEMENT
        -- carried implicit portfolio-access-control bypass; v5 split that into
        -- PORTFOLIO_ACCESS_CONTROL_BYPASS (v5.6.0-31). Grant it to every team that holds
        -- ACCESS_MANAGEMENT in v4.
        INSERT INTO "%1$s".tgt_teams_permissions ("TEAM_ID", "PERMISSION_ID")
        SELECT DISTINCT tp."TEAM_ID", (SELECT "ID" FROM "PERMISSION" WHERE "NAME" = 'PORTFOLIO_ACCESS_CONTROL_BYPASS')
          FROM "%1$s".tgt_teams_permissions tp
          JOIN "PERMISSION" p ON p."ID" = tp."PERMISSION_ID"
         WHERE p."NAME" = 'ACCESS_MANAGEMENT'
        ON CONFLICT DO NOTHING
        """,
        """
        INSERT INTO "TEAMS_PERMISSIONS" ("TEAM_ID", "PERMISSION_ID")
        SELECT "TEAM_ID", "PERMISSION_ID" FROM "%1$s".tgt_teams_permissions
        """
    );

    /**
     * 1:1 migration of {@code MAPPEDLDAPGROUP}. {@code TEAM_ID} is rewritten through
     * {@code team_canonical_id_map}. UUID stays {@code varchar(36)} in v5 (a straggler that
     * did not convert to native uuid). v5 IDs are preserved.
     */
    private static final TableMigration MAPPEDLDAPGROUP = new TableMigration(
        "MAPPEDLDAPGROUP",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_mappedldapgroup (
            "ID"      bigint NOT NULL
          , "DN"      varchar(1024) NOT NULL
          , "TEAM_ID" bigint NOT NULL
          , "UUID"    varchar(36) NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "DN"
             , "TEAM_ID"
             , "UUID"
          FROM "%s"."MAPPEDLDAPGROUP"
         ORDER BY "ID"
        """,
        List.of("ID", "DN", "TEAM_ID", "UUID"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_mappedldapgroup;
        CREATE UNLOGGED TABLE "%1$s".tgt_mappedldapgroup (
            "ID"      bigint NOT NULL PRIMARY KEY
          , "DN"      varchar(1024) NOT NULL
          , "TEAM_ID" bigint NOT NULL
          , "UUID"    varchar(36) NOT NULL
        );
        INSERT INTO "%1$s".tgt_mappedldapgroup (
            "ID"
          , "DN"
          , "TEAM_ID"
          , "UUID"
        )
        SELECT s."ID"
             , s."DN"
             , tm.canonical_id
             , s."UUID"
          FROM "%1$s".src_mappedldapgroup s
          JOIN "%1$s".team_canonical_id_map tm ON tm.orig_id = s."TEAM_ID"
        """,
        """
        INSERT INTO "MAPPEDLDAPGROUP" (
            "ID"
          , "DN"
          , "TEAM_ID"
          , "UUID"
        )
        SELECT "ID"
             , "DN"
             , "TEAM_ID"
             , "UUID" FROM "%1$s".tgt_mappedldapgroup
        """
    );

    /**
     * 1:1 migration of {@code MAPPEDOIDCGROUP}. {@code TEAM_ID} is rewritten through
     * {@code team_canonical_id_map} and {@code GROUP_ID} through
     * {@code oidcgroup_canonical_id_map}. UUID stays {@code varchar(36)} in v5 (straggler).
     * v5 IDs are preserved.
     */
    private static final TableMigration MAPPEDOIDCGROUP = new TableMigration(
        "MAPPEDOIDCGROUP",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_mappedoidcgroup (
            "ID"       bigint NOT NULL
          , "GROUP_ID" bigint NOT NULL
          , "TEAM_ID"  bigint NOT NULL
          , "UUID"     varchar(36) NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "GROUP_ID"
             , "TEAM_ID"
             , "UUID"
          FROM "%s"."MAPPEDOIDCGROUP"
         ORDER BY "ID"
        """,
        List.of("ID", "GROUP_ID", "TEAM_ID", "UUID"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_mappedoidcgroup;
        CREATE UNLOGGED TABLE "%1$s".tgt_mappedoidcgroup (
            "ID"       bigint NOT NULL PRIMARY KEY
          , "GROUP_ID" bigint NOT NULL
          , "TEAM_ID"  bigint NOT NULL
          , "UUID"     varchar(36) NOT NULL
        );
        INSERT INTO "%1$s".tgt_mappedoidcgroup (
            "ID"
          , "GROUP_ID"
          , "TEAM_ID"
          , "UUID"
        )
        SELECT s."ID"
             , gm.canonical_id
             , tm.canonical_id
             , s."UUID"
          FROM "%1$s".src_mappedoidcgroup s
          JOIN "%1$s".team_canonical_id_map     tm ON tm.orig_id = s."TEAM_ID"
          JOIN "%1$s".oidcgroup_canonical_id_map gm ON gm.orig_id = s."GROUP_ID"
        """,
        """
        INSERT INTO "MAPPEDOIDCGROUP" (
            "ID"
          , "GROUP_ID"
          , "TEAM_ID"
          , "UUID"
        )
        SELECT "ID"
             , "GROUP_ID"
             , "TEAM_ID"
             , "UUID" FROM "%1$s".tgt_mappedoidcgroup
        """
    );

    /**
     * VULNERABILITY migration. Per schema-changes:
     * §3 {@code EPSSSCORE} and {@code EPSSPERCENTILE} are removed in v5 (they moved to a new
     * {@code EPSS} table that the migrator does not populate). They are kept in src for column
     * order parity with the v4 dump, then dropped from tgt.
     * §6.1 UUID conversion + probe; malformed rows go to {@code probe_invalid_uuids} and are
     * excluded from {@code tgt_vulnerability}.
     * §6.3 {@code SEVERITY} cast to native enum {@code severity}. v4 already stores the canonical
     * set after {@code ComputeSeveritiesChange}; the cast surfaces any malformed value.
     * Builds an identity {@code vulnerability_canonical_id_map} for valid-UUID rows. Downstream
     * join tables INNER JOIN this map to drop rows pointing at malformed-UUID vulnerabilities.
     */
    private static final TableMigration VULNERABILITY = new TableMigration(
        "VULNERABILITY",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_vulnerability (
            "ID"                          bigint NOT NULL
          , "CREATED"                     timestamp with time zone
          , "CREDITS"                     text
          , "CVSSV2BASESCORE"             numeric
          , "CVSSV2EXPLOITSCORE"          numeric
          , "CVSSV2IMPACTSCORE"           numeric
          , "CVSSV2VECTOR"                varchar(255)
          , "CVSSV3BASESCORE"             numeric
          , "CVSSV3EXPLOITSCORE"          numeric
          , "CVSSV3IMPACTSCORE"           numeric
          , "CVSSV3VECTOR"                varchar(255)
          , "CVSSV4SCORE"                 numeric
          , "CVSSV4VECTOR"                varchar(255)
          , "CWES"                        varchar(255)
          , "DESCRIPTION"                 text
          , "DETAIL"                      text
          , "EPSSPERCENTILE"              numeric
          , "EPSSSCORE"                   numeric
          , "FRIENDLYVULNID"              varchar(255)
          , "OWASPRRBUSINESSIMPACTSCORE"  numeric
          , "OWASPRRLIKELIHOODSCORE"      numeric
          , "OWASPRRTECHNICALIMPACTSCORE" numeric
          , "OWASPRRVECTOR"               varchar(255)
          , "PATCHEDVERSIONS"             varchar(255)
          , "PUBLISHED"                   timestamp with time zone
          , "RECOMMENDATION"              text
          , "REFERENCES"                  text
          , "SEVERITY"                    varchar(255)
          , "SOURCE"                      varchar(255) NOT NULL
          , "SUBTITLE"                    varchar(255)
          , "TITLE"                       varchar(255)
          , "UPDATED"                     timestamp with time zone
          , "UUID"                        varchar(36) NOT NULL
          , "VULNID"                      varchar(255) NOT NULL
          , "VULNERABLEVERSIONS"          varchar(255)
        )
        """,
        """
        SELECT "ID"
             , "CREATED"
             , "CREDITS"
             , "CVSSV2BASESCORE"
             , "CVSSV2EXPLOITSCORE"
             , "CVSSV2IMPACTSCORE"
             , "CVSSV2VECTOR"
             , "CVSSV3BASESCORE"
             , "CVSSV3EXPLOITSCORE"
             , "CVSSV3IMPACTSCORE"
             , "CVSSV3VECTOR"
             , "CVSSV4SCORE"
             , "CVSSV4VECTOR"
             , "CWES"
             , "DESCRIPTION"
             , "DETAIL"
             , "EPSSPERCENTILE"
             , "EPSSSCORE"
             , "FRIENDLYVULNID"
             , "OWASPRRBUSINESSIMPACTSCORE"
             , "OWASPRRLIKELIHOODSCORE"
             , "OWASPRRTECHNICALIMPACTSCORE"
             , "OWASPRRVECTOR"
             , "PATCHEDVERSIONS"
             , "PUBLISHED"
             , "RECOMMENDATION"
             , "REFERENCES"
             , "SEVERITY"
             , "SOURCE"
             , "SUBTITLE"
             , "TITLE"
             , "UPDATED"
             , "UUID"
             , "VULNID"
             , "VULNERABLEVERSIONS"
          FROM "%s"."VULNERABILITY"
         ORDER BY "ID"
        """,
        List.of("ID", "CREATED", "CREDITS", "CVSSV2BASESCORE", "CVSSV2EXPLOITSCORE",
            "CVSSV2IMPACTSCORE", "CVSSV2VECTOR", "CVSSV3BASESCORE", "CVSSV3EXPLOITSCORE",
            "CVSSV3IMPACTSCORE", "CVSSV3VECTOR", "CVSSV4SCORE", "CVSSV4VECTOR", "CWES",
            "DESCRIPTION", "DETAIL", "EPSSPERCENTILE", "EPSSSCORE", "FRIENDLYVULNID",
            "OWASPRRBUSINESSIMPACTSCORE", "OWASPRRLIKELIHOODSCORE",
            "OWASPRRTECHNICALIMPACTSCORE", "OWASPRRVECTOR", "PATCHEDVERSIONS", "PUBLISHED",
            "RECOMMENDATION", "REFERENCES", "SEVERITY", "SOURCE", "SUBTITLE", "TITLE",
            "UPDATED", "UUID", "VULNID", "VULNERABLEVERSIONS"),
        """
        INSERT INTO "%1$s".probe_invalid_uuids (table_name, orig_id, bad_uuid)
        SELECT 'VULNERABILITY', "ID", "UUID"
          FROM "%1$s".src_vulnerability
         WHERE "UUID" !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ON CONFLICT DO NOTHING;

        DROP TABLE IF EXISTS "%1$s".vulnerability_canonical_id_map;
        CREATE UNLOGGED TABLE "%1$s".vulnerability_canonical_id_map (
            orig_id      bigint NOT NULL PRIMARY KEY
          , canonical_id bigint NOT NULL
        );
        INSERT INTO "%1$s".vulnerability_canonical_id_map (orig_id, canonical_id)
        SELECT "ID", "ID"
          FROM "%1$s".src_vulnerability
         WHERE "UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';

        DROP TABLE IF EXISTS "%1$s".tgt_vulnerability;
        CREATE UNLOGGED TABLE "%1$s".tgt_vulnerability (
            "ID"                          bigint NOT NULL PRIMARY KEY
          , "CREATED"                     timestamp with time zone
          , "CREDITS"                     text
          , "CVSSV2BASESCORE"             numeric
          , "CVSSV2EXPLOITSCORE"          numeric
          , "CVSSV2IMPACTSCORE"           numeric
          , "CVSSV2VECTOR"                varchar(255)
          , "CVSSV3BASESCORE"             numeric
          , "CVSSV3EXPLOITSCORE"          numeric
          , "CVSSV3IMPACTSCORE"           numeric
          , "CVSSV3VECTOR"                varchar(255)
          , "CVSSV4SCORE"                 numeric
          , "CVSSV4VECTOR"                varchar(255)
          , "CWES"                        varchar(255)
          , "DESCRIPTION"                 text
          , "DETAIL"                      text
          , "FRIENDLYVULNID"              varchar(255)
          , "OWASPRRBUSINESSIMPACTSCORE"  numeric
          , "OWASPRRLIKELIHOODSCORE"      numeric
          , "OWASPRRTECHNICALIMPACTSCORE" numeric
          , "OWASPRRVECTOR"               varchar(255)
          , "PATCHEDVERSIONS"             varchar(255)
          , "PUBLISHED"                   timestamp with time zone
          , "RECOMMENDATION"              text
          , "REFERENCES"                  text
          -- Stored as text + CHECK rather than the native "severity" enum so a target-side
          -- DROP SCHEMA public CASCADE (a common manual reset between load attempts) does
          -- not transitively drop this column. Keep the value list in sync with
          -- migration/.../V202605022031__init.sql.
          , "SEVERITY"                    varchar(255) CHECK ("SEVERITY" IN ('UNASSIGNED', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
          , "SOURCE"                      varchar(255) NOT NULL
          , "SUBTITLE"                    varchar(255)
          , "TITLE"                       varchar(255)
          , "UPDATED"                     timestamp with time zone
          , "UUID"                        uuid NOT NULL
          , "VULNID"                      varchar(255) NOT NULL
          , "VULNERABLEVERSIONS"          varchar(255)
        );
        INSERT INTO "%1$s".tgt_vulnerability (
            "ID"
          , "CREATED"
          , "CREDITS"
          , "CVSSV2BASESCORE"
          , "CVSSV2EXPLOITSCORE"
          , "CVSSV2IMPACTSCORE"
          , "CVSSV2VECTOR"
          , "CVSSV3BASESCORE"
          , "CVSSV3EXPLOITSCORE"
          , "CVSSV3IMPACTSCORE"
          , "CVSSV3VECTOR"
          , "CVSSV4SCORE"
          , "CVSSV4VECTOR"
          , "CWES"
          , "DESCRIPTION"
          , "DETAIL"
          , "FRIENDLYVULNID"
          , "OWASPRRBUSINESSIMPACTSCORE"
          , "OWASPRRLIKELIHOODSCORE"
          , "OWASPRRTECHNICALIMPACTSCORE"
          , "OWASPRRVECTOR"
          , "PATCHEDVERSIONS"
          , "PUBLISHED"
          , "RECOMMENDATION"
          , "REFERENCES"
          , "SEVERITY"
          , "SOURCE"
          , "SUBTITLE"
          , "TITLE"
          , "UPDATED"
          , "UUID"
          , "VULNID"
          , "VULNERABLEVERSIONS"
        )
        SELECT "ID"
             , "CREATED"
             , "CREDITS"
             , "CVSSV2BASESCORE"
             , "CVSSV2EXPLOITSCORE"
             , "CVSSV2IMPACTSCORE"
             , "CVSSV2VECTOR"
             , "CVSSV3BASESCORE"
             , "CVSSV3EXPLOITSCORE"
             , "CVSSV3IMPACTSCORE"
             , "CVSSV3VECTOR"
             , "CVSSV4SCORE"
             , "CVSSV4VECTOR"
             , "CWES"
             , "DESCRIPTION"
             , "DETAIL"
             , "FRIENDLYVULNID"
             , "OWASPRRBUSINESSIMPACTSCORE"
             , "OWASPRRLIKELIHOODSCORE"
             , "OWASPRRTECHNICALIMPACTSCORE"
             , "OWASPRRVECTOR"
             , "PATCHEDVERSIONS"
             , "PUBLISHED"
             , "RECOMMENDATION"
             , "REFERENCES"
             -- v4 allows NULL "SEVERITY"; treat that as the canonical UNASSIGNED sentinel
             -- so the v5 column is never NULL.
             , COALESCE("SEVERITY", 'UNASSIGNED')
             , "SOURCE"
             , "SUBTITLE"
             , "TITLE"
             , "UPDATED"
             , "UUID"::uuid
             , "VULNID"
             , "VULNERABLEVERSIONS"
          FROM "%1$s".src_vulnerability
         WHERE "UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        """,
        """
        INSERT INTO "VULNERABILITY" (
            "ID"
          , "CREATED"
          , "CREDITS"
          , "CVSSV2BASESCORE"
          , "CVSSV2EXPLOITSCORE"
          , "CVSSV2IMPACTSCORE"
          , "CVSSV2VECTOR"
          , "CVSSV3BASESCORE"
          , "CVSSV3EXPLOITSCORE"
          , "CVSSV3IMPACTSCORE"
          , "CVSSV3VECTOR"
          , "CVSSV4SCORE"
          , "CVSSV4VECTOR"
          , "CWES"
          , "DESCRIPTION"
          , "DETAIL"
          , "FRIENDLYVULNID"
          , "OWASPRRBUSINESSIMPACTSCORE"
          , "OWASPRRLIKELIHOODSCORE"
          , "OWASPRRTECHNICALIMPACTSCORE"
          , "OWASPRRVECTOR"
          , "PATCHEDVERSIONS"
          , "PUBLISHED"
          , "RECOMMENDATION"
          , "REFERENCES"
          , "SEVERITY"
          , "SOURCE"
          , "SUBTITLE"
          , "TITLE"
          , "UPDATED"
          , "UUID"
          , "VULNID"
          , "VULNERABLEVERSIONS"
        )
        SELECT "ID"
             , "CREATED"
             , "CREDITS"
             , "CVSSV2BASESCORE"
             , "CVSSV2EXPLOITSCORE"
             , "CVSSV2IMPACTSCORE"
             , "CVSSV2VECTOR"
             , "CVSSV3BASESCORE"
             , "CVSSV3EXPLOITSCORE"
             , "CVSSV3IMPACTSCORE"
             , "CVSSV3VECTOR"
             , "CVSSV4SCORE"
             , "CVSSV4VECTOR"
             , "CWES"
             , "DESCRIPTION"
             , "DETAIL"
             , "FRIENDLYVULNID"
             , "OWASPRRBUSINESSIMPACTSCORE"
             , "OWASPRRLIKELIHOODSCORE"
             , "OWASPRRTECHNICALIMPACTSCORE"
             , "OWASPRRVECTOR"
             , "PATCHEDVERSIONS"
             , "PUBLISHED"
             , "RECOMMENDATION"
             , "REFERENCES"
             , "SEVERITY"::severity
             , "SOURCE"
             , "SUBTITLE"
             , "TITLE"
             , "UPDATED"
             , "UUID"
             , "VULNID"
             , "VULNERABLEVERSIONS"
          FROM "%1$s".tgt_vulnerability
        """
    );

    /**
     * VULNERABLESOFTWARE migration. Per schema-changes:
     * §5.7 {@code PART}, {@code VENDOR}, {@code PRODUCT} are lowercased on import.
     * §6.1 UUID conversion + probe.
     * §6.7 {@code PURL} widens from v4 {@code varchar(255)} to v5 {@code varchar(1024)};
     * pass-through suffices.
     * Builds an identity {@code vulnerablesoftware_canonical_id_map} for valid-UUID rows
     * that are referenced by at least one vulnerability via the
     * {@code VULNERABLESOFTWARE_VULNERABILITIES} junction. Rows without a junction reference
     * are dropped per spec §"Intentional data loss" (orphans in v4 due to missing FK
     * constraints / GC). The {@code tgt_vulnerablesoftware} INSERT applies the same filter,
     * so downstream tables that INNER JOIN the canonical map (AFFECTEDVERSIONATTRIBUTION,
     * VULNERABLESOFTWARE_VULNERABILITIES) drop transitively-orphaned rows consistently.
     */
    private static final TableMigration VULNERABLESOFTWARE = new TableMigration(
        "VULNERABLESOFTWARE",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_vulnerablesoftware (
            "ID"                    bigint NOT NULL
          , "CPE22"                 varchar(255)
          , "CPE23"                 varchar(255)
          , "EDITION"               varchar(255)
          , "LANGUAGE"              varchar(255)
          , "OTHER"                 varchar(255)
          , "PART"                  varchar(255)
          , "PRODUCT"               varchar(255)
          , "PURL"                  varchar(1024)
          , "PURL_NAME"             varchar(255)
          , "PURL_NAMESPACE"        varchar(255)
          , "PURL_QUALIFIERS"       varchar(255)
          , "PURL_SUBPATH"          varchar(255)
          , "PURL_TYPE"             varchar(255)
          , "PURL_VERSION"          varchar(255)
          , "SWEDITION"             varchar(255)
          , "TARGETHW"              varchar(255)
          , "TARGETSW"              varchar(255)
          , "UPDATE"                varchar(255)
          , "UUID"                  varchar(36) NOT NULL
          , "VENDOR"                varchar(255)
          , "VERSION"               varchar(255)
          , "VERSIONENDEXCLUDING"   varchar(255)
          , "VERSIONENDINCLUDING"   varchar(255)
          , "VERSIONSTARTEXCLUDING" varchar(255)
          , "VERSIONSTARTINCLUDING" varchar(255)
          , "VULNERABLE"            boolean NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "CPE22"
             , "CPE23"
             , "EDITION"
             , "LANGUAGE"
             , "OTHER"
             , "PART"
             , "PRODUCT"
             , "PURL"
             , "PURL_NAME"
             , "PURL_NAMESPACE"
             , "PURL_QUALIFIERS"
             , "PURL_SUBPATH"
             , "PURL_TYPE"
             , "PURL_VERSION"
             , "SWEDITION"
             , "TARGETHW"
             , "TARGETSW"
             , "UPDATE"
             , "UUID"
             , "VENDOR"
             , "VERSION"
             , "VERSIONENDEXCLUDING"
             , "VERSIONENDINCLUDING"
             , "VERSIONSTARTEXCLUDING"
             , "VERSIONSTARTINCLUDING"
             , "VULNERABLE"
          FROM "%s"."VULNERABLESOFTWARE"
         ORDER BY "ID"
        """,
        List.of("ID", "CPE22", "CPE23", "EDITION", "LANGUAGE", "OTHER", "PART", "PRODUCT",
            "PURL", "PURL_NAME", "PURL_NAMESPACE", "PURL_QUALIFIERS", "PURL_SUBPATH",
            "PURL_TYPE", "PURL_VERSION", "SWEDITION", "TARGETHW", "TARGETSW", "UPDATE",
            "UUID", "VENDOR", "VERSION", "VERSIONENDEXCLUDING", "VERSIONENDINCLUDING",
            "VERSIONSTARTEXCLUDING", "VERSIONSTARTINCLUDING", "VULNERABLE"),
        """
        INSERT INTO "%1$s".probe_invalid_uuids (table_name, orig_id, bad_uuid)
        SELECT 'VULNERABLESOFTWARE', "ID", "UUID"
          FROM "%1$s".src_vulnerablesoftware
         WHERE "UUID" !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ON CONFLICT DO NOTHING;

        DROP TABLE IF EXISTS "%1$s".vulnerablesoftware_canonical_id_map;
        CREATE UNLOGGED TABLE "%1$s".vulnerablesoftware_canonical_id_map (
            orig_id      bigint NOT NULL PRIMARY KEY
          , canonical_id bigint NOT NULL
        );
        INSERT INTO "%1$s".vulnerablesoftware_canonical_id_map (orig_id, canonical_id)
        SELECT s."ID", s."ID"
          FROM "%1$s".src_vulnerablesoftware s
         WHERE s."UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
           AND EXISTS (
               SELECT 1
                 FROM "%1$s".src_vulnerablesoftware_vulnerabilities j
                WHERE j."VULNERABLESOFTWARE_ID" = s."ID"
           );

        DROP TABLE IF EXISTS "%1$s".tgt_vulnerablesoftware;
        CREATE UNLOGGED TABLE "%1$s".tgt_vulnerablesoftware (
            "ID"                    bigint NOT NULL PRIMARY KEY
          , "CPE22"                 varchar(255)
          , "CPE23"                 varchar(255)
          , "EDITION"               varchar(255)
          , "LANGUAGE"              varchar(255)
          , "OTHER"                 varchar(255)
          , "PART"                  varchar(255)
          , "PRODUCT"               varchar(255)
          , "PURL"                  varchar(1024)
          , "PURL_NAME"             varchar(255)
          , "PURL_NAMESPACE"        varchar(255)
          , "PURL_QUALIFIERS"       varchar(255)
          , "PURL_SUBPATH"          varchar(255)
          , "PURL_TYPE"             varchar(255)
          , "PURL_VERSION"          varchar(255)
          , "SWEDITION"             varchar(255)
          , "TARGETHW"              varchar(255)
          , "TARGETSW"              varchar(255)
          , "UPDATE"                varchar(255)
          , "UUID"                  uuid NOT NULL
          , "VENDOR"                varchar(255)
          , "VERSION"               varchar(255)
          , "VERSIONENDEXCLUDING"   varchar(255)
          , "VERSIONENDINCLUDING"   varchar(255)
          , "VERSIONSTARTEXCLUDING" varchar(255)
          , "VERSIONSTARTINCLUDING" varchar(255)
          , "VULNERABLE"            boolean NOT NULL
        );
        INSERT INTO "%1$s".tgt_vulnerablesoftware (
            "ID"
          , "CPE22"
          , "CPE23"
          , "EDITION"
          , "LANGUAGE"
          , "OTHER"
          , "PART"
          , "PRODUCT"
          , "PURL"
          , "PURL_NAME"
          , "PURL_NAMESPACE"
          , "PURL_QUALIFIERS"
          , "PURL_SUBPATH"
          , "PURL_TYPE"
          , "PURL_VERSION"
          , "SWEDITION"
          , "TARGETHW"
          , "TARGETSW"
          , "UPDATE"
          , "UUID"
          , "VENDOR"
          , "VERSION"
          , "VERSIONENDEXCLUDING"
          , "VERSIONENDINCLUDING"
          , "VERSIONSTARTEXCLUDING"
          , "VERSIONSTARTINCLUDING"
          , "VULNERABLE"
        )
        SELECT "ID"
             , "CPE22"
             , "CPE23"
             , "EDITION"
             , "LANGUAGE"
             , "OTHER"
             , LOWER("PART") AS "PART"
             , LOWER("PRODUCT") AS "PRODUCT"
             , "PURL"
             , "PURL_NAME"
             , "PURL_NAMESPACE"
             , "PURL_QUALIFIERS"
             , "PURL_SUBPATH"
             , "PURL_TYPE"
             , "PURL_VERSION"
             , "SWEDITION"
             , "TARGETHW"
             , "TARGETSW"
             , "UPDATE"
             , "UUID"::uuid AS "UUID"
             , LOWER("VENDOR") AS "VENDOR"
             , "VERSION"
             , "VERSIONENDEXCLUDING"
             , "VERSIONENDINCLUDING"
             , "VERSIONSTARTEXCLUDING"
             , "VERSIONSTARTINCLUDING"
             , "VULNERABLE"
          FROM "%1$s".src_vulnerablesoftware s
         WHERE s."UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
           AND EXISTS (
               SELECT 1
                 FROM "%1$s".src_vulnerablesoftware_vulnerabilities j
                WHERE j."VULNERABLESOFTWARE_ID" = s."ID"
           )
        """,
        """
        INSERT INTO "VULNERABLESOFTWARE" (
            "ID"
          , "CPE22"
          , "CPE23"
          , "EDITION"
          , "LANGUAGE"
          , "OTHER"
          , "PART"
          , "PRODUCT"
          , "PURL"
          , "PURL_NAME"
          , "PURL_NAMESPACE"
          , "PURL_QUALIFIERS"
          , "PURL_SUBPATH"
          , "PURL_TYPE"
          , "PURL_VERSION"
          , "SWEDITION"
          , "TARGETHW"
          , "TARGETSW"
          , "UPDATE"
          , "UUID"
          , "VENDOR"
          , "VERSION"
          , "VERSIONENDEXCLUDING"
          , "VERSIONENDINCLUDING"
          , "VERSIONSTARTEXCLUDING"
          , "VERSIONSTARTINCLUDING"
          , "VULNERABLE"
        )
        SELECT "ID"
             , "CPE22"
             , "CPE23"
             , "EDITION"
             , "LANGUAGE"
             , "OTHER"
             , "PART"
             , "PRODUCT"
             , "PURL"
             , "PURL_NAME"
             , "PURL_NAMESPACE"
             , "PURL_QUALIFIERS"
             , "PURL_SUBPATH"
             , "PURL_TYPE"
             , "PURL_VERSION"
             , "SWEDITION"
             , "TARGETHW"
             , "TARGETSW"
             , "UPDATE"
             , "UUID"
             , "VENDOR"
             , "VERSION"
             , "VERSIONENDEXCLUDING"
             , "VERSIONENDINCLUDING"
             , "VERSIONSTARTEXCLUDING"
             , "VERSIONSTARTINCLUDING"
             , "VULNERABLE"
          FROM "%1$s".tgt_vulnerablesoftware
        """
    );

    /**
     * VULNERABILITYMETRICS migration. Trivial pass-through; no UUID, no probe.
     */
    private static final TableMigration VULNERABILITYMETRICS = new TableMigration(
        "VULNERABILITYMETRICS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_vulnerabilitymetrics (
            "ID"          bigint NOT NULL
          , "COUNT"       integer NOT NULL
          , "MEASURED_AT" timestamp with time zone NOT NULL
          , "MONTH"       integer
          , "YEAR"        integer NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "COUNT"
             , "MEASURED_AT"
             , "MONTH"
             , "YEAR"
          FROM "%s"."VULNERABILITYMETRICS"
         ORDER BY "ID"
        """,
        List.of("ID", "COUNT", "MEASURED_AT", "MONTH", "YEAR"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_vulnerabilitymetrics;
        CREATE UNLOGGED TABLE "%1$s".tgt_vulnerabilitymetrics (
            "ID"          bigint NOT NULL PRIMARY KEY
          , "COUNT"       integer NOT NULL
          , "MEASURED_AT" timestamp with time zone NOT NULL
          , "MONTH"       integer
          , "YEAR"        integer NOT NULL
        );
        INSERT INTO "%1$s".tgt_vulnerabilitymetrics (
            "ID"
          , "COUNT"
          , "MEASURED_AT"
          , "MONTH"
          , "YEAR"
        )
        SELECT "ID"
             , "COUNT"
             , "MEASURED_AT"
             , "MONTH"
             , "YEAR"
          FROM "%1$s".src_vulnerabilitymetrics
        """,
        """
        INSERT INTO "VULNERABILITYMETRICS" (
            "ID"
          , "COUNT"
          , "MEASURED_AT"
          , "MONTH"
          , "YEAR"
        )
        SELECT "ID"
             , "COUNT"
             , "MEASURED_AT"
             , "MONTH"
             , "YEAR"
          FROM "%1$s".tgt_vulnerabilitymetrics
        """
    );

    /**
     * Source-only mirror of v4 {@code VULNERABILITYALIAS}. Consumed by the derived
     * {@code VULNERABILITY_ALIAS} transform; the wide v4 row has no 1:1 v5 counterpart.
     */
    private static final TableMigration VULNERABILITYALIAS = new TableMigration(
        "VULNERABILITYALIAS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_vulnerabilityalias (
            "ID"          bigint NOT NULL
          , "CVE_ID"      varchar(255)
          , "GHSA_ID"     varchar(255)
          , "GSD_ID"      varchar(255)
          , "INTERNAL_ID" varchar(255)
          , "OSV_ID"      varchar(255)
          , "SNYK_ID"     varchar(255)
          , "SONATYPE_ID" varchar(255)
          , "VULNDB_ID"   varchar(255)
          , "UUID"        varchar(36) NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "CVE_ID"
             , "GHSA_ID"
             , "GSD_ID"
             , "INTERNAL_ID"
             , "OSV_ID"
             , "SNYK_ID"
             , "SONATYPE_ID"
             , "VULNDB_ID"
             , "UUID"
          FROM "%s"."VULNERABILITYALIAS"
         ORDER BY "ID"
        """,
        List.of("ID", "CVE_ID", "GHSA_ID", "GSD_ID", "INTERNAL_ID",
            "OSV_ID", "SNYK_ID", "SONATYPE_ID", "VULNDB_ID", "UUID"),
        null,
        null
    );

    /**
     * Normalizes the wide v4 {@code VULNERABILITYALIAS} into the v5
     * {@code (SOURCE, VULN_ID)}-keyed {@code VULNERABILITY_ALIAS} plus
     * {@code VULNERABILITY_ALIAS_ASSERTION}. v4 carried up to nine identifier columns per
     * row; v5 stores aliases as one row per identifier with a {@code GROUP_ID} UUID grouping
     * identifiers that are transitively related across v4 rows.
     * <p>
     * The grouping algorithm is adapted near-verbatim from Liquibase changeset
     * {@code v5.7.0-42} in {@code migration/src/main/resources/migration/changelog-v5.7.0.xml}:
     * flatten the wide v4 row into long form ({@code row_id, source, vuln_id}), seed a row-to-
     * component map with identity ({@code component_id = row_id}), then iteratively propagate
     * the minimum component id across rows that share any {@code (source, vuln_id)} pair until
     * the map stabilizes. The CSAF column does not exist in the v4 dump and is unsupported in
     * v5, so it is omitted from the unpivot.
     * <p>
     * The {@code VULNERABILITY_ALIAS_ASSERTION} target is populated in the same transform so
     * the grouping and pair enumeration share a single pass. The follow-on
     * {@link #VULNERABILITY_ALIAS_ASSERTION} entry is load-only.
     */
    private static final TableMigration VULNERABILITY_ALIAS = new TableMigration(
        "VULNERABILITY_ALIAS",
        null, null, null,
        """
        DROP TABLE IF EXISTS "%1$s".tgt_vulnerability_alias;
        DROP TABLE IF EXISTS "%1$s".tgt_vulnerability_alias_assertion;
        DROP TABLE IF EXISTS "%1$s".alias_flattened;
        DROP TABLE IF EXISTS "%1$s".alias_rowmap;
        DROP TABLE IF EXISTS "%1$s".alias_groups;

        CREATE UNLOGGED TABLE "%1$s".alias_flattened (
            row_id  bigint NOT NULL
          , source  text   NOT NULL
          , vuln_id text   NOT NULL
        );
        INSERT INTO "%1$s".alias_flattened (row_id, source, vuln_id)
        SELECT va."ID", t.source, t.vuln_id
          FROM "%1$s".src_vulnerabilityalias va
         CROSS JOIN LATERAL (
           VALUES ('NVD',      va."CVE_ID")
                , ('GITHUB',   va."GHSA_ID")
                , ('GSD',      va."GSD_ID")
                , ('INTERNAL', va."INTERNAL_ID")
                , ('OSV',      va."OSV_ID")
                , ('OSSINDEX', va."SONATYPE_ID")
                , ('SNYK',     va."SNYK_ID")
                , ('VULNDB',   va."VULNDB_ID")
         ) AS t(source, vuln_id)
         WHERE t.vuln_id IS NOT NULL;
        CREATE INDEX ON "%1$s".alias_flattened (source, vuln_id);
        CREATE INDEX ON "%1$s".alias_flattened (row_id);

        CREATE UNLOGGED TABLE "%1$s".alias_rowmap (
            row_id       bigint NOT NULL PRIMARY KEY
          , component_id bigint NOT NULL
        );

        DO $body$
        DECLARE
            n      INT;
            i      INT;
            ridx   BIGINT[];
            parent INT[];
            rnk    INT[];
            grp    INT[];
            root_a INT;
            root_b INT;
        BEGIN
            SELECT array_agg(row_id ORDER BY row_id)
              INTO ridx
              FROM (SELECT DISTINCT row_id FROM "%1$s".alias_flattened) t;
            n := coalesce(array_length(ridx, 1), 0);
            IF n = 0 THEN RETURN; END IF;

            parent := array(SELECT generate_series(1, n));
            rnk    := array_fill(0, ARRAY[n]);

            FOR grp IN
                SELECT array_agg(dense.idx)
                  FROM "%1$s".alias_flattened fa
                  JOIN unnest(ridx) WITH ORDINALITY AS dense(rid, idx)
                    ON dense.rid = fa.row_id
                 GROUP BY fa.source, fa.vuln_id
                HAVING count(*) > 1
            LOOP
                FOR i IN 2 .. array_length(grp, 1) LOOP
                    root_a := grp[1];
                    WHILE parent[root_a] <> root_a LOOP root_a := parent[root_a]; END LOOP;
                    root_b := grp[i];
                    WHILE parent[root_b] <> root_b LOOP root_b := parent[root_b]; END LOOP;
                    IF root_a <> root_b THEN
                        IF rnk[root_a] < rnk[root_b] THEN
                            parent[root_a] := root_b;
                        ELSIF rnk[root_a] > rnk[root_b] THEN
                            parent[root_b] := root_a;
                        ELSE
                            parent[root_b] := root_a;
                            rnk[root_a] := rnk[root_a] + 1;
                        END IF;
                    END IF;
                END LOOP;
            END LOOP;

            FOR i IN 1 .. n LOOP
                root_a := i;
                WHILE parent[root_a] <> root_a LOOP root_a := parent[root_a]; END LOOP;
                parent[i] := root_a;
            END LOOP;

            INSERT INTO "%1$s".alias_rowmap (row_id, component_id)
            SELECT ridx[g.i], ridx[parent[g.i]]
              FROM generate_series(1, n) AS g(i);
        END $body$;
        CREATE INDEX ON "%1$s".alias_rowmap (component_id);

        CREATE UNLOGGED TABLE "%1$s".alias_groups (
            component_id bigint NOT NULL PRIMARY KEY
          , group_id     uuid   NOT NULL
        );
        INSERT INTO "%1$s".alias_groups (component_id, group_id)
        SELECT component_id, gen_random_uuid()
          FROM (SELECT DISTINCT component_id FROM "%1$s".alias_rowmap) t;

        CREATE UNLOGGED TABLE "%1$s".tgt_vulnerability_alias (
            "GROUP_ID" uuid NOT NULL
          , "SOURCE"   text NOT NULL
          , "VULN_ID"  text NOT NULL
          , PRIMARY KEY ("SOURCE", "VULN_ID")
        );
        INSERT INTO "%1$s".tgt_vulnerability_alias ("GROUP_ID", "SOURCE", "VULN_ID")
        SELECT DISTINCT ON (fa.source, fa.vuln_id)
               g.group_id, fa.source, fa.vuln_id
          FROM "%1$s".alias_flattened fa
          JOIN "%1$s".alias_rowmap rm ON rm.row_id = fa.row_id
          JOIN "%1$s".alias_groups g  ON g.component_id = rm.component_id
         ORDER BY fa.source, fa.vuln_id, g.group_id;

        CREATE UNLOGGED TABLE "%1$s".tgt_vulnerability_alias_assertion (
            "ASSERTER"     text NOT NULL
          , "VULN_SOURCE"  text NOT NULL
          , "VULN_ID"      text NOT NULL
          , "ALIAS_SOURCE" text NOT NULL
          , "ALIAS_ID"     text NOT NULL
          , PRIMARY KEY ("ASSERTER", "VULN_SOURCE", "VULN_ID", "ALIAS_SOURCE", "ALIAS_ID")
        );
        INSERT INTO "%1$s".tgt_vulnerability_alias_assertion
            ("ASSERTER", "VULN_SOURCE", "VULN_ID", "ALIAS_SOURCE", "ALIAS_ID")
        SELECT 'UNKNOWN'
             , a."SOURCE"
             , a."VULN_ID"
             , b."SOURCE"
             , b."VULN_ID"
          FROM "%1$s".tgt_vulnerability_alias a
          JOIN "%1$s".tgt_vulnerability_alias b
            ON a."GROUP_ID" = b."GROUP_ID"
           AND (a."SOURCE", a."VULN_ID") < (b."SOURCE", b."VULN_ID")
        """,
        """
        INSERT INTO "VULNERABILITY_ALIAS" ("GROUP_ID", "SOURCE", "VULN_ID")
        SELECT "GROUP_ID", "SOURCE", "VULN_ID"
          FROM "%1$s".tgt_vulnerability_alias
        """
    );

    /**
     * Load-only sibling of {@link #VULNERABILITY_ALIAS}. The assertion staging table is
     * produced by the alias transform; this entry just copies it into the v5 table.
     */
    private static final TableMigration VULNERABILITY_ALIAS_ASSERTION = new TableMigration(
        "VULNERABILITY_ALIAS_ASSERTION",
        null, null, null,
        null,
        """
        INSERT INTO "VULNERABILITY_ALIAS_ASSERTION"
            ("ASSERTER", "VULN_SOURCE", "VULN_ID", "ALIAS_SOURCE", "ALIAS_ID")
        SELECT "ASSERTER"
             , "VULN_SOURCE"
             , "VULN_ID"
             , "ALIAS_SOURCE"
             , "ALIAS_ID"
          FROM "%1$s".tgt_vulnerability_alias_assertion
        """
    );

    /**
     * Pure join migration of {@code COMPONENTS_VULNERABILITIES}. Both sides are rewritten
     * through identity canonical-id maps; the INNER JOIN drops rows whose COMPONENT or
     * VULNERABILITY was excluded for a malformed UUID. v5 enforces UNIQUE on the composite
     * key, so the staging tgt uses it as PK with {@code ON CONFLICT DO NOTHING}.
     */
    private static final TableMigration COMPONENTS_VULNERABILITIES = new TableMigration(
        "COMPONENTS_VULNERABILITIES",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_components_vulnerabilities (
            "COMPONENT_ID"     bigint NOT NULL
          , "VULNERABILITY_ID" bigint NOT NULL
        )
        """,
        """
        SELECT "COMPONENT_ID", "VULNERABILITY_ID"
          FROM "%s"."COMPONENTS_VULNERABILITIES"
        """,
        List.of("COMPONENT_ID", "VULNERABILITY_ID"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_components_vulnerabilities;
        CREATE UNLOGGED TABLE "%1$s".tgt_components_vulnerabilities (
            "COMPONENT_ID"     bigint NOT NULL
          , "VULNERABILITY_ID" bigint NOT NULL
          , PRIMARY KEY ("COMPONENT_ID", "VULNERABILITY_ID")
        );
        INSERT INTO "%1$s".tgt_components_vulnerabilities ("COMPONENT_ID", "VULNERABILITY_ID")
        SELECT DISTINCT cm.canonical_id, vm.canonical_id
          FROM "%1$s".src_components_vulnerabilities j
          JOIN "%1$s".component_canonical_id_map cm ON cm.orig_id = j."COMPONENT_ID"
          JOIN "%1$s".vulnerability_canonical_id_map vm ON vm.orig_id = j."VULNERABILITY_ID"
        ON CONFLICT DO NOTHING
        """,
        """
        INSERT INTO "COMPONENTS_VULNERABILITIES" ("COMPONENT_ID", "VULNERABILITY_ID")
        SELECT "COMPONENT_ID", "VULNERABILITY_ID" FROM "%1$s".tgt_components_vulnerabilities
        """
    );

    /**
     * Pure join migration of {@code SERVICECOMPONENTS_VULNERABILITIES}. Both sides are
     * rewritten through identity canonical-id maps; the INNER JOIN drops rows whose
     * SERVICECOMPONENT or VULNERABILITY was excluded for a malformed UUID. v5 has no
     * unique index on the composite key, but {@code SELECT DISTINCT} plus a composite PK
     * on the staging tgt is sufficient for dedup.
     */
    private static final TableMigration SERVICECOMPONENTS_VULNERABILITIES = new TableMigration(
        "SERVICECOMPONENTS_VULNERABILITIES",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_servicecomponents_vulnerabilities (
            "VULNERABILITY_ID"    bigint NOT NULL
          , "SERVICECOMPONENT_ID" bigint NOT NULL
        )
        """,
        """
        SELECT "VULNERABILITY_ID", "SERVICECOMPONENT_ID"
          FROM "%s"."SERVICECOMPONENTS_VULNERABILITIES"
        """,
        List.of("VULNERABILITY_ID", "SERVICECOMPONENT_ID"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_servicecomponents_vulnerabilities;
        CREATE UNLOGGED TABLE "%1$s".tgt_servicecomponents_vulnerabilities (
            "VULNERABILITY_ID"    bigint NOT NULL
          , "SERVICECOMPONENT_ID" bigint NOT NULL
          , PRIMARY KEY ("VULNERABILITY_ID", "SERVICECOMPONENT_ID")
        );
        INSERT INTO "%1$s".tgt_servicecomponents_vulnerabilities ("VULNERABILITY_ID", "SERVICECOMPONENT_ID")
        SELECT DISTINCT vm.canonical_id, sm.canonical_id
          FROM "%1$s".src_servicecomponents_vulnerabilities j
          JOIN "%1$s".vulnerability_canonical_id_map vm ON vm.orig_id = j."VULNERABILITY_ID"
          JOIN "%1$s".servicecomponent_canonical_id_map sm ON sm.orig_id = j."SERVICECOMPONENT_ID"
        ON CONFLICT DO NOTHING
        """,
        """
        INSERT INTO "SERVICECOMPONENTS_VULNERABILITIES" ("VULNERABILITY_ID", "SERVICECOMPONENT_ID")
        SELECT "VULNERABILITY_ID", "SERVICECOMPONENT_ID" FROM "%1$s".tgt_servicecomponents_vulnerabilities
        """
    );

    /**
     * Pure join migration of {@code VULNERABLESOFTWARE_VULNERABILITIES}. Both sides are
     * rewritten through identity canonical-id maps; the INNER JOIN drops rows whose
     * VULNERABILITY or VULNERABLESOFTWARE was excluded for a malformed UUID. v5 has no
     * unique index on the composite key, but {@code SELECT DISTINCT} plus a composite PK
     * on the staging tgt is sufficient for dedup.
     */
    private static final TableMigration VULNERABLESOFTWARE_VULNERABILITIES = new TableMigration(
        "VULNERABLESOFTWARE_VULNERABILITIES",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_vulnerablesoftware_vulnerabilities (
            "VULNERABILITY_ID"      bigint NOT NULL
          , "VULNERABLESOFTWARE_ID" bigint NOT NULL
        )
        """,
        """
        SELECT "VULNERABILITY_ID", "VULNERABLESOFTWARE_ID"
          FROM "%s"."VULNERABLESOFTWARE_VULNERABILITIES"
        """,
        List.of("VULNERABILITY_ID", "VULNERABLESOFTWARE_ID"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_vulnerablesoftware_vulnerabilities;
        CREATE UNLOGGED TABLE "%1$s".tgt_vulnerablesoftware_vulnerabilities (
            "VULNERABILITY_ID"      bigint NOT NULL
          , "VULNERABLESOFTWARE_ID" bigint NOT NULL
          , PRIMARY KEY ("VULNERABILITY_ID", "VULNERABLESOFTWARE_ID")
        );
        INSERT INTO "%1$s".tgt_vulnerablesoftware_vulnerabilities ("VULNERABILITY_ID", "VULNERABLESOFTWARE_ID")
        SELECT DISTINCT vm.canonical_id, sm.canonical_id
          FROM "%1$s".src_vulnerablesoftware_vulnerabilities j
          JOIN "%1$s".vulnerability_canonical_id_map vm ON vm.orig_id = j."VULNERABILITY_ID"
          JOIN "%1$s".vulnerablesoftware_canonical_id_map sm ON sm.orig_id = j."VULNERABLESOFTWARE_ID"
        ON CONFLICT DO NOTHING
        """,
        """
        INSERT INTO "VULNERABLESOFTWARE_VULNERABILITIES" ("VULNERABILITY_ID", "VULNERABLESOFTWARE_ID")
        SELECT "VULNERABILITY_ID", "VULNERABLESOFTWARE_ID"
          FROM "%1$s".tgt_vulnerablesoftware_vulnerabilities
        """
    );

    /**
     * 1:1 migration of {@code AFFECTEDVERSIONATTRIBUTION}. v5 drops the {@code UUID} column
     * (schema-changes §6); all other columns pass through. {@code VULNERABILITY} and
     * {@code VULNERABLE_SOFTWARE} (the FK columns are not suffixed with {@code _ID} in v4)
     * are rewritten through identity canonical-id maps; the INNER JOIN drops rows whose
     * referenced VULNERABILITY or VULNERABLESOFTWARE was excluded for a malformed UUID.
     * v4 IDs are preserved.
     */
    private static final TableMigration AFFECTEDVERSIONATTRIBUTION = new TableMigration(
        "AFFECTEDVERSIONATTRIBUTION",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_affectedversionattribution (
            "ID"                 bigint NOT NULL
          , "FIRST_SEEN"         timestamptz NOT NULL
          , "LAST_SEEN"          timestamptz NOT NULL
          , "SOURCE"             varchar(255) NOT NULL
          , "UUID"               varchar(36) NOT NULL
          , "VULNERABILITY"      bigint NOT NULL
          , "VULNERABLE_SOFTWARE" bigint NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "FIRST_SEEN"
             , "LAST_SEEN"
             , "SOURCE"
             , "UUID"
             , "VULNERABILITY"
             , "VULNERABLE_SOFTWARE"
          FROM "%s"."AFFECTEDVERSIONATTRIBUTION"
         ORDER BY "ID"
        """,
        List.of("ID", "FIRST_SEEN", "LAST_SEEN", "SOURCE", "UUID", "VULNERABILITY", "VULNERABLE_SOFTWARE"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_affectedversionattribution;
        CREATE UNLOGGED TABLE "%1$s".tgt_affectedversionattribution (
            "ID"                  bigint NOT NULL PRIMARY KEY
          , "FIRST_SEEN"          timestamptz NOT NULL
          , "LAST_SEEN"           timestamptz NOT NULL
          , "SOURCE"               varchar(255) NOT NULL
          , "VULNERABILITY"       bigint NOT NULL
          , "VULNERABLE_SOFTWARE" bigint NOT NULL
        );
        INSERT INTO "%1$s".tgt_affectedversionattribution (
            "ID"
          , "FIRST_SEEN"
          , "LAST_SEEN"
          , "SOURCE"
          , "VULNERABILITY"
          , "VULNERABLE_SOFTWARE"
        )
        SELECT a."ID"
             , a."FIRST_SEEN"
             , a."LAST_SEEN"
             , a."SOURCE"
             , vm.canonical_id
             , sm.canonical_id
          FROM "%1$s".src_affectedversionattribution a
          JOIN "%1$s".vulnerability_canonical_id_map vm ON vm.orig_id = a."VULNERABILITY"
          JOIN "%1$s".vulnerablesoftware_canonical_id_map sm ON sm.orig_id = a."VULNERABLE_SOFTWARE"
        """,
        """
        INSERT INTO "AFFECTEDVERSIONATTRIBUTION" (
            "ID"
          , "FIRST_SEEN"
          , "LAST_SEEN"
          , "SOURCE"
          , "VULNERABILITY"
          , "VULNERABLE_SOFTWARE"
        )
        SELECT "ID"
             , "FIRST_SEEN"
             , "LAST_SEEN"
             , "SOURCE"
             , "VULNERABILITY"
             , "VULNERABLE_SOFTWARE"
          FROM "%1$s".tgt_affectedversionattribution
        """
    );

    /**
     * 1:1 migration of {@code BOM}. UUID converts to native {@code uuid}; malformed-UUID rows
     * land in {@code probe_invalid_uuids} and are excluded from tgt. {@code PROJECT_ID} is
     * rewritten through {@code project_canonical_id_map}; the INNER JOIN drops rows whose
     * project was excluded for a malformed UUID. v5 adds {@code GENERATED} as an additive
     * column, NULL-filled on import (schema-changes §8). v4 IDs are preserved.
     */
    private static final TableMigration BOM = new TableMigration(
        "BOM",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_bom (
            "ID"            bigint NOT NULL
          , "BOM_FORMAT"    varchar(255)
          , "BOM_VERSION"   integer
          , "IMPORTED"      timestamptz NOT NULL
          , "PROJECT_ID"    bigint NOT NULL
          , "SERIAL_NUMBER" varchar(255)
          , "SPEC_VERSION"  varchar(255)
          , "UUID"          varchar(36) NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "BOM_FORMAT"
             , "BOM_VERSION"
             , "IMPORTED"
             , "PROJECT_ID"
             , "SERIAL_NUMBER"
             , "SPEC_VERSION"
             , "UUID"
          FROM "%s"."BOM"
         ORDER BY "ID"
        """,
        List.of("ID", "BOM_FORMAT", "BOM_VERSION", "IMPORTED", "PROJECT_ID",
            "SERIAL_NUMBER", "SPEC_VERSION", "UUID"),
        """
        INSERT INTO "%1$s".probe_invalid_uuids (table_name, orig_id, bad_uuid)
        SELECT 'BOM', "ID", "UUID"
          FROM "%1$s".src_bom
         WHERE "UUID" !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ON CONFLICT DO NOTHING;

        DROP TABLE IF EXISTS "%1$s".tgt_bom;
        CREATE UNLOGGED TABLE "%1$s".tgt_bom (
            "ID"            bigint NOT NULL PRIMARY KEY
          , "BOM_FORMAT"    varchar(255)
          , "BOM_VERSION"   integer
          , "IMPORTED"      timestamptz NOT NULL
          , "PROJECT_ID"    bigint NOT NULL
          , "SERIAL_NUMBER" varchar(255)
          , "SPEC_VERSION"  varchar(255)
          , "UUID"          uuid NOT NULL
          , "GENERATED"     timestamptz
        );
        INSERT INTO "%1$s".tgt_bom (
            "ID"
          , "BOM_FORMAT"
          , "BOM_VERSION"
          , "IMPORTED"
          , "PROJECT_ID"
          , "SERIAL_NUMBER"
          , "SPEC_VERSION"
          , "UUID"
          , "GENERATED"
        )
        SELECT b."ID"
             , b."BOM_FORMAT"
             , b."BOM_VERSION"
             , b."IMPORTED"
             , pm.canonical_id
             , b."SERIAL_NUMBER"
             , b."SPEC_VERSION"
             , b."UUID"::uuid
             , NULL
          FROM "%1$s".src_bom b
          JOIN "%1$s".project_canonical_id_map pm ON pm.orig_id = b."PROJECT_ID"
         WHERE b."UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        """,
        """
        INSERT INTO "BOM" (
            "ID"
          , "BOM_FORMAT"
          , "BOM_VERSION"
          , "IMPORTED"
          , "PROJECT_ID"
          , "SERIAL_NUMBER"
          , "SPEC_VERSION"
          , "UUID"
          , "GENERATED"
        )
        SELECT "ID"
             , "BOM_FORMAT"
             , "BOM_VERSION"
             , "IMPORTED"
             , "PROJECT_ID"
             , "SERIAL_NUMBER"
             , "SPEC_VERSION"
             , "UUID"
             , "GENERATED"
          FROM "%1$s".tgt_bom
        """
    );

    /**
     * 1:1 migration of {@code VEX}. UUID converts to native {@code uuid}; malformed-UUID rows
     * land in {@code probe_invalid_uuids} and are excluded from tgt. {@code PROJECT_ID} is
     * rewritten through {@code project_canonical_id_map}; the INNER JOIN drops rows whose
     * project was excluded for a malformed UUID. v4 IDs are preserved.
     */
    private static final TableMigration VEX = new TableMigration(
        "VEX",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_vex (
            "ID"            bigint NOT NULL
          , "IMPORTED"      timestamptz NOT NULL
          , "PROJECT_ID"    bigint NOT NULL
          , "SERIAL_NUMBER" varchar(255)
          , "SPEC_VERSION"  varchar(255)
          , "UUID"          varchar(36) NOT NULL
          , "VEX_FORMAT"    varchar(255)
          , "VEX_VERSION"   integer
        )
        """,
        """
        SELECT "ID"
             , "IMPORTED"
             , "PROJECT_ID"
             , "SERIAL_NUMBER"
             , "SPEC_VERSION"
             , "UUID"
             , "VEX_FORMAT"
             , "VEX_VERSION"
          FROM "%s"."VEX"
         ORDER BY "ID"
        """,
        List.of("ID", "IMPORTED", "PROJECT_ID", "SERIAL_NUMBER", "SPEC_VERSION",
            "UUID", "VEX_FORMAT", "VEX_VERSION"),
        """
        INSERT INTO "%1$s".probe_invalid_uuids (table_name, orig_id, bad_uuid)
        SELECT 'VEX', "ID", "UUID"
          FROM "%1$s".src_vex
         WHERE "UUID" !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ON CONFLICT DO NOTHING;

        DROP TABLE IF EXISTS "%1$s".tgt_vex;
        CREATE UNLOGGED TABLE "%1$s".tgt_vex (
            "ID"            bigint NOT NULL PRIMARY KEY
          , "IMPORTED"      timestamptz NOT NULL
          , "PROJECT_ID"    bigint NOT NULL
          , "SERIAL_NUMBER" varchar(255)
          , "SPEC_VERSION"  varchar(255)
          , "UUID"          uuid NOT NULL
          , "VEX_FORMAT"    varchar(255)
          , "VEX_VERSION"   integer
        );
        INSERT INTO "%1$s".tgt_vex (
            "ID"
          , "IMPORTED"
          , "PROJECT_ID"
          , "SERIAL_NUMBER"
          , "SPEC_VERSION"
          , "UUID"
          , "VEX_FORMAT"
          , "VEX_VERSION"
        )
        SELECT v."ID"
             , v."IMPORTED"
             , pm.canonical_id
             , v."SERIAL_NUMBER"
             , v."SPEC_VERSION"
             , v."UUID"::uuid
             , v."VEX_FORMAT"
             , v."VEX_VERSION"
          FROM "%1$s".src_vex v
          JOIN "%1$s".project_canonical_id_map pm ON pm.orig_id = v."PROJECT_ID"
         WHERE v."UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        """,
        """
        INSERT INTO "VEX" (
            "ID"
          , "IMPORTED"
          , "PROJECT_ID"
          , "SERIAL_NUMBER"
          , "SPEC_VERSION"
          , "UUID"
          , "VEX_FORMAT"
          , "VEX_VERSION"
        )
        SELECT "ID"
             , "IMPORTED"
             , "PROJECT_ID"
             , "SERIAL_NUMBER"
             , "SPEC_VERSION"
             , "UUID"
             , "VEX_FORMAT"
             , "VEX_VERSION"
          FROM "%1$s".tgt_vex
        """
    );

    /**
     * 1:1 migration of {@code FINDINGATTRIBUTION} with 3-column dedup on
     * {@code (COMPONENT_ID, VULNERABILITY_ID, ANALYZERIDENTITY)}. v5 enforces this as a UNIQUE.
     * The {@code UUID} column is dropped (schema-changes §6); {@code REFERENCE_URL} widens to
     * {@code text}; {@code MATCHING_PERCENTAGE} and {@code DELETED_AT} are NULL on import
     * (§8). {@code ANALYZERIDENTITY} is value-remapped per §5.6. {@code COMPONENT_ID},
     * {@code PROJECT_ID}, {@code VULNERABILITY_ID} are rewritten through canonical-id maps;
     * INNER JOINs drop rows referencing excluded entities. Tiebreaker keeps the newest
     * {@code ATTRIBUTED_ON} (then highest ID). v4 IDs are preserved.
     */
    private static final TableMigration FINDINGATTRIBUTION = new TableMigration(
        "FINDINGATTRIBUTION",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_findingattribution (
            "ID"               bigint NOT NULL
          , "ALT_ID"           varchar(255)
          , "ANALYZERIDENTITY" varchar(255) NOT NULL
          , "ATTRIBUTED_ON"    timestamptz NOT NULL
          , "COMPONENT_ID"     bigint NOT NULL
          , "PROJECT_ID"       bigint NOT NULL
          , "REFERENCE_URL"    varchar(255)
          , "UUID"             varchar(36) NOT NULL
          , "VULNERABILITY_ID" bigint NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "ALT_ID"
             , "ANALYZERIDENTITY"
             , "ATTRIBUTED_ON"
             , "COMPONENT_ID"
             , "PROJECT_ID"
             , "REFERENCE_URL"
             , "UUID"
             , "VULNERABILITY_ID"
          FROM "%s"."FINDINGATTRIBUTION"
         ORDER BY "ID"
        """,
        List.of("ID", "ALT_ID", "ANALYZERIDENTITY", "ATTRIBUTED_ON", "COMPONENT_ID",
            "PROJECT_ID", "REFERENCE_URL", "UUID", "VULNERABILITY_ID"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_findingattribution;
        CREATE UNLOGGED TABLE "%1$s".tgt_findingattribution (
            "ID"                  bigint NOT NULL PRIMARY KEY
          , "ALT_ID"              varchar(255)
          , "ANALYZERIDENTITY"    varchar(255) NOT NULL
          , "ATTRIBUTED_ON"       timestamptz NOT NULL
          , "COMPONENT_ID"        bigint NOT NULL
          , "PROJECT_ID"          bigint NOT NULL
          , "REFERENCE_URL"       text
          , "VULNERABILITY_ID"    bigint NOT NULL
          , "MATCHING_PERCENTAGE" smallint
          , "DELETED_AT"          timestamptz
        );
        INSERT INTO "%1$s".tgt_findingattribution (
            "ID"
          , "ALT_ID"
          , "ANALYZERIDENTITY"
          , "ATTRIBUTED_ON"
          , "COMPONENT_ID"
          , "PROJECT_ID"
          , "REFERENCE_URL"
          , "VULNERABILITY_ID"
          , "MATCHING_PERCENTAGE"
          , "DELETED_AT"
        )
        SELECT "ID"
             , "ALT_ID"
             , "ANALYZERIDENTITY"
             , "ATTRIBUTED_ON"
             , "COMPONENT_ID"
             , "PROJECT_ID"
             , "REFERENCE_URL"
             , "VULNERABILITY_ID"
             , NULL
             , NULL
          FROM (
            SELECT f."ID"
                 , f."ALT_ID"
                 , CASE f."ANALYZERIDENTITY" WHEN 'INTERNAL_ANALYZER'  THEN 'internal' WHEN 'NONE'               THEN 'none' WHEN 'OSSINDEX_ANALYZER'  THEN 'oss-index' WHEN 'SNYK_ANALYZER'      THEN 'snyk' WHEN 'VULNDB_ANALYZER'    THEN 'vuln-db' ELSE f."ANALYZERIDENTITY" END AS "ANALYZERIDENTITY"
                 , f."ATTRIBUTED_ON"
                 , cm.canonical_id AS "COMPONENT_ID"
                 , pm.canonical_id AS "PROJECT_ID"
                 , f."REFERENCE_URL"
                 , vm.canonical_id AS "VULNERABILITY_ID"
                 , ROW_NUMBER() OVER ( PARTITION BY cm.canonical_id, vm.canonical_id, CASE f."ANALYZERIDENTITY" WHEN 'INTERNAL_ANALYZER'  THEN 'internal' WHEN 'NONE'               THEN 'none' WHEN 'OSSINDEX_ANALYZER'  THEN 'oss-index' WHEN 'SNYK_ANALYZER'      THEN 'snyk' WHEN 'VULNDB_ANALYZER'    THEN 'vuln-db' ELSE f."ANALYZERIDENTITY" END
                     ORDER BY f."ATTRIBUTED_ON" DESC NULLS LAST, f."ID" DESC
                   ) AS rn
              FROM "%1$s".src_findingattribution f
              JOIN "%1$s".component_canonical_id_map cm ON cm.orig_id = f."COMPONENT_ID"
              JOIN "%1$s".project_canonical_id_map pm ON pm.orig_id = f."PROJECT_ID"
              JOIN "%1$s".vulnerability_canonical_id_map vm ON vm.orig_id = f."VULNERABILITY_ID"
          ) ranked
         WHERE rn = 1
        """,
        """
        INSERT INTO "FINDINGATTRIBUTION" (
            "ID"
          , "ALT_ID"
          , "ANALYZERIDENTITY"
          , "ATTRIBUTED_ON"
          , "COMPONENT_ID"
          , "PROJECT_ID"
          , "REFERENCE_URL"
          , "VULNERABILITY_ID"
          , "MATCHING_PERCENTAGE"
          , "DELETED_AT"
        )
        SELECT "ID"
             , "ALT_ID"
             , "ANALYZERIDENTITY"
             , "ATTRIBUTED_ON"
             , "COMPONENT_ID"
             , "PROJECT_ID"
             , "REFERENCE_URL"
             , "VULNERABILITY_ID"
             , "MATCHING_PERCENTAGE"
             , "DELETED_AT"
          FROM "%1$s".tgt_findingattribution
        """
    );

    /**
     * 1:1 migration of {@code POLICYVIOLATION} with 3-column dedup on
     * {@code (COMPONENT_ID, PROJECT_ID, POLICYCONDITION_ID)} per schema-changes §4.7. v5
     * enforces this as a UNIQUE. UUID converts to native {@code uuid}; malformed-UUID rows
     * land in {@code probe_invalid_uuids} and are excluded. {@code COMPONENT_ID} and
     * {@code PROJECT_ID} are rewritten through canonical-id maps; {@code POLICYCONDITION_ID}
     * passes through (POLICYCONDITION preserves v4 IDs). Tiebreaker keeps the newest
     * {@code TIMESTAMP} (then highest ID). v4 IDs are preserved.
     */
    private static final TableMigration POLICYVIOLATION = new TableMigration(
        "POLICYVIOLATION",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_policyviolation (
            "ID"                 bigint NOT NULL
          , "COMPONENT_ID"       bigint NOT NULL
          , "POLICYCONDITION_ID" bigint NOT NULL
          , "PROJECT_ID"         bigint NOT NULL
          , "TEXT"               varchar(255)
          , "TIMESTAMP"          timestamptz NOT NULL
          , "TYPE"               varchar(255) NOT NULL
          , "UUID"               varchar(36) NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "COMPONENT_ID"
             , "POLICYCONDITION_ID"
             , "PROJECT_ID"
             , "TEXT"
             , "TIMESTAMP"
             , "TYPE"
             , "UUID"
          FROM "%s"."POLICYVIOLATION"
         ORDER BY "ID"
        """,
        List.of("ID", "COMPONENT_ID", "POLICYCONDITION_ID", "PROJECT_ID",
            "TEXT", "TIMESTAMP", "TYPE", "UUID"),
        """
        INSERT INTO "%1$s".probe_invalid_uuids (table_name, orig_id, bad_uuid)
        SELECT 'POLICYVIOLATION', "ID", "UUID"
          FROM "%1$s".src_policyviolation
         WHERE "UUID" !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ON CONFLICT DO NOTHING;

        DROP TABLE IF EXISTS "%1$s".tgt_policyviolation;
        CREATE UNLOGGED TABLE "%1$s".tgt_policyviolation (
            "ID"                 bigint NOT NULL PRIMARY KEY
          , "COMPONENT_ID"       bigint NOT NULL
          , "POLICYCONDITION_ID" bigint NOT NULL
          , "PROJECT_ID"         bigint NOT NULL
          , "TEXT"               varchar(255)
          , "TIMESTAMP"          timestamptz NOT NULL
          , "TYPE"               varchar(255) NOT NULL
          , "UUID"               uuid NOT NULL
        );
        INSERT INTO "%1$s".tgt_policyviolation (
            "ID"
          , "COMPONENT_ID"
          , "POLICYCONDITION_ID"
          , "PROJECT_ID"
          , "TEXT"
          , "TIMESTAMP"
          , "TYPE"
          , "UUID"
        )
        SELECT "ID"
             , "COMPONENT_ID"
             , "POLICYCONDITION_ID"
             , "PROJECT_ID"
             , "TEXT"
             , "TIMESTAMP"
             , "TYPE"
             , "UUID"::uuid
          FROM (
            SELECT v."ID"
                 , cm.canonical_id AS "COMPONENT_ID"
                 , v."POLICYCONDITION_ID"
                 , pm.canonical_id AS "PROJECT_ID"
                 , v."TEXT"
                 , v."TIMESTAMP"
                 , v."TYPE"
                 , v."UUID"
                 , ROW_NUMBER() OVER ( PARTITION BY cm.canonical_id, pm.canonical_id, v."POLICYCONDITION_ID"
                     ORDER BY v."TIMESTAMP" DESC NULLS LAST, v."ID" DESC
                   ) AS rn
              FROM "%1$s".src_policyviolation v
              JOIN "%1$s".component_canonical_id_map cm ON cm.orig_id = v."COMPONENT_ID"
              JOIN "%1$s".project_canonical_id_map pm ON pm.orig_id = v."PROJECT_ID"
             WHERE v."UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
          ) ranked
         WHERE rn = 1
        """,
        """
        INSERT INTO "POLICYVIOLATION" (
            "ID"
          , "COMPONENT_ID"
          , "POLICYCONDITION_ID"
          , "PROJECT_ID"
          , "TEXT"
          , "TIMESTAMP"
          , "TYPE"
          , "UUID"
        )
        SELECT "ID"
             , "COMPONENT_ID"
             , "POLICYCONDITION_ID"
             , "PROJECT_ID"
             , "TEXT"
             , "TIMESTAMP"
             , "TYPE"
             , "UUID"
          FROM "%1$s".tgt_policyviolation
        """
    );

    /**
     * 1:1 migration of {@code ANALYSIS}. {@code COMPONENT_ID}, {@code PROJECT_ID},
     * {@code VULNERABILITY_ID} are rewritten through canonical-id maps; INNER JOINs drop
     * rows referencing excluded entities. v5 adds {@code CVSSV2VECTOR}, {@code CVSSV2SCORE},
     * {@code CVSSV3VECTOR}, {@code CVSSV3SCORE}, {@code CVSSV4VECTOR}, {@code CVSSV4SCORE},
     * {@code OWASPVECTOR}, {@code OWASPSCORE}, {@code SEVERITY}, {@code VULNERABILITY_POLICY_ID}
     * as additive columns, NULL-filled on import (schema-changes §8). v4 IDs are preserved.
     */
    private static final TableMigration ANALYSIS = new TableMigration(
        "ANALYSIS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_analysis (
            "ID"               bigint NOT NULL
          , "DETAILS"          text
          , "JUSTIFICATION"    varchar(255)
          , "RESPONSE"         varchar(255)
          , "STATE"            varchar(255) NOT NULL
          , "COMPONENT_ID"     bigint
          , "PROJECT_ID"       bigint
          , "SUPPRESSED"       boolean NOT NULL
          , "VULNERABILITY_ID" bigint NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "DETAILS"
             , "JUSTIFICATION"
             , "RESPONSE"
             , "STATE"
             , "COMPONENT_ID"
             , "PROJECT_ID"
             , "SUPPRESSED"
             , "VULNERABILITY_ID"
          FROM "%s"."ANALYSIS"
         ORDER BY "ID"
        """,
        List.of("ID", "DETAILS", "JUSTIFICATION", "RESPONSE", "STATE",
            "COMPONENT_ID", "PROJECT_ID", "SUPPRESSED", "VULNERABILITY_ID"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_analysis;
        CREATE UNLOGGED TABLE "%1$s".tgt_analysis (
            "ID"                      bigint NOT NULL PRIMARY KEY
          , "DETAILS"                 text
          , "JUSTIFICATION"           varchar(255)
          , "RESPONSE"                varchar(255)
          , "STATE"                   varchar(255) NOT NULL
          , "COMPONENT_ID"            bigint
          , "PROJECT_ID"              bigint
          , "SUPPRESSED"              boolean NOT NULL
          , "VULNERABILITY_ID"        bigint NOT NULL
          , "CVSSV2VECTOR"            varchar(255)
          , "CVSSV2SCORE"             numeric
          , "CVSSV3VECTOR"            varchar(255)
          , "CVSSV3SCORE"             numeric
          , "CVSSV4VECTOR"            varchar(255)
          , "CVSSV4SCORE"             numeric
          , "OWASPVECTOR"             varchar(255)
          , "OWASPSCORE"              numeric
          , "SEVERITY"                varchar(255)
          , "VULNERABILITY_POLICY_ID" bigint
        );
        INSERT INTO "%1$s".tgt_analysis (
            "ID"
          , "DETAILS"
          , "JUSTIFICATION"
          , "RESPONSE"
          , "STATE"
          , "COMPONENT_ID"
          , "PROJECT_ID"
          , "SUPPRESSED"
          , "VULNERABILITY_ID"
          , "CVSSV2VECTOR"
          , "CVSSV2SCORE"
          , "CVSSV3VECTOR"
          , "CVSSV3SCORE"
          , "CVSSV4VECTOR"
          , "CVSSV4SCORE"
          , "OWASPVECTOR"
          , "OWASPSCORE"
          , "SEVERITY"
          , "VULNERABILITY_POLICY_ID"
        )
        SELECT a."ID"
             , a."DETAILS"
             , a."JUSTIFICATION"
             , a."RESPONSE"
             , a."STATE"
             , cm.canonical_id
             , pm.canonical_id
             , a."SUPPRESSED"
             , vm.canonical_id
             , NULL
             , NULL
             , NULL
             , NULL
             , NULL
             , NULL
             , NULL
             , NULL
             , NULL
             , NULL
          FROM "%1$s".src_analysis a
          JOIN "%1$s".component_canonical_id_map cm ON cm.orig_id = a."COMPONENT_ID"
          JOIN "%1$s".project_canonical_id_map pm ON pm.orig_id = a."PROJECT_ID"
          JOIN "%1$s".vulnerability_canonical_id_map vm ON vm.orig_id = a."VULNERABILITY_ID"
        """,
        """
        INSERT INTO "ANALYSIS" (
            "ID"
          , "DETAILS"
          , "JUSTIFICATION"
          , "RESPONSE"
          , "STATE"
          , "COMPONENT_ID"
          , "PROJECT_ID"
          , "SUPPRESSED"
          , "VULNERABILITY_ID"
          , "CVSSV2VECTOR"
          , "CVSSV2SCORE"
          , "CVSSV3VECTOR"
          , "CVSSV3SCORE"
          , "CVSSV4VECTOR"
          , "CVSSV4SCORE"
          , "OWASPVECTOR"
          , "OWASPSCORE"
          , "SEVERITY"
          , "VULNERABILITY_POLICY_ID"
        )
        SELECT "ID"
             , "DETAILS"
             , "JUSTIFICATION"
             , "RESPONSE"
             , "STATE"
             , "COMPONENT_ID"
             , "PROJECT_ID"
             , "SUPPRESSED"
             , "VULNERABILITY_ID"
             , "CVSSV2VECTOR"
             , "CVSSV2SCORE"
             , "CVSSV3VECTOR"
             , "CVSSV3SCORE"
             , "CVSSV4VECTOR"
             , "CVSSV4SCORE"
             , "OWASPVECTOR"
             , "OWASPSCORE"
             , "SEVERITY"::severity
             , "VULNERABILITY_POLICY_ID"
          FROM "%1$s".tgt_analysis
        """
    );

    /**
     * 1:1 migration of {@code ANALYSISCOMMENT}. {@code ANALYSIS_ID} passes through (ANALYSIS
     * preserves v4 IDs); orphaned rows whose parent ANALYSIS was dropped are removed via
     * INNER JOIN against {@code tgt_analysis}. v4 IDs are preserved.
     */
    private static final TableMigration ANALYSISCOMMENT = new TableMigration(
        "ANALYSISCOMMENT",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_analysiscomment (
            "ID"          bigint NOT NULL
          , "ANALYSIS_ID" bigint NOT NULL
          , "COMMENT"     text NOT NULL
          , "COMMENTER"   varchar(255)
          , "TIMESTAMP"   timestamptz NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "ANALYSIS_ID"
             , "COMMENT"
             , "COMMENTER"
             , "TIMESTAMP"
          FROM "%s"."ANALYSISCOMMENT"
         ORDER BY "ID"
        """,
        List.of("ID", "ANALYSIS_ID", "COMMENT", "COMMENTER", "TIMESTAMP"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_analysiscomment;
        CREATE UNLOGGED TABLE "%1$s".tgt_analysiscomment (
            "ID"          bigint NOT NULL PRIMARY KEY
          , "ANALYSIS_ID" bigint NOT NULL
          , "COMMENT"     text NOT NULL
          , "COMMENTER"   varchar(255)
          , "TIMESTAMP"   timestamptz NOT NULL
        );
        INSERT INTO "%1$s".tgt_analysiscomment (
            "ID"
          , "ANALYSIS_ID"
          , "COMMENT"
          , "COMMENTER"
          , "TIMESTAMP"
        )
        SELECT c."ID"
             , c."ANALYSIS_ID"
             , c."COMMENT"
             , c."COMMENTER"
             , c."TIMESTAMP"
          FROM "%1$s".src_analysiscomment c
          JOIN "%1$s".tgt_analysis a ON a."ID" = c."ANALYSIS_ID"
        """,
        """
        INSERT INTO "ANALYSISCOMMENT" (
            "ID"
          , "ANALYSIS_ID"
          , "COMMENT"
          , "COMMENTER"
          , "TIMESTAMP"
        )
        SELECT "ID"
             , "ANALYSIS_ID"
             , "COMMENT"
             , "COMMENTER"
             , "TIMESTAMP"
          FROM "%1$s".tgt_analysiscomment
        """
    );

    /**
     * 1:1 migration of {@code VIOLATIONANALYSIS}. {@code COMPONENT_ID} and {@code PROJECT_ID}
     * are rewritten through canonical-id maps; {@code POLICYVIOLATION_ID} passes through
     * (POLICYVIOLATION preserves v4 IDs). Orphaned rows whose POLICYVIOLATION was dropped
     * are removed via INNER JOIN against {@code tgt_policyviolation}. v4 allows NULL
     * COMPONENT_ID / PROJECT_ID; these are rare in practice but the LEFT JOINs preserve them.
     * v4 IDs are preserved.
     */
    private static final TableMigration VIOLATIONANALYSIS = new TableMigration(
        "VIOLATIONANALYSIS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_violationanalysis (
            "ID"                 bigint NOT NULL
          , "STATE"              varchar(255) NOT NULL
          , "COMPONENT_ID"       bigint
          , "POLICYVIOLATION_ID" bigint NOT NULL
          , "PROJECT_ID"         bigint
          , "SUPPRESSED"         boolean NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "STATE"
             , "COMPONENT_ID"
             , "POLICYVIOLATION_ID"
             , "PROJECT_ID"
             , "SUPPRESSED"
          FROM "%s"."VIOLATIONANALYSIS"
         ORDER BY "ID"
        """,
        List.of("ID", "STATE", "COMPONENT_ID", "POLICYVIOLATION_ID", "PROJECT_ID", "SUPPRESSED"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_violationanalysis;
        CREATE UNLOGGED TABLE "%1$s".tgt_violationanalysis (
            "ID"                 bigint NOT NULL PRIMARY KEY
          , "STATE"              varchar(255) NOT NULL
          , "COMPONENT_ID"       bigint
          , "POLICYVIOLATION_ID" bigint NOT NULL
          , "PROJECT_ID"         bigint
          , "SUPPRESSED"         boolean NOT NULL
        );
        INSERT INTO "%1$s".tgt_violationanalysis (
            "ID"
          , "STATE"
          , "COMPONENT_ID"
          , "POLICYVIOLATION_ID"
          , "PROJECT_ID"
          , "SUPPRESSED"
        )
        SELECT v."ID"
             , v."STATE"
             , cm.canonical_id
             , v."POLICYVIOLATION_ID"
             , pm.canonical_id
             , v."SUPPRESSED"
          FROM "%1$s".src_violationanalysis v
          JOIN "%1$s".tgt_policyviolation pv ON pv."ID" = v."POLICYVIOLATION_ID"
          LEFT JOIN "%1$s".component_canonical_id_map cm ON cm.orig_id = v."COMPONENT_ID"
          LEFT JOIN "%1$s".project_canonical_id_map pm ON pm.orig_id = v."PROJECT_ID"
        """,
        """
        INSERT INTO "VIOLATIONANALYSIS" (
            "ID"
          , "STATE"
          , "COMPONENT_ID"
          , "POLICYVIOLATION_ID"
          , "PROJECT_ID"
          , "SUPPRESSED"
        )
        SELECT "ID"
             , "STATE"
             , "COMPONENT_ID"
             , "POLICYVIOLATION_ID"
             , "PROJECT_ID"
             , "SUPPRESSED"
          FROM "%1$s".tgt_violationanalysis
        """
    );

    /**
     * 1:1 migration of {@code VIOLATIONANALYSISCOMMENT}. {@code VIOLATIONANALYSIS_ID} passes
     * through (VIOLATIONANALYSIS preserves v4 IDs); orphans are dropped via INNER JOIN
     * against {@code tgt_violationanalysis}. v4 IDs are preserved.
     */
    private static final TableMigration VIOLATIONANALYSISCOMMENT = new TableMigration(
        "VIOLATIONANALYSISCOMMENT",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_violationanalysiscomment (
            "ID"                   bigint NOT NULL
          , "COMMENT"              text NOT NULL
          , "COMMENTER"            varchar(255)
          , "TIMESTAMP"            timestamptz NOT NULL
          , "VIOLATIONANALYSIS_ID" bigint NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "COMMENT"
             , "COMMENTER"
             , "TIMESTAMP"
             , "VIOLATIONANALYSIS_ID"
          FROM "%s"."VIOLATIONANALYSISCOMMENT"
         ORDER BY "ID"
        """,
        List.of("ID", "COMMENT", "COMMENTER", "TIMESTAMP", "VIOLATIONANALYSIS_ID"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_violationanalysiscomment;
        CREATE UNLOGGED TABLE "%1$s".tgt_violationanalysiscomment (
            "ID"                   bigint NOT NULL PRIMARY KEY
          , "COMMENT"               text NOT NULL
          , "COMMENTER"             varchar(255)
          , "TIMESTAMP"             timestamptz NOT NULL
          , "VIOLATIONANALYSIS_ID" bigint NOT NULL
        );
        INSERT INTO "%1$s".tgt_violationanalysiscomment (
            "ID"
          , "COMMENT"
          , "COMMENTER"
          , "TIMESTAMP"
          , "VIOLATIONANALYSIS_ID"
        )
        SELECT c."ID"
             , c."COMMENT"
             , c."COMMENTER"
             , c."TIMESTAMP"
             , c."VIOLATIONANALYSIS_ID"
          FROM "%1$s".src_violationanalysiscomment c
          JOIN "%1$s".tgt_violationanalysis v ON v."ID" = c."VIOLATIONANALYSIS_ID"
        """,
        """
        INSERT INTO "VIOLATIONANALYSISCOMMENT" (
            "ID"
          , "COMMENT"
          , "COMMENTER"
          , "TIMESTAMP"
          , "VIOLATIONANALYSIS_ID"
        )
        SELECT "ID"
             , "COMMENT"
             , "COMMENTER"
             , "TIMESTAMP"
             , "VIOLATIONANALYSIS_ID"
          FROM "%1$s".tgt_violationanalysiscomment
        """
    );

    /**
     * 1:1 migration of {@code CONFIGPROPERTY} per schema-changes §5.9 and §7.8. Applies the
     * ENCRYPTEDSTRING wipe ({@code PROPERTYVALUE → NULL}, {@code PROPERTYTYPE → STRING}) and
     * the {@code integrations / defectdojo.apiKey} value wipe, then drops rows whose
     * {@code PROPERTYTYPE} is outside the v5 enum. v4 ID is preserved.
     */
    private static final TableMigration CONFIGPROPERTY = new TableMigration(
        "CONFIGPROPERTY",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_configproperty (
            "ID"            bigint NOT NULL
          , "DESCRIPTION"   varchar(255)
          , "GROUPNAME"     varchar(255) NOT NULL
          , "PROPERTYNAME"  varchar(255) NOT NULL
          , "PROPERTYTYPE"  varchar(255) NOT NULL
          , "PROPERTYVALUE" text
        )
        """,
        """
        SELECT "ID"
             , "DESCRIPTION"
             , "GROUPNAME"
             , "PROPERTYNAME"
             , "PROPERTYTYPE"
             , "PROPERTYVALUE"
          FROM "%s"."CONFIGPROPERTY"
         ORDER BY "ID"
        """,
        List.of("ID", "DESCRIPTION", "GROUPNAME", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_configproperty;
        CREATE UNLOGGED TABLE "%1$s".tgt_configproperty (
            "ID"            bigint NOT NULL PRIMARY KEY
          , "DESCRIPTION"   varchar(255)
          , "GROUPNAME"     varchar(255) NOT NULL
          , "PROPERTYNAME"  varchar(255) NOT NULL
          , "PROPERTYTYPE"  varchar(255) NOT NULL
          , "PROPERTYVALUE" text
        );
        WITH wiped AS (
            SELECT "ID"
                 , "DESCRIPTION"
                 , "GROUPNAME"
                 , "PROPERTYNAME"
                 , CASE WHEN "PROPERTYTYPE" = 'ENCRYPTEDSTRING' THEN 'STRING' ELSE "PROPERTYTYPE" END AS "PROPERTYTYPE"
                 , CASE WHEN "PROPERTYTYPE" = 'ENCRYPTEDSTRING' THEN NULL WHEN "GROUPNAME" = 'integrations' AND "PROPERTYNAME" = 'defectdojo.apiKey' THEN NULL ELSE "PROPERTYVALUE" END AS "PROPERTYVALUE"
              FROM "%1$s".src_configproperty
        )
        INSERT INTO "%1$s".tgt_configproperty
            ("ID", "DESCRIPTION", "GROUPNAME", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE")
        SELECT "ID"
             , "DESCRIPTION"
             , "GROUPNAME"
             , "PROPERTYNAME"
             , "PROPERTYTYPE"
             , "PROPERTYVALUE"
          FROM wiped
         WHERE "PROPERTYTYPE" IN ('BOOLEAN', 'INTEGER', 'NUMBER', 'STRING', 'TIMESTAMP', 'URL', 'UUID')
        """,
        """
        INSERT INTO "CONFIGPROPERTY"
            ("ID", "DESCRIPTION", "GROUPNAME", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE")
        SELECT "ID"
             , "DESCRIPTION"
             , "GROUPNAME"
             , "PROPERTYNAME"
             , "PROPERTYTYPE"
             , "PROPERTYVALUE"
          FROM "%1$s".tgt_configproperty
        """
    );

    /**
     * 1:1 migration of {@code PROJECT_PROPERTY} with PROJECT_ID rewrite through
     * {@code project_canonical_id_map}. Applies the ENCRYPTEDSTRING wipe and drops rows whose
     * {@code PROPERTYTYPE} is outside the v5 enum (schema-changes §5.9 / §7.8). v4 has no
     * UUID column on this table.
     */
    private static final TableMigration PROJECT_PROPERTY = new TableMigration(
        "PROJECT_PROPERTY",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_project_property (
            "ID"            bigint NOT NULL
          , "DESCRIPTION"   varchar(255)
          , "GROUPNAME"     varchar(255) NOT NULL
          , "PROJECT_ID"    bigint NOT NULL
          , "PROPERTYNAME"  varchar(255) NOT NULL
          , "PROPERTYTYPE"  varchar(255) NOT NULL
          , "PROPERTYVALUE" varchar(1024)
        )
        """,
        """
        SELECT "ID"
             , "DESCRIPTION"
             , "GROUPNAME"
             , "PROJECT_ID"
             , "PROPERTYNAME"
             , "PROPERTYTYPE"
             , "PROPERTYVALUE"
          FROM "%s"."PROJECT_PROPERTY"
         ORDER BY "ID"
        """,
        List.of("ID", "DESCRIPTION", "GROUPNAME", "PROJECT_ID", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_project_property;
        CREATE UNLOGGED TABLE "%1$s".tgt_project_property (
            "ID"            bigint NOT NULL PRIMARY KEY
          , "DESCRIPTION"   varchar(255)
          , "GROUPNAME"     varchar(255) NOT NULL
          , "PROJECT_ID"    bigint NOT NULL
          , "PROPERTYNAME"  varchar(255) NOT NULL
          , "PROPERTYTYPE"  varchar(255) NOT NULL
          , "PROPERTYVALUE" varchar(1024)
        );
        WITH rewritten AS (
            SELECT p."ID"
                 , p."DESCRIPTION"
                 , p."GROUPNAME"
                 , pm.canonical_id AS "PROJECT_ID"
                 , p."PROPERTYNAME"
                 , CASE WHEN p."PROPERTYTYPE" = 'ENCRYPTEDSTRING' THEN 'STRING' ELSE p."PROPERTYTYPE" END AS "PROPERTYTYPE"
                 , CASE WHEN p."PROPERTYTYPE" = 'ENCRYPTEDSTRING' THEN NULL ELSE p."PROPERTYVALUE" END AS "PROPERTYVALUE"
              FROM "%1$s".src_project_property p
              JOIN "%1$s".project_canonical_id_map pm ON pm.orig_id = p."PROJECT_ID"
        )
        INSERT INTO "%1$s".tgt_project_property
            ("ID", "DESCRIPTION", "GROUPNAME", "PROJECT_ID", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE")
        SELECT "ID"
             , "DESCRIPTION"
             , "GROUPNAME"
             , "PROJECT_ID"
             , "PROPERTYNAME"
             , "PROPERTYTYPE"
             , "PROPERTYVALUE"
          FROM rewritten
         WHERE "PROPERTYTYPE" IN ('BOOLEAN', 'INTEGER', 'NUMBER', 'STRING', 'TIMESTAMP', 'URL', 'UUID')
        """,
        """
        INSERT INTO "PROJECT_PROPERTY"
            ("ID", "DESCRIPTION", "GROUPNAME", "PROJECT_ID", "PROPERTYNAME", "PROPERTYTYPE", "PROPERTYVALUE")
        SELECT "ID"
             , "DESCRIPTION"
             , "GROUPNAME"
             , "PROJECT_ID"
             , "PROPERTYNAME"
             , "PROPERTYTYPE"
             , "PROPERTYVALUE"
          FROM "%1$s".tgt_project_property
        """
    );

    /**
     * 1:1 migration of {@code COMPONENT_PROPERTY} with COMPONENT_ID rewrite through
     * {@code component_canonical_id_map}. Applies the ENCRYPTEDSTRING wipe and drops rows
     * whose {@code PROPERTYTYPE} is outside the v5 enum (schema-changes §5.9 / §7.8). v4
     * UUID (varchar(36)) converts to native uuid; malformed UUIDs feed the invalid-UUID
     * probe and are excluded.
     */
    private static final TableMigration COMPONENT_PROPERTY = new TableMigration(
        "COMPONENT_PROPERTY",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_component_property (
            "ID"            bigint NOT NULL
          , "COMPONENT_ID"  bigint NOT NULL
          , "DESCRIPTION"   varchar(255)
          , "GROUPNAME"     varchar(255)
          , "PROPERTYNAME"  varchar(255) NOT NULL
          , "PROPERTYTYPE"  varchar(255) NOT NULL
          , "PROPERTYVALUE" varchar(1024)
          , "UUID"          varchar(36) NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "COMPONENT_ID"
             , "DESCRIPTION"
             , "GROUPNAME"
             , "PROPERTYNAME"
             , "PROPERTYTYPE"
             , "PROPERTYVALUE"
             , "UUID"
          FROM "%s"."COMPONENT_PROPERTY"
         ORDER BY "ID"
        """,
        List.of("ID", "COMPONENT_ID", "DESCRIPTION", "GROUPNAME", "PROPERTYNAME",
            "PROPERTYTYPE", "PROPERTYVALUE", "UUID"),
        """
        INSERT INTO "%1$s".probe_invalid_uuids (table_name, orig_id, bad_uuid)
        SELECT 'COMPONENT_PROPERTY', "ID", "UUID"
          FROM "%1$s".src_component_property
         WHERE "UUID" !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ON CONFLICT DO NOTHING;

        DROP TABLE IF EXISTS "%1$s".tgt_component_property;
        CREATE UNLOGGED TABLE "%1$s".tgt_component_property (
            "ID"            bigint NOT NULL PRIMARY KEY
          , "COMPONENT_ID"  bigint NOT NULL
          , "DESCRIPTION"   varchar(255)
          , "GROUPNAME"     varchar(255)
          , "PROPERTYNAME"  varchar(255) NOT NULL
          , "PROPERTYTYPE"  varchar(255) NOT NULL
          , "PROPERTYVALUE" varchar(1024)
          , "UUID"          uuid NOT NULL
        );
        WITH rewritten AS (
            SELECT p."ID"
                 , cm.canonical_id AS "COMPONENT_ID"
                 , p."DESCRIPTION"
                 , p."GROUPNAME"
                 , p."PROPERTYNAME"
                 , CASE WHEN p."PROPERTYTYPE" = 'ENCRYPTEDSTRING' THEN 'STRING' ELSE p."PROPERTYTYPE" END AS "PROPERTYTYPE"
                 , CASE WHEN p."PROPERTYTYPE" = 'ENCRYPTEDSTRING' THEN NULL ELSE p."PROPERTYVALUE" END AS "PROPERTYVALUE"
                 , p."UUID"
              FROM "%1$s".src_component_property p
              JOIN "%1$s".component_canonical_id_map cm ON cm.orig_id = p."COMPONENT_ID"
             WHERE p."UUID" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        )
        INSERT INTO "%1$s".tgt_component_property
            ("ID", "COMPONENT_ID", "DESCRIPTION", "GROUPNAME", "PROPERTYNAME",
             "PROPERTYTYPE", "PROPERTYVALUE", "UUID")
        SELECT "ID"
             , "COMPONENT_ID"
             , "DESCRIPTION"
             , "GROUPNAME"
             , "PROPERTYNAME"
             , "PROPERTYTYPE"
             , "PROPERTYVALUE"
             , "UUID"::uuid
          FROM rewritten
         WHERE "PROPERTYTYPE" IN ('BOOLEAN', 'INTEGER', 'NUMBER', 'STRING', 'TIMESTAMP', 'URL', 'UUID')
        """,
        """
        INSERT INTO "COMPONENT_PROPERTY"
            ("ID", "COMPONENT_ID", "DESCRIPTION", "GROUPNAME", "PROPERTYNAME",
             "PROPERTYTYPE", "PROPERTYVALUE", "UUID")
        SELECT "ID"
             , "COMPONENT_ID"
             , "DESCRIPTION"
             , "GROUPNAME"
             , "PROPERTYNAME"
             , "PROPERTYTYPE"
             , "PROPERTYVALUE"
             , "UUID"
          FROM "%1$s".tgt_component_property
        """
    );

    /**
     * 1:1 migration of {@code DEPENDENCYMETRICS} with retention filtering, composite-key
     * dedup, FK rewrites, and drop of the surrogate {@code ID} column per
     * schema-changes §7.4. The v5 table is RANGE-partitioned on {@code LAST_OCCURRENCE}
     * with composite PK {@code (COMPONENT_ID, LAST_OCCURRENCE)}. {@code COMPONENT_ID} and
     * {@code PROJECT_ID} are rewritten through canonical-id maps; INNER JOINs drop rows
     * referencing excluded entities. Rows with {@code LAST_OCCURRENCE} older than the
     * {@code metrics_retention_cutoff_at} value in {@code migration_config} are dropped.
     * Tiebreaker for composite-key dedup keeps {@code MAX(ID)}.
     */
    private static final TableMigration DEPENDENCYMETRICS = new TableMigration(
        "DEPENDENCYMETRICS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_dependencymetrics (
            "ID"                                     bigint NOT NULL
          , "COMPONENT_ID"                           bigint NOT NULL
          , "CRITICAL"                               integer NOT NULL
          , "FINDINGS_AUDITED"                       integer
          , "FINDINGS_TOTAL"                         integer
          , "FINDINGS_UNAUDITED"                     integer
          , "FIRST_OCCURRENCE"                       timestamptz NOT NULL
          , "HIGH"                                   integer NOT NULL
          , "RISKSCORE"                              double precision NOT NULL
          , "LAST_OCCURRENCE"                        timestamptz NOT NULL
          , "LOW"                                    integer NOT NULL
          , "MEDIUM"                                 integer NOT NULL
          , "POLICYVIOLATIONS_AUDITED"               integer
          , "POLICYVIOLATIONS_FAIL"                  integer
          , "POLICYVIOLATIONS_INFO"                  integer
          , "POLICYVIOLATIONS_LICENSE_AUDITED"       integer
          , "POLICYVIOLATIONS_LICENSE_TOTAL"         integer
          , "POLICYVIOLATIONS_LICENSE_UNAUDITED"     integer
          , "POLICYVIOLATIONS_OPERATIONAL_AUDITED"   integer
          , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"     integer
          , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED" integer
          , "POLICYVIOLATIONS_SECURITY_AUDITED"      integer
          , "POLICYVIOLATIONS_SECURITY_TOTAL"        integer
          , "POLICYVIOLATIONS_SECURITY_UNAUDITED"    integer
          , "POLICYVIOLATIONS_TOTAL"                 integer
          , "POLICYVIOLATIONS_UNAUDITED"             integer
          , "POLICYVIOLATIONS_WARN"                  integer
          , "PROJECT_ID"                             bigint NOT NULL
          , "SUPPRESSED"                             integer NOT NULL
          , "UNASSIGNED_SEVERITY"                    integer
          , "VULNERABILITIES"                        integer NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "COMPONENT_ID"
             , "CRITICAL"
             , "FINDINGS_AUDITED"
             , "FINDINGS_TOTAL"
             , "FINDINGS_UNAUDITED"
             , "FIRST_OCCURRENCE"
             , "HIGH"
             , "RISKSCORE"
             , "LAST_OCCURRENCE"
             , "LOW"
             , "MEDIUM"
             , "POLICYVIOLATIONS_AUDITED"
             , "POLICYVIOLATIONS_FAIL"
             , "POLICYVIOLATIONS_INFO"
             , "POLICYVIOLATIONS_LICENSE_AUDITED"
             , "POLICYVIOLATIONS_LICENSE_TOTAL"
             , "POLICYVIOLATIONS_LICENSE_UNAUDITED"
             , "POLICYVIOLATIONS_OPERATIONAL_AUDITED"
             , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"
             , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
             , "POLICYVIOLATIONS_SECURITY_AUDITED"
             , "POLICYVIOLATIONS_SECURITY_TOTAL"
             , "POLICYVIOLATIONS_SECURITY_UNAUDITED"
             , "POLICYVIOLATIONS_TOTAL"
             , "POLICYVIOLATIONS_UNAUDITED"
             , "POLICYVIOLATIONS_WARN"
             , "PROJECT_ID"
             , "SUPPRESSED"
             , "UNASSIGNED_SEVERITY"
             , "VULNERABILITIES"
          FROM "%s"."DEPENDENCYMETRICS"
         ORDER BY "ID"
        """,
        List.of("ID", "COMPONENT_ID", "CRITICAL", "FINDINGS_AUDITED", "FINDINGS_TOTAL",
            "FINDINGS_UNAUDITED", "FIRST_OCCURRENCE", "HIGH", "RISKSCORE",
            "LAST_OCCURRENCE", "LOW", "MEDIUM",
            "POLICYVIOLATIONS_AUDITED", "POLICYVIOLATIONS_FAIL", "POLICYVIOLATIONS_INFO",
            "POLICYVIOLATIONS_LICENSE_AUDITED", "POLICYVIOLATIONS_LICENSE_TOTAL",
            "POLICYVIOLATIONS_LICENSE_UNAUDITED",
            "POLICYVIOLATIONS_OPERATIONAL_AUDITED", "POLICYVIOLATIONS_OPERATIONAL_TOTAL",
            "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED",
            "POLICYVIOLATIONS_SECURITY_AUDITED", "POLICYVIOLATIONS_SECURITY_TOTAL",
            "POLICYVIOLATIONS_SECURITY_UNAUDITED",
            "POLICYVIOLATIONS_TOTAL", "POLICYVIOLATIONS_UNAUDITED", "POLICYVIOLATIONS_WARN",
            "PROJECT_ID", "SUPPRESSED", "UNASSIGNED_SEVERITY", "VULNERABILITIES"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_dependencymetrics;
        CREATE UNLOGGED TABLE "%1$s".tgt_dependencymetrics (
            "COMPONENT_ID"                           bigint NOT NULL
          , "CRITICAL"                               integer NOT NULL
          , "FINDINGS_AUDITED"                       integer
          , "FINDINGS_TOTAL"                         integer
          , "FINDINGS_UNAUDITED"                     integer
          , "FIRST_OCCURRENCE"                       timestamptz NOT NULL
          , "HIGH"                                   integer NOT NULL
          , "RISKSCORE"                              double precision NOT NULL
          , "LAST_OCCURRENCE"                        timestamptz NOT NULL
          , "LOW"                                    integer NOT NULL
          , "MEDIUM"                                 integer NOT NULL
          , "POLICYVIOLATIONS_AUDITED"               integer
          , "POLICYVIOLATIONS_FAIL"                  integer
          , "POLICYVIOLATIONS_INFO"                  integer
          , "POLICYVIOLATIONS_LICENSE_AUDITED"       integer
          , "POLICYVIOLATIONS_LICENSE_TOTAL"         integer
          , "POLICYVIOLATIONS_LICENSE_UNAUDITED"     integer
          , "POLICYVIOLATIONS_OPERATIONAL_AUDITED"   integer
          , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"     integer
          , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED" integer
          , "POLICYVIOLATIONS_SECURITY_AUDITED"      integer
          , "POLICYVIOLATIONS_SECURITY_TOTAL"        integer
          , "POLICYVIOLATIONS_SECURITY_UNAUDITED"    integer
          , "POLICYVIOLATIONS_TOTAL"                 integer
          , "POLICYVIOLATIONS_UNAUDITED"             integer
          , "POLICYVIOLATIONS_WARN"                  integer
          , "PROJECT_ID"                             bigint NOT NULL
          , "SUPPRESSED"                             integer NOT NULL
          , "UNASSIGNED_SEVERITY"                    integer
          , "VULNERABILITIES"                        integer NOT NULL
          , PRIMARY KEY ("COMPONENT_ID", "LAST_OCCURRENCE")
        );
        INSERT INTO "%1$s".tgt_dependencymetrics (
            "COMPONENT_ID"
          , "CRITICAL"
          , "FINDINGS_AUDITED"
          , "FINDINGS_TOTAL"
          , "FINDINGS_UNAUDITED"
          , "FIRST_OCCURRENCE"
          , "HIGH"
          , "RISKSCORE"
          , "LAST_OCCURRENCE"
          , "LOW"
          , "MEDIUM"
          , "POLICYVIOLATIONS_AUDITED"
          , "POLICYVIOLATIONS_FAIL"
          , "POLICYVIOLATIONS_INFO"
          , "POLICYVIOLATIONS_LICENSE_AUDITED"
          , "POLICYVIOLATIONS_LICENSE_TOTAL"
          , "POLICYVIOLATIONS_LICENSE_UNAUDITED"
          , "POLICYVIOLATIONS_OPERATIONAL_AUDITED"
          , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"
          , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
          , "POLICYVIOLATIONS_SECURITY_AUDITED"
          , "POLICYVIOLATIONS_SECURITY_TOTAL"
          , "POLICYVIOLATIONS_SECURITY_UNAUDITED"
          , "POLICYVIOLATIONS_TOTAL"
          , "POLICYVIOLATIONS_UNAUDITED"
          , "POLICYVIOLATIONS_WARN"
          , "PROJECT_ID"
          , "SUPPRESSED"
          , "UNASSIGNED_SEVERITY"
          , "VULNERABILITIES"
        )
        SELECT "COMPONENT_ID"
             , "CRITICAL"
             , "FINDINGS_AUDITED"
             , "FINDINGS_TOTAL"
             , "FINDINGS_UNAUDITED"
             , "FIRST_OCCURRENCE"
             , "HIGH"
             , "RISKSCORE"
             , "LAST_OCCURRENCE"
             , "LOW"
             , "MEDIUM"
             , "POLICYVIOLATIONS_AUDITED"
             , "POLICYVIOLATIONS_FAIL"
             , "POLICYVIOLATIONS_INFO"
             , "POLICYVIOLATIONS_LICENSE_AUDITED"
             , "POLICYVIOLATIONS_LICENSE_TOTAL"
             , "POLICYVIOLATIONS_LICENSE_UNAUDITED"
             , "POLICYVIOLATIONS_OPERATIONAL_AUDITED"
             , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"
             , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
             , "POLICYVIOLATIONS_SECURITY_AUDITED"
             , "POLICYVIOLATIONS_SECURITY_TOTAL"
             , "POLICYVIOLATIONS_SECURITY_UNAUDITED"
             , "POLICYVIOLATIONS_TOTAL"
             , "POLICYVIOLATIONS_UNAUDITED"
             , "POLICYVIOLATIONS_WARN"
             , "PROJECT_ID"
             , "SUPPRESSED"
             , "UNASSIGNED_SEVERITY"
             , "VULNERABILITIES"
          FROM (
            SELECT cm.canonical_id AS "COMPONENT_ID"
                 , m."CRITICAL"
                 , m."FINDINGS_AUDITED"
                 , m."FINDINGS_TOTAL"
                 , m."FINDINGS_UNAUDITED"
                 , m."FIRST_OCCURRENCE"
                 , m."HIGH"
                 , m."RISKSCORE"
                 , m."LAST_OCCURRENCE"
                 , m."LOW"
                 , m."MEDIUM"
                 , m."POLICYVIOLATIONS_AUDITED"
                 , m."POLICYVIOLATIONS_FAIL"
                 , m."POLICYVIOLATIONS_INFO"
                 , m."POLICYVIOLATIONS_LICENSE_AUDITED"
                 , m."POLICYVIOLATIONS_LICENSE_TOTAL"
                 , m."POLICYVIOLATIONS_LICENSE_UNAUDITED"
                 , m."POLICYVIOLATIONS_OPERATIONAL_AUDITED"
                 , m."POLICYVIOLATIONS_OPERATIONAL_TOTAL"
                 , m."POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
                 , m."POLICYVIOLATIONS_SECURITY_AUDITED"
                 , m."POLICYVIOLATIONS_SECURITY_TOTAL"
                 , m."POLICYVIOLATIONS_SECURITY_UNAUDITED"
                 , m."POLICYVIOLATIONS_TOTAL"
                 , m."POLICYVIOLATIONS_UNAUDITED"
                 , m."POLICYVIOLATIONS_WARN"
                 , pm.canonical_id AS "PROJECT_ID"
                 , m."SUPPRESSED"
                 , m."UNASSIGNED_SEVERITY"
                 , m."VULNERABILITIES"
                 , ROW_NUMBER() OVER ( PARTITION BY cm.canonical_id, m."LAST_OCCURRENCE"
                     ORDER BY m."ID" DESC
                   ) AS rn
              FROM "%1$s".src_dependencymetrics m
              JOIN "%1$s".component_canonical_id_map cm ON cm.orig_id = m."COMPONENT_ID"
              JOIN "%1$s".project_canonical_id_map   pm ON pm.orig_id = m."PROJECT_ID"
             WHERE m."LAST_OCCURRENCE" >= (
                 SELECT value::timestamptz FROM "%1$s".migration_config
                  WHERE key = 'metrics_retention_cutoff_at'
             )
          ) ranked
         WHERE rn = 1
        """,
        """
        INSERT INTO "DEPENDENCYMETRICS" (
            "COMPONENT_ID"
          , "CRITICAL"
          , "FINDINGS_AUDITED"
          , "FINDINGS_TOTAL"
          , "FINDINGS_UNAUDITED"
          , "FIRST_OCCURRENCE"
          , "HIGH"
          , "RISKSCORE"
          , "LAST_OCCURRENCE"
          , "LOW"
          , "MEDIUM"
          , "POLICYVIOLATIONS_AUDITED"
          , "POLICYVIOLATIONS_FAIL"
          , "POLICYVIOLATIONS_INFO"
          , "POLICYVIOLATIONS_LICENSE_AUDITED"
          , "POLICYVIOLATIONS_LICENSE_TOTAL"
          , "POLICYVIOLATIONS_LICENSE_UNAUDITED"
          , "POLICYVIOLATIONS_OPERATIONAL_AUDITED"
          , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"
          , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
          , "POLICYVIOLATIONS_SECURITY_AUDITED"
          , "POLICYVIOLATIONS_SECURITY_TOTAL"
          , "POLICYVIOLATIONS_SECURITY_UNAUDITED"
          , "POLICYVIOLATIONS_TOTAL"
          , "POLICYVIOLATIONS_UNAUDITED"
          , "POLICYVIOLATIONS_WARN"
          , "PROJECT_ID"
          , "SUPPRESSED"
          , "UNASSIGNED_SEVERITY"
          , "VULNERABILITIES"
        )
        SELECT "COMPONENT_ID"
             , "CRITICAL"
             , "FINDINGS_AUDITED"
             , "FINDINGS_TOTAL"
             , "FINDINGS_UNAUDITED"
             , "FIRST_OCCURRENCE"
             , "HIGH"
             , "RISKSCORE"
             , "LAST_OCCURRENCE"
             , "LOW"
             , "MEDIUM"
             , "POLICYVIOLATIONS_AUDITED"
             , "POLICYVIOLATIONS_FAIL"
             , "POLICYVIOLATIONS_INFO"
             , "POLICYVIOLATIONS_LICENSE_AUDITED"
             , "POLICYVIOLATIONS_LICENSE_TOTAL"
             , "POLICYVIOLATIONS_LICENSE_UNAUDITED"
             , "POLICYVIOLATIONS_OPERATIONAL_AUDITED"
             , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"
             , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
             , "POLICYVIOLATIONS_SECURITY_AUDITED"
             , "POLICYVIOLATIONS_SECURITY_TOTAL"
             , "POLICYVIOLATIONS_SECURITY_UNAUDITED"
             , "POLICYVIOLATIONS_TOTAL"
             , "POLICYVIOLATIONS_UNAUDITED"
             , "POLICYVIOLATIONS_WARN"
             , "PROJECT_ID"
             , "SUPPRESSED"
             , "UNASSIGNED_SEVERITY"
             , "VULNERABILITIES"
          FROM "%1$s".tgt_dependencymetrics
        """
    );

    /**
     * 1:1 migration of {@code PROJECTMETRICS} with retention filtering, composite-key
     * dedup, FK rewrite, and drop of the surrogate {@code ID} column plus the v4-only
     * {@code COLLECTION_LOGIC} / {@code COLLECTION_LOGIC_CHANGED} columns per
     * schema-changes §7.4. The v5 table is RANGE-partitioned on {@code LAST_OCCURRENCE}
     * with composite PK {@code (PROJECT_ID, LAST_OCCURRENCE)}. {@code PROJECT_ID} is
     * rewritten through {@code project_canonical_id_map}. Tiebreaker for composite-key
     * dedup keeps {@code MAX(ID)}.
     */
    private static final TableMigration PROJECTMETRICS = new TableMigration(
        "PROJECTMETRICS",
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS "%s".src_projectmetrics (
            "ID"                                     bigint NOT NULL
          , "COLLECTION_LOGIC"                       varchar(255)
          , "COLLECTION_LOGIC_CHANGED"               boolean
          , "COMPONENTS"                             integer NOT NULL
          , "CRITICAL"                               integer NOT NULL
          , "FINDINGS_AUDITED"                       integer
          , "FINDINGS_TOTAL"                         integer
          , "FINDINGS_UNAUDITED"                     integer
          , "FIRST_OCCURRENCE"                       timestamptz NOT NULL
          , "HIGH"                                   integer NOT NULL
          , "RISKSCORE"                              double precision NOT NULL
          , "LAST_OCCURRENCE"                        timestamptz NOT NULL
          , "LOW"                                    integer NOT NULL
          , "MEDIUM"                                 integer NOT NULL
          , "POLICYVIOLATIONS_AUDITED"               integer
          , "POLICYVIOLATIONS_FAIL"                  integer
          , "POLICYVIOLATIONS_INFO"                  integer
          , "POLICYVIOLATIONS_LICENSE_AUDITED"       integer
          , "POLICYVIOLATIONS_LICENSE_TOTAL"         integer
          , "POLICYVIOLATIONS_LICENSE_UNAUDITED"     integer
          , "POLICYVIOLATIONS_OPERATIONAL_AUDITED"   integer
          , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"     integer
          , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED" integer
          , "POLICYVIOLATIONS_SECURITY_AUDITED"      integer
          , "POLICYVIOLATIONS_SECURITY_TOTAL"        integer
          , "POLICYVIOLATIONS_SECURITY_UNAUDITED"    integer
          , "POLICYVIOLATIONS_TOTAL"                 integer
          , "POLICYVIOLATIONS_UNAUDITED"             integer
          , "POLICYVIOLATIONS_WARN"                  integer
          , "PROJECT_ID"                             bigint NOT NULL
          , "SUPPRESSED"                             integer NOT NULL
          , "UNASSIGNED_SEVERITY"                    integer
          , "VULNERABILITIES"                        integer NOT NULL
          , "VULNERABLECOMPONENTS"                   integer NOT NULL
        )
        """,
        """
        SELECT "ID"
             , "COLLECTION_LOGIC"
             , "COLLECTION_LOGIC_CHANGED"
             , "COMPONENTS"
             , "CRITICAL"
             , "FINDINGS_AUDITED"
             , "FINDINGS_TOTAL"
             , "FINDINGS_UNAUDITED"
             , "FIRST_OCCURRENCE"
             , "HIGH"
             , "RISKSCORE"
             , "LAST_OCCURRENCE"
             , "LOW"
             , "MEDIUM"
             , "POLICYVIOLATIONS_AUDITED"
             , "POLICYVIOLATIONS_FAIL"
             , "POLICYVIOLATIONS_INFO"
             , "POLICYVIOLATIONS_LICENSE_AUDITED"
             , "POLICYVIOLATIONS_LICENSE_TOTAL"
             , "POLICYVIOLATIONS_LICENSE_UNAUDITED"
             , "POLICYVIOLATIONS_OPERATIONAL_AUDITED"
             , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"
             , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
             , "POLICYVIOLATIONS_SECURITY_AUDITED"
             , "POLICYVIOLATIONS_SECURITY_TOTAL"
             , "POLICYVIOLATIONS_SECURITY_UNAUDITED"
             , "POLICYVIOLATIONS_TOTAL"
             , "POLICYVIOLATIONS_UNAUDITED"
             , "POLICYVIOLATIONS_WARN"
             , "PROJECT_ID"
             , "SUPPRESSED"
             , "UNASSIGNED_SEVERITY"
             , "VULNERABILITIES"
             , "VULNERABLECOMPONENTS"
          FROM "%s"."PROJECTMETRICS"
         ORDER BY "ID"
        """,
        List.of("ID", "COLLECTION_LOGIC", "COLLECTION_LOGIC_CHANGED",
            "COMPONENTS", "CRITICAL", "FINDINGS_AUDITED", "FINDINGS_TOTAL",
            "FINDINGS_UNAUDITED", "FIRST_OCCURRENCE", "HIGH", "RISKSCORE",
            "LAST_OCCURRENCE", "LOW", "MEDIUM",
            "POLICYVIOLATIONS_AUDITED", "POLICYVIOLATIONS_FAIL", "POLICYVIOLATIONS_INFO",
            "POLICYVIOLATIONS_LICENSE_AUDITED", "POLICYVIOLATIONS_LICENSE_TOTAL",
            "POLICYVIOLATIONS_LICENSE_UNAUDITED",
            "POLICYVIOLATIONS_OPERATIONAL_AUDITED", "POLICYVIOLATIONS_OPERATIONAL_TOTAL",
            "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED",
            "POLICYVIOLATIONS_SECURITY_AUDITED", "POLICYVIOLATIONS_SECURITY_TOTAL",
            "POLICYVIOLATIONS_SECURITY_UNAUDITED",
            "POLICYVIOLATIONS_TOTAL", "POLICYVIOLATIONS_UNAUDITED", "POLICYVIOLATIONS_WARN",
            "PROJECT_ID", "SUPPRESSED", "UNASSIGNED_SEVERITY",
            "VULNERABILITIES", "VULNERABLECOMPONENTS"),
        """
        DROP TABLE IF EXISTS "%1$s".tgt_projectmetrics;
        CREATE UNLOGGED TABLE "%1$s".tgt_projectmetrics (
            "COMPONENTS"                             integer NOT NULL
          , "CRITICAL"                               integer NOT NULL
          , "FINDINGS_AUDITED"                       integer
          , "FINDINGS_TOTAL"                         integer
          , "FINDINGS_UNAUDITED"                     integer
          , "FIRST_OCCURRENCE"                       timestamptz NOT NULL
          , "HIGH"                                   integer NOT NULL
          , "RISKSCORE"                              double precision NOT NULL
          , "LAST_OCCURRENCE"                        timestamptz NOT NULL
          , "LOW"                                    integer NOT NULL
          , "MEDIUM"                                 integer NOT NULL
          , "POLICYVIOLATIONS_AUDITED"               integer
          , "POLICYVIOLATIONS_FAIL"                  integer
          , "POLICYVIOLATIONS_INFO"                  integer
          , "POLICYVIOLATIONS_LICENSE_AUDITED"       integer
          , "POLICYVIOLATIONS_LICENSE_TOTAL"         integer
          , "POLICYVIOLATIONS_LICENSE_UNAUDITED"     integer
          , "POLICYVIOLATIONS_OPERATIONAL_AUDITED"   integer
          , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"     integer
          , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED" integer
          , "POLICYVIOLATIONS_SECURITY_AUDITED"      integer
          , "POLICYVIOLATIONS_SECURITY_TOTAL"        integer
          , "POLICYVIOLATIONS_SECURITY_UNAUDITED"    integer
          , "POLICYVIOLATIONS_TOTAL"                 integer
          , "POLICYVIOLATIONS_UNAUDITED"             integer
          , "POLICYVIOLATIONS_WARN"                  integer
          , "PROJECT_ID"                             bigint NOT NULL
          , "SUPPRESSED"                             integer NOT NULL
          , "UNASSIGNED_SEVERITY"                    integer
          , "VULNERABILITIES"                        integer NOT NULL
          , "VULNERABLECOMPONENTS"                   integer NOT NULL
          , PRIMARY KEY ("PROJECT_ID", "LAST_OCCURRENCE")
        );
        INSERT INTO "%1$s".tgt_projectmetrics (
            "COMPONENTS"
          , "CRITICAL"
          , "FINDINGS_AUDITED"
          , "FINDINGS_TOTAL"
          , "FINDINGS_UNAUDITED"
          , "FIRST_OCCURRENCE"
          , "HIGH"
          , "RISKSCORE"
          , "LAST_OCCURRENCE"
          , "LOW"
          , "MEDIUM"
          , "POLICYVIOLATIONS_AUDITED"
          , "POLICYVIOLATIONS_FAIL"
          , "POLICYVIOLATIONS_INFO"
          , "POLICYVIOLATIONS_LICENSE_AUDITED"
          , "POLICYVIOLATIONS_LICENSE_TOTAL"
          , "POLICYVIOLATIONS_LICENSE_UNAUDITED"
          , "POLICYVIOLATIONS_OPERATIONAL_AUDITED"
          , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"
          , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
          , "POLICYVIOLATIONS_SECURITY_AUDITED"
          , "POLICYVIOLATIONS_SECURITY_TOTAL"
          , "POLICYVIOLATIONS_SECURITY_UNAUDITED"
          , "POLICYVIOLATIONS_TOTAL"
          , "POLICYVIOLATIONS_UNAUDITED"
          , "POLICYVIOLATIONS_WARN"
          , "PROJECT_ID"
          , "SUPPRESSED"
          , "UNASSIGNED_SEVERITY"
          , "VULNERABILITIES"
          , "VULNERABLECOMPONENTS"
        )
        SELECT "COMPONENTS"
             , "CRITICAL"
             , "FINDINGS_AUDITED"
             , "FINDINGS_TOTAL"
             , "FINDINGS_UNAUDITED"
             , "FIRST_OCCURRENCE"
             , "HIGH"
             , "RISKSCORE"
             , "LAST_OCCURRENCE"
             , "LOW"
             , "MEDIUM"
             , "POLICYVIOLATIONS_AUDITED"
             , "POLICYVIOLATIONS_FAIL"
             , "POLICYVIOLATIONS_INFO"
             , "POLICYVIOLATIONS_LICENSE_AUDITED"
             , "POLICYVIOLATIONS_LICENSE_TOTAL"
             , "POLICYVIOLATIONS_LICENSE_UNAUDITED"
             , "POLICYVIOLATIONS_OPERATIONAL_AUDITED"
             , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"
             , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
             , "POLICYVIOLATIONS_SECURITY_AUDITED"
             , "POLICYVIOLATIONS_SECURITY_TOTAL"
             , "POLICYVIOLATIONS_SECURITY_UNAUDITED"
             , "POLICYVIOLATIONS_TOTAL"
             , "POLICYVIOLATIONS_UNAUDITED"
             , "POLICYVIOLATIONS_WARN"
             , "PROJECT_ID"
             , "SUPPRESSED"
             , "UNASSIGNED_SEVERITY"
             , "VULNERABILITIES"
             , "VULNERABLECOMPONENTS"
          FROM (
            SELECT m."COMPONENTS"
                 , m."CRITICAL"
                 , m."FINDINGS_AUDITED"
                 , m."FINDINGS_TOTAL"
                 , m."FINDINGS_UNAUDITED"
                 , m."FIRST_OCCURRENCE"
                 , m."HIGH"
                 , m."RISKSCORE"
                 , m."LAST_OCCURRENCE"
                 , m."LOW"
                 , m."MEDIUM"
                 , m."POLICYVIOLATIONS_AUDITED"
                 , m."POLICYVIOLATIONS_FAIL"
                 , m."POLICYVIOLATIONS_INFO"
                 , m."POLICYVIOLATIONS_LICENSE_AUDITED"
                 , m."POLICYVIOLATIONS_LICENSE_TOTAL"
                 , m."POLICYVIOLATIONS_LICENSE_UNAUDITED"
                 , m."POLICYVIOLATIONS_OPERATIONAL_AUDITED"
                 , m."POLICYVIOLATIONS_OPERATIONAL_TOTAL"
                 , m."POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
                 , m."POLICYVIOLATIONS_SECURITY_AUDITED"
                 , m."POLICYVIOLATIONS_SECURITY_TOTAL"
                 , m."POLICYVIOLATIONS_SECURITY_UNAUDITED"
                 , m."POLICYVIOLATIONS_TOTAL"
                 , m."POLICYVIOLATIONS_UNAUDITED"
                 , m."POLICYVIOLATIONS_WARN"
                 , pm.canonical_id AS "PROJECT_ID"
                 , m."SUPPRESSED"
                 , m."UNASSIGNED_SEVERITY"
                 , m."VULNERABILITIES"
                 , m."VULNERABLECOMPONENTS"
                 , ROW_NUMBER() OVER ( PARTITION BY pm.canonical_id, m."LAST_OCCURRENCE"
                     ORDER BY m."ID" DESC
                   ) AS rn
              FROM "%1$s".src_projectmetrics m
              JOIN "%1$s".project_canonical_id_map pm ON pm.orig_id = m."PROJECT_ID"
             WHERE m."LAST_OCCURRENCE" >= (
                 SELECT value::timestamptz FROM "%1$s".migration_config
                  WHERE key = 'metrics_retention_cutoff_at'
             )
          ) ranked
         WHERE rn = 1
        """,
        """
        INSERT INTO "PROJECTMETRICS" (
            "COMPONENTS"
          , "CRITICAL"
          , "FINDINGS_AUDITED"
          , "FINDINGS_TOTAL"
          , "FINDINGS_UNAUDITED"
          , "FIRST_OCCURRENCE"
          , "HIGH"
          , "RISKSCORE"
          , "LAST_OCCURRENCE"
          , "LOW"
          , "MEDIUM"
          , "POLICYVIOLATIONS_AUDITED"
          , "POLICYVIOLATIONS_FAIL"
          , "POLICYVIOLATIONS_INFO"
          , "POLICYVIOLATIONS_LICENSE_AUDITED"
          , "POLICYVIOLATIONS_LICENSE_TOTAL"
          , "POLICYVIOLATIONS_LICENSE_UNAUDITED"
          , "POLICYVIOLATIONS_OPERATIONAL_AUDITED"
          , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"
          , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
          , "POLICYVIOLATIONS_SECURITY_AUDITED"
          , "POLICYVIOLATIONS_SECURITY_TOTAL"
          , "POLICYVIOLATIONS_SECURITY_UNAUDITED"
          , "POLICYVIOLATIONS_TOTAL"
          , "POLICYVIOLATIONS_UNAUDITED"
          , "POLICYVIOLATIONS_WARN"
          , "PROJECT_ID"
          , "SUPPRESSED"
          , "UNASSIGNED_SEVERITY"
          , "VULNERABILITIES"
          , "VULNERABLECOMPONENTS"
        )
        SELECT "COMPONENTS"
             , "CRITICAL"
             , "FINDINGS_AUDITED"
             , "FINDINGS_TOTAL"
             , "FINDINGS_UNAUDITED"
             , "FIRST_OCCURRENCE"
             , "HIGH"
             , "RISKSCORE"
             , "LAST_OCCURRENCE"
             , "LOW"
             , "MEDIUM"
             , "POLICYVIOLATIONS_AUDITED"
             , "POLICYVIOLATIONS_FAIL"
             , "POLICYVIOLATIONS_INFO"
             , "POLICYVIOLATIONS_LICENSE_AUDITED"
             , "POLICYVIOLATIONS_LICENSE_TOTAL"
             , "POLICYVIOLATIONS_LICENSE_UNAUDITED"
             , "POLICYVIOLATIONS_OPERATIONAL_AUDITED"
             , "POLICYVIOLATIONS_OPERATIONAL_TOTAL"
             , "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED"
             , "POLICYVIOLATIONS_SECURITY_AUDITED"
             , "POLICYVIOLATIONS_SECURITY_TOTAL"
             , "POLICYVIOLATIONS_SECURITY_UNAUDITED"
             , "POLICYVIOLATIONS_TOTAL"
             , "POLICYVIOLATIONS_UNAUDITED"
             , "POLICYVIOLATIONS_WARN"
             , "PROJECT_ID"
             , "SUPPRESSED"
             , "UNASSIGNED_SEVERITY"
             , "VULNERABILITIES"
             , "VULNERABLECOMPONENTS"
          FROM "%1$s".tgt_projectmetrics
        """
    );

    /**
     * Load order. Respects v5 FK dependencies per pipeline design §9.
     */
    private static final List<TableMigration> ALL = List.of(
        // Reference / leaf tables
        LICENSE,
        LICENSEGROUP,
        LICENSEGROUP_LICENSE,
        TEAM,
        TAG,
        OIDCGROUP,
        REPOSITORY,
        // Legacy user sources (no v5 counterpart, consumed by USER consolidation)
        LDAPUSER,
        MANAGEDUSER,
        OIDCUSER,
        LDAPUSERS_TEAMS,
        MANAGEDUSERS_TEAMS,
        OIDCUSERS_TEAMS,
        // Derived consolidations
        USER_CONSOLIDATED,
        USERS_TEAMS,
        // PERMISSION mapping and the consolidated USERS_PERMISSIONS join
        PERMISSION,
        LDAPUSERS_PERMISSIONS,
        MANAGEDUSERS_PERMISSIONS,
        OIDCUSERS_PERMISSIONS,
        USERS_PERMISSIONS,
        // PROJECT and its derived closure
        PROJECT,
        PROJECT_HIERARCHY,
        PROJECT_METADATA,
        PROJECT_ACCESS_TEAMS,
        PROJECT_ACCESS_USERS,
        PROJECTS_TAGS,
        REPOSITORY_META_COMPONENT,
        COMPONENT,
        SERVICECOMPONENT,
        PACKAGE_METADATA,
        // API keys and team-scoped adjuncts (FK order: APIKEY -> APIKEYS_TEAMS;
        // TEAMS_PERMISSIONS -> TEAM + PERMISSION; MAPPEDLDAPGROUP -> TEAM;
        // MAPPEDOIDCGROUP -> TEAM + OIDCGROUP)
        APIKEY,
        APIKEYS_TEAMS,
        TEAMS_PERMISSIONS,
        MAPPEDLDAPGROUP,
        MAPPEDOIDCGROUP,
        // Vulnerability family (peers; downstream join tables come later)
        VULNERABILITY,
        VULNERABLESOFTWARE,
        VULNERABILITYMETRICS,
        VULNERABILITYALIAS,
        VULNERABILITY_ALIAS,
        VULNERABILITY_ALIAS_ASSERTION,
        // Vulnerability join tables (FK-dependent on COMPONENT + VULNERABILITY + VULNERABLESOFTWARE)
        COMPONENTS_VULNERABILITIES,
        SERVICECOMPONENTS_VULNERABILITIES,
        VULNERABLESOFTWARE_VULNERABILITIES,
        AFFECTEDVERSIONATTRIBUTION,
        // BOM / VEX (FK-dependent on PROJECT)
        BOM,
        VEX,
        // Notification chain (FK order: publisher -> rule -> join tables)
        NOTIFICATIONPUBLISHER,
        NOTIFICATIONRULE,
        NOTIFICATIONRULE_TAGS,
        NOTIFICATIONRULE_TEAMS,
        NOTIFICATIONRULE_PROJECTS,
        // Policy chain (FK order: POLICY -> POLICYCONDITION, POLICY_TAGS, POLICY_PROJECTS)
        POLICY,
        POLICYCONDITION,
        POLICY_TAGS,
        POLICY_PROJECTS,
        // Findings chain (FK order: FINDINGATTRIBUTION, POLICYVIOLATION, ANALYSIS,
        // ANALYSISCOMMENT, VIOLATIONANALYSIS, VIOLATIONANALYSISCOMMENT)
        FINDINGATTRIBUTION,
        POLICYVIOLATION,
        ANALYSIS,
        ANALYSISCOMMENT,
        VIOLATIONANALYSIS,
        VIOLATIONANALYSISCOMMENT,
        // Property tables (FK order: CONFIGPROPERTY standalone; PROJECT_PROPERTY ← PROJECT;
        // COMPONENT_PROPERTY ← COMPONENT)
        CONFIGPROPERTY,
        PROJECT_PROPERTY,
        COMPONENT_PROPERTY,
        // Metrics tables (FK order: PROJECTMETRICS ← PROJECT; DEPENDENCYMETRICS ← COMPONENT + PROJECT).
        // Partitions are pre-created in LoadPhase.preLoad().
        PROJECTMETRICS,
        DEPENDENCYMETRICS
    );

    private TableRegistry() {
    }

    public static List<TableMigration> all() {
        return ALL;
    }

    public static List<TableMigration> extracted() {
        return ALL.stream().filter(TableMigration::hasExtract).toList();
    }

    public static List<TableMigration> transformed() {
        return ALL.stream().filter(TableMigration::hasTransform).toList();
    }

    public static List<TableMigration> loaded() {
        return ALL.stream().filter(TableMigration::hasLoad).toList();
    }
}
