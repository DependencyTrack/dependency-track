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

import org.dependencytrack.v4migrator.config.GlobalOptions;
import org.dependencytrack.v4migrator.config.SourceOptions;
import org.dependencytrack.v4migrator.extract.ExtractPhase;
import org.dependencytrack.v4migrator.load.LoadPhase;
import org.dependencytrack.v4migrator.testsupport.V4PostgresSource;
import org.dependencytrack.v4migrator.testsupport.V5TargetContainer;
import org.dependencytrack.v4migrator.transform.TransformPhase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises the v4 PERMISSION → v5 PERMISSION migration. The migrator seeds v5
 * {@code PERMISSION} with the full v5 catalog and builds {@code permission_name_map} by
 * inner-joining v4 NAME against v5 PERMISSION; v4 names absent from v5 (e.g.
 * {@code VIEW_BADGES}) drop out and their join rows are silently removed. The migrator
 * also fans v4 {@code ACCESS_MANAGEMENT} out to v5 {@code PORTFOLIO_ACCESS_CONTROL_BYPASS}
 * (preserving v4's implicit portfolio-access-control bypass) and v4
 * {@code SYSTEM_CONFIGURATION} out to v5 {@code SECRET_MANAGEMENT} (preserving v4's implicit
 * secret-management ability).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class UsersPermissionsIT {

    private V4PostgresSource source;
    private V5TargetContainer target;

    @BeforeAll
    void start() {
        source = new V4PostgresSource().start();
        target = new V5TargetContainer().start();
    }

    @AfterAll
    void stop() {
        if (source != null) {
            source.close();
        }
        if (target != null) {
            target.close();
        }
    }

    @Test
    @Order(1)
    void mapsPermissionsByNameAndRewritesJoins() throws Exception {
        // Seed v4: a TEAM, four permissions (two carried over to v5, one v4-only, one that
        // implies a v5-only permission), a MANAGED user "alice" with VIEW_PORTFOLIO and the
        // v4-only one, an LDAP user "bob" with only the v4-only one, an OIDC user "carol" with
        // ACCESS_MANAGEMENT to exercise the bypass fan-out, and a MANAGED user "dave" with
        // SYSTEM_CONFIGURATION to exercise the secret-management fan-out. Engineering holds
        // both ACCESS_MANAGEMENT and SYSTEM_CONFIGURATION to exercise both fan-outs at the team level.
        source.jdbi().useHandle(h -> {
            h.execute("INSERT INTO \"TEAM\" (\"ID\", \"NAME\", \"UUID\") VALUES (1, 'Engineering', '11111111-1111-1111-1111-111111111111')");
            h.execute("INSERT INTO \"PERMISSION\" (\"ID\", \"NAME\") VALUES (1, 'VIEW_PORTFOLIO')");
            // VIEW_BADGES was a v4 permission that v5 removed; verifies v4-only names drop out.
            h.execute("INSERT INTO \"PERMISSION\" (\"ID\", \"NAME\") VALUES (2, 'VIEW_BADGES')");
            h.execute("INSERT INTO \"PERMISSION\" (\"ID\", \"NAME\") VALUES (3, 'ACCESS_MANAGEMENT')");
            h.execute("INSERT INTO \"PERMISSION\" (\"ID\", \"NAME\") VALUES (4, 'SYSTEM_CONFIGURATION')");
            h.execute("""
                INSERT INTO "MANAGEDUSER" (
                    "ID", "USERNAME", "PASSWORD", "FULLNAME", "EMAIL",
                    "FORCE_PASSWORD_CHANGE", "LAST_PASSWORD_CHANGE",
                    "NON_EXPIRY_PASSWORD", "SUSPENDED"
                )
                VALUES (10, 'alice', 'hash', 'Alice Managed', 'alice@example.com',
                        FALSE, '2025-01-01T00:00:00Z', FALSE, FALSE)
                """);
            h.execute("""
                INSERT INTO "LDAPUSER" ("ID", "USERNAME", "DN", "EMAIL")
                VALUES (20, 'bob', 'cn=bob,dc=example,dc=com', 'bob@ldap.example.com')
                """);
            h.execute("""
                INSERT INTO "OIDCUSER" ("ID", "USERNAME", "EMAIL", "SUBJECT_IDENTIFIER")
                VALUES (30, 'carol', 'carol@oidc.example.com', 'sub-carol')
                """);
            h.execute("""
                INSERT INTO "MANAGEDUSER" (
                    "ID", "USERNAME", "PASSWORD", "FULLNAME", "EMAIL",
                    "FORCE_PASSWORD_CHANGE", "LAST_PASSWORD_CHANGE",
                    "NON_EXPIRY_PASSWORD", "SUSPENDED"
                )
                VALUES (40, 'dave', 'hash', 'Dave Managed', 'dave@example.com',
                        FALSE, '2025-01-01T00:00:00Z', FALSE, FALSE)
                """);
            h.execute("INSERT INTO \"MANAGEDUSERS_PERMISSIONS\" (\"MANAGEDUSER_ID\", \"PERMISSION_ID\") VALUES (10, 1)");
            h.execute("INSERT INTO \"MANAGEDUSERS_PERMISSIONS\" (\"MANAGEDUSER_ID\", \"PERMISSION_ID\") VALUES (10, 2)");
            h.execute("INSERT INTO \"LDAPUSERS_PERMISSIONS\" (\"LDAPUSER_ID\", \"PERMISSION_ID\") VALUES (20, 2)");
            h.execute("INSERT INTO \"OIDCUSERS_PERMISSIONS\" (\"OIDCUSER_ID\", \"PERMISSION_ID\") VALUES (30, 3)");
            h.execute("INSERT INTO \"MANAGEDUSERS_PERMISSIONS\" (\"MANAGEDUSER_ID\", \"PERMISSION_ID\") VALUES (40, 4)");
            h.execute("INSERT INTO \"TEAMS_PERMISSIONS\" (\"TEAM_ID\", \"PERMISSION_ID\") VALUES (1, 3)");
            h.execute("INSERT INTO \"TEAMS_PERMISSIONS\" (\"TEAM_ID\", \"PERMISSION_ID\") VALUES (1, 4)");
        });

        runPipeline();

        // permission_name_map: only v4 names that match a seeded v5 catalog entry survive.
        // VIEW_BADGES is v4-only and drops out of the inner join against v5 PERMISSION.
        final List<Map<String, Object>> mapRows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT orig_id, name
                      FROM dt_v4_migration.permission_name_map
                     ORDER BY orig_id
                    """)
                .mapToMap()
                .list());

        assertThat(mapRows).extracting(m -> m.get("name"))
            .containsExactlyInAnyOrder("VIEW_PORTFOLIO", "ACCESS_MANAGEMENT", "SYSTEM_CONFIGURATION");

        // Full v5 catalog is seeded regardless of which subset v4 had. PORTFOLIO_ACCESS_CONTROL_BYPASS
        // (a v5.6.0 addition not present in v4) must be available for the implication fan-out below.
        final List<String> perms = target.jdbi().withHandle(h ->
            h.createQuery("SELECT \"NAME\" FROM \"PERMISSION\" ORDER BY \"NAME\"")
                .mapTo(String.class)
                .list());
        assertThat(perms).contains(
            "ACCESS_MANAGEMENT", "ACCESS_MANAGEMENT_CREATE", "ACCESS_MANAGEMENT_READ",
            "ACCESS_MANAGEMENT_UPDATE", "ACCESS_MANAGEMENT_DELETE",
            "PORTFOLIO_ACCESS_CONTROL_BYPASS", "VIEW_PORTFOLIO",
            "SECRET_MANAGEMENT", "SYSTEM_CONFIGURATION");
        assertThat(perms).doesNotContain("VIEW_BADGES");

        // USERS_PERMISSIONS final state:
        //   - alice keeps VIEW_PORTFOLIO; her VIEW_BADGES assignment drops with the name.
        //   - bob's only assignment was VIEW_BADGES, so he ends with no permissions.
        //   - carol keeps ACCESS_MANAGEMENT AND gains PORTFOLIO_ACCESS_CONTROL_BYPASS via fan-out.
        //   - dave keeps SYSTEM_CONFIGURATION AND gains SECRET_MANAGEMENT via fan-out.
        final List<Map<String, Object>> userPerms = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT u."USERNAME" AS username, p."NAME" AS permission_name
                      FROM "USERS_PERMISSIONS" up
                      JOIN "USER" u       ON u."ID" = up."USER_ID"
                      JOIN "PERMISSION" p ON p."ID" = up."PERMISSION_ID"
                     ORDER BY u."USERNAME", p."NAME"
                    """)
                .mapToMap()
                .list());

        assertThat(userPerms).extracting(m -> m.get("username") + ":" + m.get("permission_name"))
            .containsExactlyInAnyOrder(
                "alice:VIEW_PORTFOLIO",
                "carol:ACCESS_MANAGEMENT",
                "carol:PORTFOLIO_ACCESS_CONTROL_BYPASS",
                "dave:SYSTEM_CONFIGURATION",
                "dave:SECRET_MANAGEMENT");

        // TEAMS_PERMISSIONS: Engineering held ACCESS_MANAGEMENT and SYSTEM_CONFIGURATION,
        // so must also gain PORTFOLIO_ACCESS_CONTROL_BYPASS and SECRET_MANAGEMENT via fan-out.
        final List<Map<String, Object>> teamPerms = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT t."NAME" AS team_name, p."NAME" AS permission_name
                      FROM "TEAMS_PERMISSIONS" tp
                      JOIN "TEAM" t       ON t."ID" = tp."TEAM_ID"
                      JOIN "PERMISSION" p ON p."ID" = tp."PERMISSION_ID"
                     ORDER BY t."NAME", p."NAME"
                    """)
                .mapToMap()
                .list());

        assertThat(teamPerms).extracting(m -> m.get("team_name") + ":" + m.get("permission_name"))
            .containsExactlyInAnyOrder(
                "Engineering:ACCESS_MANAGEMENT",
                "Engineering:PORTFOLIO_ACCESS_CONTROL_BYPASS",
                "Engineering:SYSTEM_CONFIGURATION",
                "Engineering:SECRET_MANAGEMENT");
    }

    /**
     * Regression for <a href="https://github.com/DependencyTrack/dependency-track/issues/6217">#6217</a>:
     * the doc-guided recovery from a failed {@code load} drops and re-creates the v5 schema,
     * then re-runs {@code bootstrap} and {@code load} (without {@code transform}). Bootstrap
     * must therefore leave the v5 {@code PERMISSION} catalog populated so that the
     * {@code USERS_PERMISSIONS_PERMISSION_FK} on the subsequent join-table load resolves.
     */
    @Test
    @Order(2)
    void shouldSucceedWhenLoadResumedAfterPermissionReset() {
        // Simulate the operator's recovery: drop everything that hangs off PERMISSION,
        // including PERMISSION itself, and restart the identity sequence so the re-seed
        // produces identical IDs to the originals captured in permission_name_map.
        target.jdbi().useHandle(h ->
            h.execute("TRUNCATE TABLE \"PERMISSION\" RESTART IDENTITY CASCADE"));

        // Re-bootstrap: only the PERMISSION seed step (Flyway is already at head).
        PermissionCatalog.seed(target.jdbi());

        // Re-run just the join-table loads. The permission_name_map and tgt_*_permissions
        // staging tables are still in place from the first pipeline run.
        final TableMigration teamsPerms = TableRegistry.loaded().stream()
            .filter(t -> t.name().equals("TEAMS_PERMISSIONS"))
            .findFirst().orElseThrow();
        final TableMigration usersPerms = TableRegistry.loaded().stream()
            .filter(t -> t.name().equals("USERS_PERMISSIONS"))
            .findFirst().orElseThrow();

        target.jdbi().useHandle(h -> {
            h.execute(teamsPerms.loadSql().formatted("dt_v4_migration"));
            h.execute(usersPerms.loadSql().formatted("dt_v4_migration"));
        });

        final List<Map<String, Object>> userPerms = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT u."USERNAME" AS username, p."NAME" AS permission_name
                      FROM "USERS_PERMISSIONS" up
                      JOIN "USER" u       ON u."ID" = up."USER_ID"
                      JOIN "PERMISSION" p ON p."ID" = up."PERMISSION_ID"
                     ORDER BY u."USERNAME", p."NAME"
                    """)
                .mapToMap()
                .list());

        assertThat(userPerms).extracting(m -> m.get("username") + ":" + m.get("permission_name"))
            .containsExactlyInAnyOrder(
                "alice:VIEW_PORTFOLIO",
                "carol:ACCESS_MANAGEMENT",
                "carol:PORTFOLIO_ACCESS_CONTROL_BYPASS",
                "dave:SYSTEM_CONFIGURATION",
                "dave:SECRET_MANAGEMENT");

        final List<Map<String, Object>> teamPerms = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT t."NAME" AS team_name, p."NAME" AS permission_name
                      FROM "TEAMS_PERMISSIONS" tp
                      JOIN "TEAM" t       ON t."ID" = tp."TEAM_ID"
                      JOIN "PERMISSION" p ON p."ID" = tp."PERMISSION_ID"
                     ORDER BY t."NAME", p."NAME"
                    """)
                .mapToMap()
                .list());

        assertThat(teamPerms).extracting(m -> m.get("team_name") + ":" + m.get("permission_name"))
            .containsExactlyInAnyOrder(
                "Engineering:ACCESS_MANAGEMENT",
                "Engineering:PORTFOLIO_ACCESS_CONTROL_BYPASS",
                "Engineering:SYSTEM_CONFIGURATION",
                "Engineering:SECRET_MANAGEMENT");
    }

    private void runPipeline() throws Exception {
        final GlobalOptions global = new GlobalOptions();
        global.targetUrl = target.jdbcUrl();
        global.targetUser = target.username();
        global.targetPass = target.password();
        global.stagingSchema = "dt_v4_migration";
        global.logLevel = "INFO";

        final SourceOptions src = new SourceOptions();
        src.sourceUrl = source.jdbcUrl();
        src.sourceUser = source.username();
        src.sourcePass = source.password();

        new ExtractPhase(global, src, target.jdbi(), 90).run();
        new TransformPhase(global, target.jdbi()).run();
        new LoadPhase(global, target.jdbi(), false).run();
    }
}
