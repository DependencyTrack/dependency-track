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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises the v4 PERMISSION → v5 PERMISSION migration. The migrator seeds v5
 * {@code PERMISSION} with the full v5 catalog and builds {@code permission_name_map} by
 * inner-joining v4 NAME against v5 PERMISSION; v4 names absent from v5 (e.g.
 * {@code VIEW_BADGES}) drop out and their join rows are silently removed. The migrator
 * also fans v4 {@code ACCESS_MANAGEMENT} out to v5 {@code PORTFOLIO_ACCESS_CONTROL_BYPASS}
 * to preserve v4's implicit portfolio-access-control bypass.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
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
    void mapsPermissionsByNameAndRewritesJoins() throws Exception {
        // Seed v4: a TEAM, two permissions (one carried over to v5, one v4-only), a MANAGED
        // user "alice" with both, an LDAP user "bob" with only the v4-only one, and an OIDC
        // user "carol" with ACCESS_MANAGEMENT to exercise the implication fan-out.
        source.jdbi().useHandle(h -> {
            h.execute("INSERT INTO \"TEAM\" (\"ID\", \"NAME\", \"UUID\") VALUES (1, 'Engineering', '11111111-1111-1111-1111-111111111111')");
            h.execute("INSERT INTO \"PERMISSION\" (\"ID\", \"NAME\") VALUES (1, 'VIEW_PORTFOLIO')");
            // VIEW_BADGES was a v4 permission that v5 removed; verifies v4-only names drop out.
            h.execute("INSERT INTO \"PERMISSION\" (\"ID\", \"NAME\") VALUES (2, 'VIEW_BADGES')");
            h.execute("INSERT INTO \"PERMISSION\" (\"ID\", \"NAME\") VALUES (3, 'ACCESS_MANAGEMENT')");
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
            h.execute("INSERT INTO \"MANAGEDUSERS_PERMISSIONS\" (\"MANAGEDUSER_ID\", \"PERMISSION_ID\") VALUES (10, 1)");
            h.execute("INSERT INTO \"MANAGEDUSERS_PERMISSIONS\" (\"MANAGEDUSER_ID\", \"PERMISSION_ID\") VALUES (10, 2)");
            h.execute("INSERT INTO \"LDAPUSERS_PERMISSIONS\" (\"LDAPUSER_ID\", \"PERMISSION_ID\") VALUES (20, 2)");
            h.execute("INSERT INTO \"OIDCUSERS_PERMISSIONS\" (\"OIDCUSER_ID\", \"PERMISSION_ID\") VALUES (30, 3)");
            h.execute("INSERT INTO \"TEAMS_PERMISSIONS\" (\"TEAM_ID\", \"PERMISSION_ID\") VALUES (1, 3)");
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
            .containsExactlyInAnyOrder("VIEW_PORTFOLIO", "ACCESS_MANAGEMENT");

        // Full v5 catalog is seeded regardless of which subset v4 had. PORTFOLIO_ACCESS_CONTROL_BYPASS
        // (a v5.6.0 addition not present in v4) must be available for the implication fan-out below.
        final List<String> perms = target.jdbi().withHandle(h ->
            h.createQuery("SELECT \"NAME\" FROM \"PERMISSION\" ORDER BY \"NAME\"")
                .mapTo(String.class)
                .list());
        assertThat(perms).contains(
            "ACCESS_MANAGEMENT", "ACCESS_MANAGEMENT_CREATE", "ACCESS_MANAGEMENT_READ",
            "ACCESS_MANAGEMENT_UPDATE", "ACCESS_MANAGEMENT_DELETE",
            "PORTFOLIO_ACCESS_CONTROL_BYPASS", "VIEW_PORTFOLIO");
        assertThat(perms).doesNotContain("VIEW_BADGES", "SECRET_MANAGEMENT_READ");

        // USERS_PERMISSIONS final state:
        //   - alice keeps VIEW_PORTFOLIO; her VIEW_BADGES assignment drops with the name.
        //   - bob's only assignment was VIEW_BADGES, so he ends with no permissions.
        //   - carol keeps ACCESS_MANAGEMENT AND gains PORTFOLIO_ACCESS_CONTROL_BYPASS via fan-out.
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
                "carol:PORTFOLIO_ACCESS_CONTROL_BYPASS");

        // TEAMS_PERMISSIONS: Engineering had ACCESS_MANAGEMENT, must also gain
        // PORTFOLIO_ACCESS_CONTROL_BYPASS via fan-out.
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
                "Engineering:PORTFOLIO_ACCESS_CONTROL_BYPASS");
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
