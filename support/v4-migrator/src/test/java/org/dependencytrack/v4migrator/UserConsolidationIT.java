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
 * Exercises the LDAP/MANAGED/OIDC → USER consolidation including the {@code -CONFLICT-LDAP}
 * / {@code -CONFLICT-OIDC} suffix path and the USERS_TEAMS join.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UserConsolidationIT {

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
    void consolidatesUsersAndUsersTeams() throws Exception {
        // Seed v4: a TEAM, a MANAGED user "alice", an LDAP user also named "alice" (will
        // get -CONFLICT-LDAP), an OIDC user "bob" (no conflict), and a NULL-USERNAME LDAP
        // user that must be dropped silently.
        source.jdbi().useHandle(h -> {
            h.execute("INSERT INTO \"TEAM\" (\"ID\", \"NAME\", \"UUID\") VALUES (1, 'Engineering', '11111111-1111-1111-1111-111111111111')");
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
                VALUES (20, 'alice', 'cn=alice,dc=example,dc=com', 'alice@ldap.example.com')
                """);
            h.execute("""
                INSERT INTO "LDAPUSER" ("ID", "USERNAME", "DN", "EMAIL")
                VALUES (21, NULL, 'cn=ghost,dc=example,dc=com', NULL)
                """);
            h.execute("""
                INSERT INTO "OIDCUSER" ("ID", "USERNAME", "SUBJECT_IDENTIFIER", "EMAIL")
                VALUES (30, 'bob', 'oidc-sub-bob', 'bob@example.com')
                """);
            h.execute("INSERT INTO \"MANAGEDUSERS_TEAMS\" (\"TEAM_ID\", \"MANAGEDUSER_ID\") VALUES (1, 10)");
            h.execute("INSERT INTO \"LDAPUSERS_TEAMS\" (\"TEAM_ID\", \"LDAPUSER_ID\") VALUES (1, 20)");
            h.execute("INSERT INTO \"OIDCUSERS_TEAMS\" (\"TEAM_ID\", \"OIDCUSERS_ID\") VALUES (1, 30)");
        });

        runPipeline();

        final List<Map<String, Object>> users = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "TYPE", "USERNAME", "EMAIL", "FULLNAME", "PASSWORD", "DN", "SUBJECT_IDENTIFIER"
                      FROM "USER"
                     ORDER BY "USERNAME"
                    """)
                .mapToMap()
                .list());

        // Expect 3 rows: alice (MANAGED), alice-CONFLICT-LDAP (LDAP), bob (OIDC).
        // The NULL-USERNAME LDAP row should not appear.
        assertThat(users).hasSize(3);

        assertThat(users.get(0))
            .containsEntry("type", "MANAGED")
            .containsEntry("username", "alice")
            .containsEntry("fullname", "Alice Managed")
            .containsEntry("password", "hash");

        assertThat(users.get(1))
            .containsEntry("type", "LDAP")
            .containsEntry("username", "alice-CONFLICT-LDAP")
            .containsEntry("dn", "cn=alice,dc=example,dc=com");

        assertThat(users.get(2))
            .containsEntry("type", "OIDC")
            .containsEntry("username", "bob")
            .containsEntry("subject_identifier", "oidc-sub-bob");

        // USERS_TEAMS: three rows, one per real user, all pointing at team 1.
        final List<Map<String, Object>> userTeams = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT u."USERNAME", ut."TEAM_ID"
                      FROM "USERS_TEAMS" ut
                      JOIN "USER" u ON u."ID" = ut."USER_ID"
                     ORDER BY u."USERNAME"
                    """)
                .mapToMap()
                .list());

        assertThat(userTeams).hasSize(3);
        assertThat(userTeams).extracting(r -> r.get("username"))
            .containsExactly("alice", "alice-CONFLICT-LDAP", "bob");
        assertThat(userTeams).allSatisfy(r -> assertThat(r).containsEntry("team_id", 1L));
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
