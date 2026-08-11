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
import static org.assertj.core.api.Assertions.tuple;

/**
 * Mappings that are distinct under v4's UNIQUE (TEAM_ID, GROUP_ID) / (TEAM_ID, DN) can collapse
 * onto the same pair once same-named TEAMs and OIDCGROUPs are canonicalized. The migrator must
 * merge them instead of failing the load on MAPPEDOIDCGROUP_U1 / MAPPEDLDAPGROUP_U1.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MappedGroupDedupIT {

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
    void shouldMergeMappingsThatCollideAfterTeamAndGroupCollapse() throws Exception {
        source.jdbi().useHandle(h -> {
            // Two TEAMs share NAME 'Engineering'; canonical = ID 1 (MIN(ID)).
            h.execute("INSERT INTO \"TEAM\" (\"ID\", \"NAME\", \"UUID\") VALUES (1, 'Engineering', '11111111-1111-1111-1111-111111111111')");
            h.execute("INSERT INTO \"TEAM\" (\"ID\", \"NAME\", \"UUID\") VALUES (5, 'Engineering', '55555555-5555-5555-5555-555555555555')");

            // Two OIDCGROUPs share NAME 'admins'; canonical = ID 8 (MIN(ID)).
            h.execute("INSERT INTO \"OIDCGROUP\" (\"ID\", \"NAME\", \"UUID\") VALUES (8, 'admins', '88888888-8888-8888-8888-888888888888')");
            h.execute("INSERT INTO \"OIDCGROUP\" (\"ID\", \"NAME\", \"UUID\") VALUES (9, 'admins', '99999999-9999-9999-9999-999999999999')");

            // Distinct in v4: (1, 8), (5, 8), (1, 9). All three collapse onto (1, 8).
            h.execute("INSERT INTO \"MAPPEDOIDCGROUP\" (\"ID\", \"GROUP_ID\", \"TEAM_ID\", \"UUID\") VALUES (200, 8, 1, 'aaaaaaaa-0000-0000-0000-000000000200')");
            h.execute("INSERT INTO \"MAPPEDOIDCGROUP\" (\"ID\", \"GROUP_ID\", \"TEAM_ID\", \"UUID\") VALUES (201, 8, 5, 'aaaaaaaa-0000-0000-0000-000000000201')");
            h.execute("INSERT INTO \"MAPPEDOIDCGROUP\" (\"ID\", \"GROUP_ID\", \"TEAM_ID\", \"UUID\") VALUES (202, 9, 1, 'aaaaaaaa-0000-0000-0000-000000000202')");

            // Distinct in v4: (1, cn=eng), (5, cn=eng). Both collapse onto (1, cn=eng).
            // (7, cn=sec) is unaffected and must survive.
            h.execute("INSERT INTO \"TEAM\" (\"ID\", \"NAME\", \"UUID\") VALUES (7, 'Security', '77777777-7777-7777-7777-777777777777')");
            h.execute("INSERT INTO \"MAPPEDLDAPGROUP\" (\"ID\", \"DN\", \"TEAM_ID\", \"UUID\") VALUES (100, 'cn=eng,dc=example,dc=com', 1, 'bbbbbbbb-0000-0000-0000-000000000100')");
            h.execute("INSERT INTO \"MAPPEDLDAPGROUP\" (\"ID\", \"DN\", \"TEAM_ID\", \"UUID\") VALUES (101, 'cn=eng,dc=example,dc=com', 5, 'bbbbbbbb-0000-0000-0000-000000000101')");
            h.execute("INSERT INTO \"MAPPEDLDAPGROUP\" (\"ID\", \"DN\", \"TEAM_ID\", \"UUID\") VALUES (102, 'cn=sec,dc=example,dc=com', 7, 'bbbbbbbb-0000-0000-0000-000000000102')");
        });

        runPipeline();

        // One surviving OIDC mapping, keeping MIN(ID) and its UUID.
        final List<Map<String, Object>> oidc = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "GROUP_ID", "TEAM_ID", "UUID"
                      FROM "MAPPEDOIDCGROUP"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(oidc).extracting("id", "group_id", "team_id", "uuid")
            .containsExactly(tuple(200L, 8L, 1L, "aaaaaaaa-0000-0000-0000-000000000200"));

        final List<Map<String, Object>> ldap = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "DN", "TEAM_ID", "UUID"
                      FROM "MAPPEDLDAPGROUP"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(ldap).extracting("id", "dn", "team_id", "uuid")
            .containsExactly(
                tuple(100L, "cn=eng,dc=example,dc=com", 1L, "bbbbbbbb-0000-0000-0000-000000000100"),
                tuple(102L, "cn=sec,dc=example,dc=com", 7L, "bbbbbbbb-0000-0000-0000-000000000102")
            );
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
