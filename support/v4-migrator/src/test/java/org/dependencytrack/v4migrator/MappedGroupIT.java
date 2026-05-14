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
 * 1:1 migration of {@code MAPPEDLDAPGROUP} and {@code MAPPEDOIDCGROUP}. UUID stays
 * {@code varchar(36)} in v5 for both tables (stragglers that did not convert to native uuid).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MappedGroupIT {

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
    void migratesMappedGroups() throws Exception {
        final String ldapUuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        final String oidcUuid = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        source.jdbi().useHandle(h -> {
            h.execute("INSERT INTO \"TEAM\" (\"ID\", \"NAME\", \"UUID\") VALUES (1, 'Engineering', '11111111-1111-1111-1111-111111111111')");
            h.execute("INSERT INTO \"OIDCGROUP\" (\"ID\", \"NAME\", \"UUID\") VALUES (5, 'admins', '22222222-2222-2222-2222-222222222222')");
            h.createUpdate("""
                    INSERT INTO "MAPPEDLDAPGROUP" ("ID", "DN", "TEAM_ID", "UUID")
                    VALUES (100, 'cn=eng,dc=example,dc=com', 1, :u)
                """).bind("u", ldapUuid).execute();
            h.createUpdate("""
                    INSERT INTO "MAPPEDOIDCGROUP" ("ID", "GROUP_ID", "TEAM_ID", "UUID")
                    VALUES (200, 5, 1, :u)
                """).bind("u", oidcUuid).execute();
        });

        runPipeline();

        final List<Map<String, Object>> ldap = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "DN", "TEAM_ID", "UUID"
                      FROM "MAPPEDLDAPGROUP"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(ldap).extracting("id", "dn", "team_id", "uuid")
            .containsExactly(tuple(100L, "cn=eng,dc=example,dc=com", 1L, ldapUuid));

        final List<Map<String, Object>> oidc = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "GROUP_ID", "TEAM_ID", "UUID"
                      FROM "MAPPEDOIDCGROUP"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(oidc).extracting("id", "group_id", "team_id", "uuid")
            .containsExactly(tuple(200L, 5L, 1L, oidcUuid));
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
