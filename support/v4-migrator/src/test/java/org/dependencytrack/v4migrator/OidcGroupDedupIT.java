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
 * v4 has no UNIQUE constraint on OIDCGROUP.NAME but v5 adds one; in practice deployments do
 * not contain duplicates, so the dedup behaves as a no-op here. The migrator still produces
 * an {@code oidcgroup_canonical_id_map} for the future MAPPEDOIDCGROUP join-table transform.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OidcGroupDedupIT {

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
    void migratesOidcGroupsAndBuildsCanonicalMap() throws Exception {
        source.jdbi().useHandle(h -> {
            h.execute("INSERT INTO \"OIDCGROUP\" (\"ID\", \"NAME\", \"UUID\") VALUES (1, 'admins',     '11111111-1111-1111-1111-111111111111')");
            h.execute("INSERT INTO \"OIDCGROUP\" (\"ID\", \"NAME\", \"UUID\") VALUES (2, 'developers', '22222222-2222-2222-2222-222222222222')");
            h.execute("INSERT INTO \"OIDCGROUP\" (\"ID\", \"NAME\", \"UUID\") VALUES (7, 'auditors',   '77777777-7777-7777-7777-777777777777')");
        });

        runPipeline();

        final List<Map<String, Object>> groups = target.jdbi().withHandle(h ->
            h.createQuery("SELECT \"ID\", \"NAME\", \"UUID\" FROM \"OIDCGROUP\" ORDER BY \"ID\"").mapToMap().list());
        assertThat(groups).extracting("id", "name", "uuid")
            .containsExactly(
                tuple(1L, "admins",     "11111111-1111-1111-1111-111111111111"),
                tuple(2L, "developers", "22222222-2222-2222-2222-222222222222"),
                tuple(7L, "auditors",   "77777777-7777-7777-7777-777777777777")
            );

        final List<Map<String, Object>> map = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT orig_id, canonical_id
                      FROM "dt_v4_migration".oidcgroup_canonical_id_map
                     ORDER BY orig_id
                    """).mapToMap().list());
        assertThat(map).extracting("orig_id", "canonical_id")
            .containsExactly(
                tuple(1L, 1L),
                tuple(2L, 2L),
                tuple(7L, 7L)
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
