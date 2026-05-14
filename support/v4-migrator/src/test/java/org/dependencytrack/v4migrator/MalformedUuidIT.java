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
 * A v4 LICENSE row carries a malformed UUID. The migrator records it in
 * {@code probe_invalid_uuids} and excludes it from the target. The well-formed row migrates.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MalformedUuidIT {

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
    void invalidUuidRowsAreProbedAndSkipped() throws Exception {
        source.jdbi().useHandle(h -> {
            h.createUpdate("""
                INSERT INTO "LICENSE" ("ID", "ISDEPRECATED", "ISOSIAPPROVED", "NAME", "UUID")
                VALUES (1, FALSE, TRUE, 'Apache 2.0', :u)
                """).bind("u", "c5b25734-69ce-4e9b-a4f3-1f0fa5b27d5f").execute();
            h.createUpdate("""
                INSERT INTO "LICENSE" ("ID", "ISDEPRECATED", "ISOSIAPPROVED", "NAME", "UUID")
                VALUES (2, FALSE, TRUE, 'Broken', :u)
                """).bind("u", "not-a-uuid").execute();
        });

        runPipeline();

        // The well-formed row is in v5.
        final List<Map<String, Object>> v5 = target.jdbi().withHandle(h ->
            h.createQuery("SELECT \"ID\", \"NAME\" FROM \"LICENSE\" ORDER BY \"ID\"").mapToMap().list());
        assertThat(v5).hasSize(1);
        assertThat(v5.get(0)).containsEntry("id", 1L).containsEntry("name", "Apache 2.0");

        // The malformed row was probed.
        final List<Map<String, Object>> probe = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT table_name, orig_id, bad_uuid
                      FROM "dt_v4_migration".probe_invalid_uuids
                     ORDER BY orig_id
                    """).mapToMap().list());
        assertThat(probe).hasSize(1);
        assertThat(probe.get(0))
            .containsEntry("table_name", "LICENSE")
            .containsEntry("orig_id", 2L)
            .containsEntry("bad_uuid", "not-a-uuid");
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
