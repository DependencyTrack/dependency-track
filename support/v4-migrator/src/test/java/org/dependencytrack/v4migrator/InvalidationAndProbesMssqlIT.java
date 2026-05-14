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
import org.dependencytrack.v4migrator.testsupport.V4MssqlSource;
import org.dependencytrack.v4migrator.testsupport.V5TargetContainer;
import org.dependencytrack.v4migrator.transform.TransformPhase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class InvalidationAndProbesMssqlIT {

    private V4MssqlSource source;
    private V5TargetContainer target;

    @BeforeAll
    void start() {
        source = new V4MssqlSource().start();
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
    void nullUsernameRowsLandInProbeAndReRunInvalidatesDownstream() throws Exception {
        source.withIdentityInsert("MANAGEDUSER", h -> h.execute("""
            INSERT INTO [MANAGEDUSER] (
                [ID], [USERNAME], [PASSWORD],
                [FORCE_PASSWORD_CHANGE], [LAST_PASSWORD_CHANGE],
                [NON_EXPIRY_PASSWORD], [SUSPENDED]
            )
            VALUES (1, 'alice', 'h', 0, '2025-01-01T00:00:00', 0, 0)
            """));
        source.withIdentityInsert("LDAPUSER", h -> h.execute("""
            INSERT INTO [LDAPUSER] ([ID], [USERNAME], [DN])
            VALUES (2, NULL, 'cn=ghost,dc=example,dc=com')
            """));

        final GlobalOptions global = global();
        final SourceOptions src = src();
        new ExtractPhase(global, src, target.jdbi(), 90).run();
        new TransformPhase(global, target.jdbi()).run();

        final List<Map<String, Object>> skipped = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT table_name, orig_id, reason
                      FROM "dt_v4_migration".probe_skipped_users
                     ORDER BY table_name, orig_id
                    """).mapToMap().list());
        assertThat(skipped).hasSize(1);
        assertThat(skipped.get(0))
            .containsEntry("table_name", "LDAPUSER")
            .containsEntry("orig_id", 2L)
            .containsEntry("reason", "USERNAME IS NULL");

        target.jdbi().useHandle(h -> h.execute("""
            INSERT INTO "dt_v4_migration".migration_state
                (table_name, phase, status, rows_processed, started_at, completed_at)
            VALUES ('FAKE', 'LOAD', 'COMPLETED', 0, NOW(), NOW())
            """));

        new ExtractPhase(global, src, target.jdbi(), 90).run();

        final List<String> tgtTables = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT table_name FROM information_schema.tables
                     WHERE table_schema = 'dt_v4_migration'
                       AND table_name LIKE 'tgt\\_%' ESCAPE '\\'
                    """).mapTo(String.class).list());
        assertThat(tgtTables).isEmpty();

        final Long downstreamRows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT count(*) FROM "dt_v4_migration".migration_state
                     WHERE phase IN ('TRANSFORM', 'LOAD')
                    """).mapTo(Long.class).one());
        assertThat(downstreamRows).isZero();

        final Long probeRowsAfterReExtract = target.jdbi().withHandle(h ->
            h.createQuery("SELECT count(*) FROM \"dt_v4_migration\".probe_skipped_users")
                .mapTo(Long.class).one());
        assertThat(probeRowsAfterReExtract).isZero();
    }

    private GlobalOptions global() {
        final GlobalOptions g = new GlobalOptions();
        g.targetUrl = target.jdbcUrl();
        g.targetUser = target.username();
        g.targetPass = target.password();
        g.stagingSchema = "dt_v4_migration";
        g.logLevel = "INFO";
        return g;
    }

    private SourceOptions src() {
        final SourceOptions s = new SourceOptions();
        s.sourceUrl = source.jdbcUrl();
        s.sourceUser = source.username();
        s.sourcePass = source.password();
        return s;
    }
}
