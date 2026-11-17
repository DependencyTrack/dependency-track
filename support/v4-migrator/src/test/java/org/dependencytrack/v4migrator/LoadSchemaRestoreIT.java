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

import org.dependencytrack.migration.MigrationExecutor;
import org.dependencytrack.v4migrator.config.GlobalOptions;
import org.dependencytrack.v4migrator.config.SourceOptions;
import org.dependencytrack.v4migrator.extract.ExtractPhase;
import org.dependencytrack.v4migrator.load.LoadPhase;
import org.dependencytrack.v4migrator.preflight.Preflight;
import org.dependencytrack.v4migrator.preflight.Preflight.Mode;
import org.dependencytrack.v4migrator.preflight.PreflightResult;
import org.dependencytrack.v4migrator.testsupport.V4PostgresSource;
import org.dependencytrack.v4migrator.testsupport.V5TargetContainer;
import org.dependencytrack.v4migrator.transform.TransformPhase;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class LoadSchemaRestoreIT {

    private static final String STAGING_SCHEMA = "dt_v4_migration";

    private V4PostgresSource source;
    private V5TargetContainer target;
    private GlobalOptions global;

    @BeforeEach
    void setUp() throws Exception {
        source = new V4PostgresSource().start();
        target = new V5TargetContainer().start();

        global = new GlobalOptions();
        global.targetUrl = target.jdbcUrl();
        global.targetUser = target.username();
        global.targetPass = target.password();
        global.stagingSchema = STAGING_SCHEMA;
        global.logLevel = "INFO";

        source.jdbi().useHandle(h -> h.execute("""
                INSERT INTO "LICENSE" ("ID", "ISDEPRECATED", "ISOSIAPPROVED", "NAME", "UUID")
                VALUES (1, FALSE, TRUE, 'Apache 2.0', 'c5b25734-69ce-4e9b-a4f3-1f0fa5b27d5f')
                """));

        final SourceOptions src = new SourceOptions();
        src.sourceUrl = source.jdbcUrl();
        src.sourceUser = source.username();
        src.sourcePass = source.password();
        new ExtractPhase(global, src, target.jdbi(), 90).run();
        new TransformPhase(global, target.jdbi()).run();
    }

    @AfterEach
    void tearDown() {
        target.close();
        source.close();
    }

    @Test
    void loadShouldRestoreForeignKeysAndIndexes() {
        final Set<String> expected = new HashSet<>(schemaObjects(target.jdbi()));
        // The migrator pins an older schema head. V202606101343 drops these FKs on the
        // apiserver's first start, so validating them after the load would be wasted work.
        assertThat(expected)
                .filteredOn(it -> it.startsWith("FK DEPENDENCYMETRICS.") || it.startsWith("FK PROJECTMETRICS."))
                .hasSize(3);
        expected.removeIf(it -> it.startsWith("FK DEPENDENCYMETRICS.") || it.startsWith("FK PROJECTMETRICS."));

        new LoadPhase(global, target.jdbi(), false).run();

        assertThat(schemaObjects(target.jdbi())).containsExactlyInAnyOrderElementsOf(expected);
    }

    @Test
    void loadShouldExplainRecoveryOnFailureAndSucceedAfterRecovery() {
        target.jdbi().useHandle(h -> h.execute("""
                INSERT INTO "%s".tgt_components_vulnerabilities ("COMPONENT_ID", "VULNERABILITY_ID")
                VALUES (999, 999)
                """.formatted(STAGING_SCHEMA)));

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> new LoadPhase(global, target.jdbi(), false).run())
                .withMessageContaining("foreign keys and indexes may be missing")
                .withMessageContaining("drop the v5 schema")
                .withMessageContaining("keep staging schema '%s'".formatted(STAGING_SCHEMA));

        target.jdbi().useHandle(h -> {
            h.execute("DROP SCHEMA public CASCADE");
            h.execute("CREATE SCHEMA public");
            h.execute("TRUNCATE \"%s\".tgt_components_vulnerabilities".formatted(STAGING_SCHEMA));
        });
        new MigrationExecutor(target.dataSource(), Preflight.EXPECTED_FLYWAY_HEAD, /* skipRepeatable */ true).execute();
        PermissionCatalog.seed(target.jdbi());
        assertThat(new Preflight(target.jdbi(), null, global).run().ok()).isTrue();

        new LoadPhase(global, target.jdbi(), false).run();

        final long licenses = target.jdbi()
                .withHandle(h -> h.createQuery("SELECT count(*) FROM \"LICENSE\"")
                        .mapTo(Long.class)
                        .one());
        assertThat(licenses).isEqualTo(1L);
    }

    @Test
    void preflightShouldFailWhenForeignKeyMissingFromEmptyTarget() {
        target.jdbi().useHandle(h -> h.execute("""
                ALTER TABLE "COMPONENTS_VULNERABILITIES" DROP CONSTRAINT "COMPONENTS_VULNERABILITIES_COMPONENT_FK"
                """));

        for (final Mode mode : List.of(Mode.DEFAULT, Mode.POST_LOAD)) {
            final PreflightResult result = new Preflight(target.jdbi(), null, global, mode).run();

            assertThat(result.ok()).isFalse();
            assertThat(result.failures())
                    .anyMatch(it -> it.contains("COMPONENTS_VULNERABILITIES_COMPONENT_FK")
                            && it.contains("drop the v5 schema"));
        }
    }

    private static List<String> schemaObjects(final Jdbi jdbi) {
        return jdbi.withHandle(h -> h.createQuery("""
                SELECT 'FK ' || t.relname || '.' || c.conname || ' ' || pg_get_constraintdef(c.oid)
                  FROM pg_constraint c
                  JOIN pg_class t ON t.oid = c.conrelid
                 WHERE c.contype = 'f'
                   AND c.connamespace = current_schema()::regnamespace
                   AND NOT t.relispartition
                UNION ALL
                SELECT 'INDEX ' || pg_get_indexdef(i.indexrelid)
                  FROM pg_index i
                  JOIN pg_class t ON t.oid = i.indrelid
                 WHERE t.relnamespace = current_schema()::regnamespace
                   AND NOT t.relispartition
                """).mapTo(String.class).list());
    }
}
