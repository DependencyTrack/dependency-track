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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/**
 * Verifies the schema-changes §7.8 PASSWORD purge: any REPOSITORY row with a non-null
 * PASSWORD lands in v5 with PASSWORD nulled and ENABLED set to FALSE so an admin must
 * re-enter the secret. Rows with PASSWORD NULL pass through untouched.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RepositoryPasswordPurgeIT {

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
    void purgesPasswordAndDisablesRepository() throws Exception {
        final UUID securedUuid = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        final UUID openUuid    = UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        source.jdbi().useHandle(h -> {
            h.createUpdate("""
                    INSERT INTO "REPOSITORY" (
                        "ID", "AUTHENTICATIONREQUIRED", "ENABLED", "IDENTIFIER", "INTERNAL",
                        "PASSWORD", "RESOLUTION_ORDER", "TYPE", "URL", "USERNAME", "UUID"
                    )
                    VALUES (1, TRUE, TRUE, 'private-maven', FALSE, 'hunter2', 1, 'MAVEN',
                            'https://repo.example.com/private', 'svc', :u)
                """).bind("u", securedUuid.toString()).execute();
            h.createUpdate("""
                    INSERT INTO "REPOSITORY" (
                        "ID", "AUTHENTICATIONREQUIRED", "ENABLED", "IDENTIFIER", "INTERNAL",
                        "PASSWORD", "RESOLUTION_ORDER", "TYPE", "URL", "USERNAME", "UUID"
                    )
                    VALUES (2, FALSE, TRUE, 'central', FALSE,
                            NULL, 2, 'MAVEN', 'https://repo.maven.apache.org/maven2', NULL, :u)
                """).bind("u", openUuid.toString()).execute();
        });

        runPipeline();

        final List<Map<String, Object>> rows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "IDENTIFIER", "ENABLED", "PASSWORD", "USERNAME", "UUID"
                      FROM "REPOSITORY"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(rows).extracting("id", "identifier", "enabled", "password", "username", "uuid")
            .containsExactly(
                tuple(1L, "private-maven", false, null, "svc", securedUuid),
                tuple(2L, "central",       true,  null, null,  openUuid)
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
