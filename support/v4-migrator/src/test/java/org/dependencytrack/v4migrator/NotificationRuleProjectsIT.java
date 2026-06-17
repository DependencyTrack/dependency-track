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
 * Exercises the v4 NOTIFICATIONRULE_PROJECTS transform: NOTIFICATIONRULE_ID rewritten
 * through the rule canonical-id map; PROJECT_ID rewritten through the project canonical-id
 * map but preserved as NULL when the v4 row carries NULL (semantic: rule matches all
 * projects).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class NotificationRuleProjectsIT {

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
    void preservesNullProjectAndRewritesNonNull() throws Exception {
        source.jdbi().useHandle(h -> {
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "LAST_BOM_IMPORTED")
                VALUES (5, 'Foo', '1.0', '00000000-0000-0000-0000-000000000005',
                        '2024-12-01T00:00:00Z')
                """);
            h.execute("""
                INSERT INTO "NOTIFICATIONPUBLISHER" (
                    "ID", "DEFAULT_PUBLISHER", "DESCRIPTION", "NAME", "PUBLISHER_CLASS",
                    "TEMPLATE", "TEMPLATE_MIME_TYPE", "UUID"
                )
                VALUES (1, TRUE, 'Slack', 'Slack',
                        'org.dependencytrack.notification.publisher.SlackPublisher',
                        'tmpl', 'application/json',
                        '11111111-1111-1111-1111-111111111111')
                """);
            h.execute("""
                INSERT INTO "NOTIFICATIONRULE" (
                    "ID", "ENABLED", "LOG_SUCCESSFUL_PUBLISH", "MESSAGE", "NAME",
                    "NOTIFICATION_LEVEL", "NOTIFY_CHILDREN", "NOTIFY_ON", "PUBLISHER",
                    "PUBLISHER_CONFIG", "SCOPE", "UUID"
                )
                VALUES (10, TRUE, NULL, NULL, 'Rule A',
                        'INFORMATIONAL', TRUE, NULL, 1, NULL, 'PORTFOLIO',
                        'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')
                """);
            h.execute("INSERT INTO \"NOTIFICATIONRULE_PROJECTS\" (\"NOTIFICATIONRULE_ID\", \"PROJECT_ID\") VALUES (10, 5)");
            h.execute("INSERT INTO \"NOTIFICATIONRULE_PROJECTS\" (\"NOTIFICATIONRULE_ID\", \"PROJECT_ID\") VALUES (10, NULL)");
        });

        runPipeline();

        final List<Map<String, Object>> rows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "NOTIFICATIONRULE_ID", "PROJECT_ID"
                      FROM "NOTIFICATIONRULE_PROJECTS"
                     ORDER BY "PROJECT_ID" NULLS FIRST
                    """).mapToMap().list());
        assertThat(rows).extracting("notificationrule_id", "project_id")
            .containsExactly(
                tuple(10L, null),
                tuple(10L, 5L)
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
