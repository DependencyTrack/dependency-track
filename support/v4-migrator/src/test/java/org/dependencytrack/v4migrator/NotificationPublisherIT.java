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
 * Exercises the v4 NOTIFICATIONPUBLISHER → v5 NOTIFICATIONPUBLISHER transform:
 * dedup-by-NAME, UUID conversion, and the {@code PUBLISHER_CLASS → EXTENSION_NAME} remap
 * per schema-changes §5.5 (with Java-package prefix stripped). Unknown classes pass
 * through (with the package stripped) so operators can register a custom v5 extension.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class NotificationPublisherIT {

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
    void mapsPublisherClassAndDedupesByName() throws Exception {
        source.jdbi().useHandle(h -> {
            // Fully-qualified known publisher.
            h.execute("""
                INSERT INTO "NOTIFICATIONPUBLISHER" (
                    "ID", "DEFAULT_PUBLISHER", "DESCRIPTION", "NAME", "PUBLISHER_CLASS",
                    "TEMPLATE", "TEMPLATE_MIME_TYPE", "UUID"
                )
                VALUES (1, TRUE, 'Slack publisher', 'Slack',
                        'org.dependencytrack.notification.publisher.SlackPublisher',
                        'tmpl', 'application/json',
                        '11111111-1111-1111-1111-111111111111')
                """);
            // Simple class name (no package).
            h.execute("""
                INSERT INTO "NOTIFICATIONPUBLISHER" (
                    "ID", "DEFAULT_PUBLISHER", "DESCRIPTION", "NAME", "PUBLISHER_CLASS",
                    "TEMPLATE", "TEMPLATE_MIME_TYPE", "UUID"
                )
                VALUES (2, TRUE, 'Jira publisher', 'Jira',
                        'JiraPublisher',
                        'tmpl', 'application/json',
                        '22222222-2222-2222-2222-222222222222')
                """);
            // Unknown / custom publisher: package stripped but otherwise pass-through.
            h.execute("""
                INSERT INTO "NOTIFICATIONPUBLISHER" (
                    "ID", "DEFAULT_PUBLISHER", "DESCRIPTION", "NAME", "PUBLISHER_CLASS",
                    "TEMPLATE", "TEMPLATE_MIME_TYPE", "UUID"
                )
                VALUES (3, FALSE, 'Custom', 'Custom',
                        'com.example.CustomPublisher',
                        'tmpl', 'application/json',
                        '33333333-3333-3333-3333-333333333333')
                """);
            // Duplicate by NAME (canonical = MIN(ID) = 1).
            h.execute("""
                INSERT INTO "NOTIFICATIONPUBLISHER" (
                    "ID", "DEFAULT_PUBLISHER", "DESCRIPTION", "NAME", "PUBLISHER_CLASS",
                    "TEMPLATE", "TEMPLATE_MIME_TYPE", "UUID"
                )
                VALUES (4, FALSE, 'Slack dup', 'Slack',
                        'org.dependencytrack.notification.publisher.SlackPublisher',
                        'tmpl', 'application/json',
                        '44444444-4444-4444-4444-444444444444')
                """);
        });

        runPipeline();

        final List<Map<String, Object>> rows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "NAME", "EXTENSION_NAME"
                      FROM "NOTIFICATIONPUBLISHER"
                     ORDER BY "ID"
                    """).mapToMap().list());

        assertThat(rows).extracting("id", "name", "extension_name")
            .containsExactly(
                tuple(1L, "Slack", "slack"),
                tuple(2L, "Jira", "jira"),
                tuple(3L, "Custom", "CustomPublisher")
            );

        // Canonical map: duplicate row 4 collapses onto 1.
        final List<Map<String, Object>> map = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT orig_id, canonical_id
                      FROM "dt_v4_migration".notificationpublisher_canonical_id_map
                     ORDER BY orig_id
                    """).mapToMap().list());
        assertThat(map).extracting("orig_id", "canonical_id")
            .containsExactly(
                tuple(1L, 1L),
                tuple(2L, 2L),
                tuple(3L, 3L),
                tuple(4L, 1L)
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
