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
 * Exercises the v4 NOTIFICATIONRULE → v5 NOTIFICATIONRULE transform: PUBLISHER_CONFIG
 * rebuild per schema-changes §7.6, NOTIFICATION_LEVEL enum cast (§6.4), NOTIFY_ON CSV →
 * text[] (§6.5), forced {@code ENABLED=FALSE}, and a malformed-JSON fallback to the
 * blank stub.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class NotificationRuleStubIT {

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
    void rebuildsPublisherConfigAndForcesDisabled() throws Exception {
        source.jdbi().useHandle(h -> {
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
            // Parseable PUBLISHER_CONFIG — destination must end up inside destinationUrl.
            h.execute("""
                INSERT INTO "NOTIFICATIONRULE" (
                    "ID", "ENABLED", "LOG_SUCCESSFUL_PUBLISH", "MESSAGE", "NAME",
                    "NOTIFICATION_LEVEL", "NOTIFY_CHILDREN", "NOTIFY_ON", "PUBLISHER",
                    "PUBLISHER_CONFIG", "SCOPE", "UUID"
                )
                VALUES (10, TRUE, TRUE, 'Hello', 'Good Rule',
                        'INFORMATIONAL', TRUE,
                        'BOM_PROCESSED,NEW_VULNERABILITY', 1,
                        '{"destination": "https://hooks.slack.com/abc"}',
                        'PORTFOLIO',
                        'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')
                """);
            // Malformed PUBLISHER_CONFIG — try_jsonb returns NULL, fall back to default.
            h.execute("""
                INSERT INTO "NOTIFICATIONRULE" (
                    "ID", "ENABLED", "LOG_SUCCESSFUL_PUBLISH", "MESSAGE", "NAME",
                    "NOTIFICATION_LEVEL", "NOTIFY_CHILDREN", "NOTIFY_ON", "PUBLISHER",
                    "PUBLISHER_CONFIG", "SCOPE", "UUID"
                )
                VALUES (11, TRUE, FALSE, 'Broken', 'Bad Rule',
                        'WARNING', FALSE, NULL, 1,
                        'not json', 'PORTFOLIO',
                        'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb')
                """);
        });

        runPipeline();

        final List<Map<String, Object>> rows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "ENABLED", "NAME",
                           "NOTIFICATION_LEVEL"::text AS notification_level,
                           "NOTIFY_ON",
                           "PUBLISHER_CONFIG"::text AS publisher_config,
                           "TRIGGER_TYPE"
                      FROM "NOTIFICATIONRULE"
                     ORDER BY "ID"
                    """).mapToMap().list());

        assertThat(rows).hasSize(2);

        final Map<String, Object> good = rows.get(0);
        assertThat(good).containsEntry("id", 10L)
            .containsEntry("enabled", false)
            .containsEntry("name", "Good Rule")
            .containsEntry("notification_level", "INFORMATIONAL")
            .containsEntry("trigger_type", "EVENT");
        assertThat((String[]) ((java.sql.Array) good.get("notify_on")).getArray())
            .containsExactly("BOM_PROCESSED", "NEW_VULNERABILITY");
        assertThat((String) good.get("publisher_config"))
            .contains("\"destinationUrl\"")
            .contains("https://hooks.slack.com/abc");

        final Map<String, Object> bad = rows.get(1);
        assertThat(bad).containsEntry("id", 11L)
            .containsEntry("enabled", false)
            .containsEntry("name", "Bad Rule")
            .containsEntry("notification_level", "WARNING")
            .containsEntry("trigger_type", "EVENT");
        assertThat(bad.get("notify_on")).isNull();
        assertThat((String) bad.get("publisher_config"))
            .contains("\"destinationUrl\"")
            .contains("https://example.com");
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
