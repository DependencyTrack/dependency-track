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
 * Exercises the v4 NOTIFICATIONRULE_TAGS / NOTIFICATIONRULE_TEAMS join-table transforms.
 * Both columns are rewritten through the rule and tag/team canonical-id maps. v4 allows
 * NULL {@code TEAM_ID}; v5 tightens to NOT NULL so those rows are dropped.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class NotificationJoinIT {

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
    void rewritesJoinTablesAndDropsNullTeam() throws Exception {
        source.jdbi().useHandle(h -> {
            h.execute("INSERT INTO \"TAG\" (\"ID\", \"NAME\") VALUES (1, 'frontend')");
            h.execute("INSERT INTO \"TAG\" (\"ID\", \"NAME\") VALUES (2, 'backend')");
            h.execute("INSERT INTO \"TEAM\" (\"ID\", \"NAME\", \"UUID\") VALUES (1, 'Engineering', '00000000-0000-0000-0000-000000000001')");
            h.execute("INSERT INTO \"TEAM\" (\"ID\", \"NAME\", \"UUID\") VALUES (2, 'Security',    '00000000-0000-0000-0000-000000000002')");
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
            // Tags and teams on the rule.
            h.execute("INSERT INTO \"NOTIFICATIONRULE_TAGS\" (\"NOTIFICATIONRULE_ID\", \"TAG_ID\") VALUES (10, 1)");
            h.execute("INSERT INTO \"NOTIFICATIONRULE_TAGS\" (\"NOTIFICATIONRULE_ID\", \"TAG_ID\") VALUES (10, 2)");
            h.execute("INSERT INTO \"NOTIFICATIONRULE_TEAMS\" (\"NOTIFICATIONRULE_ID\", \"TEAM_ID\") VALUES (10, 1)");
            // NULL TEAM_ID — must be dropped on the way to v5.
            h.execute("INSERT INTO \"NOTIFICATIONRULE_TEAMS\" (\"NOTIFICATIONRULE_ID\", \"TEAM_ID\") VALUES (10, NULL)");
        });

        runPipeline();

        final List<Map<String, Object>> tags = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "NOTIFICATIONRULE_ID", "TAG_ID"
                      FROM "NOTIFICATIONRULE_TAGS"
                     ORDER BY "TAG_ID"
                    """).mapToMap().list());
        assertThat(tags).extracting("notificationrule_id", "tag_id")
            .containsExactly(
                tuple(10L, 1L),
                tuple(10L, 2L)
            );

        final List<Map<String, Object>> teams = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "NOTIFICATIONRULE_ID", "TEAM_ID"
                      FROM "NOTIFICATIONRULE_TEAMS"
                     ORDER BY "TEAM_ID"
                    """).mapToMap().list());
        assertThat(teams).extracting("notificationrule_id", "team_id")
            .containsExactly(tuple(10L, 1L));
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
