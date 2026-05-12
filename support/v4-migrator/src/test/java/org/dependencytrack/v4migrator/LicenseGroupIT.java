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
 * Straight 1:1 migration of LICENSEGROUP and its LICENSEGROUP_LICENSE join table. UUID on
 * the parent converts from {@code varchar(36)} to native {@code uuid}; the join table is a
 * pure pass-through.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class LicenseGroupIT {

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
    void migratesLicenseGroupAndJoin() throws Exception {
        final UUID apacheUuid = UUID.fromString("c5b25734-69ce-4e9b-a4f3-1f0fa5b27d5f");
        final UUID groupUuid  = UUID.fromString("dddddddd-dddd-dddd-dddd-dddddddddddd");
        source.jdbi().useHandle(h -> {
            h.createUpdate("""
                    INSERT INTO "LICENSE"
                        ("ID", "ISDEPRECATED", "ISOSIAPPROVED", "NAME", "LICENSEID", "UUID")
                    VALUES (1, FALSE, TRUE, 'Apache 2.0', 'Apache-2.0', :u)
                """).bind("u", apacheUuid.toString()).execute();
            h.createUpdate("""
                    INSERT INTO "LICENSEGROUP" ("ID", "NAME", "RISKWEIGHT", "UUID")
                    VALUES (10, 'Permissive', 1, :u)
                """).bind("u", groupUuid.toString()).execute();
            h.execute("""
                    INSERT INTO "LICENSEGROUP_LICENSE" ("LICENSEGROUP_ID", "LICENSE_ID")
                    VALUES (10, 1)
                """);
        });

        runPipeline();

        final List<Map<String, Object>> groups = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "NAME", "RISKWEIGHT", "UUID"
                      FROM "LICENSEGROUP"
                     ORDER BY "ID"
                    """).mapToMap().list());
        assertThat(groups).extracting("id", "name", "riskweight", "uuid")
            .containsExactly(tuple(10L, "Permissive", 1, groupUuid));

        final List<Map<String, Object>> joins = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "LICENSEGROUP_ID", "LICENSE_ID"
                      FROM "LICENSEGROUP_LICENSE"
                     ORDER BY "LICENSEGROUP_ID", "LICENSE_ID"
                    """).mapToMap().list());
        assertThat(joins).extracting("licensegroup_id", "license_id")
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
