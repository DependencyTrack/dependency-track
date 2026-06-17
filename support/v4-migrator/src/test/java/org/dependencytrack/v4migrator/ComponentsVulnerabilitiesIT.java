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
 * Exercises the two pure-join transforms COMPONENTS_VULNERABILITIES and
 * VULNERABLESOFTWARE_VULNERABILITIES. Each is INNER-JOINed through the relevant
 * canonical-id maps; rows referencing a malformed-UUID entity are dropped.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ComponentsVulnerabilitiesIT {

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
    void rewritesJoinTablesThroughCanonicalMapsAndDropsMalformedRefs() throws Exception {
        source.jdbi().useHandle(h -> {
            h.execute("""
                INSERT INTO "PROJECT" ("ID", "NAME", "VERSION", "UUID", "LAST_BOM_IMPORTED")
                VALUES (1, 'P', '1.0', '00000000-0000-0000-0000-000000000001',
                        '2024-01-01T00:00:00Z')
                """);
            h.execute("""
                INSERT INTO "COMPONENT" ("ID", "NAME", "UUID", "PROJECT_ID")
                VALUES (10, 'c1', '00000000-0000-0000-0000-00000000000a', 1)
                """);
            h.execute("""
                INSERT INTO "VULNERABILITY" ("ID", "UUID", "VULNID", "SOURCE", "SEVERITY")
                VALUES (100, '00000000-0000-0000-0000-000000000100', 'CVE-2024-0001', 'NVD', 'HIGH')
                """);
            // Malformed-UUID vulnerability is dropped from the v5 vuln set, so joins must drop too.
            h.execute("""
                INSERT INTO "VULNERABILITY" ("ID", "UUID", "VULNID", "SOURCE", "SEVERITY")
                VALUES (200, 'not-a-uuid', 'CVE-2024-0002', 'NVD', 'LOW')
                """);
            h.execute("""
                INSERT INTO "VULNERABLESOFTWARE" (
                    "ID", "UUID", "VULNERABLE", "PURL"
                )
                VALUES (1000, '00000000-0000-0000-0000-0000000000aa', TRUE, 'pkg:maven/g/a@1')
                """);

            // CV: one good join, one referencing the malformed-UUID vuln (must drop), and a dup.
            h.execute("INSERT INTO \"COMPONENTS_VULNERABILITIES\" (\"COMPONENT_ID\", \"VULNERABILITY_ID\") VALUES (10, 100)");
            h.execute("INSERT INTO \"COMPONENTS_VULNERABILITIES\" (\"COMPONENT_ID\", \"VULNERABILITY_ID\") VALUES (10, 100)");
            h.execute("INSERT INTO \"COMPONENTS_VULNERABILITIES\" (\"COMPONENT_ID\", \"VULNERABILITY_ID\") VALUES (10, 200)");

            // VV: one good, one referencing malformed-UUID vuln (must drop).
            h.execute("INSERT INTO \"VULNERABLESOFTWARE_VULNERABILITIES\" (\"VULNERABILITY_ID\", \"VULNERABLESOFTWARE_ID\") VALUES (100, 1000)");
            h.execute("INSERT INTO \"VULNERABLESOFTWARE_VULNERABILITIES\" (\"VULNERABILITY_ID\", \"VULNERABLESOFTWARE_ID\") VALUES (200, 1000)");
        });

        runPipeline();

        final List<Map<String, Object>> cv = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "COMPONENT_ID", "VULNERABILITY_ID"
                      FROM "COMPONENTS_VULNERABILITIES"
                     ORDER BY "COMPONENT_ID", "VULNERABILITY_ID"
                    """).mapToMap().list());
        assertThat(cv).extracting("component_id", "vulnerability_id")
            .containsExactly(tuple(10L, 100L));

        final List<Map<String, Object>> vv = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "VULNERABILITY_ID", "VULNERABLESOFTWARE_ID"
                      FROM "VULNERABLESOFTWARE_VULNERABILITIES"
                     ORDER BY "VULNERABILITY_ID", "VULNERABLESOFTWARE_ID"
                    """).mapToMap().list());
        assertThat(vv).extracting("vulnerability_id", "vulnerablesoftware_id")
            .containsExactly(tuple(100L, 1000L));
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
