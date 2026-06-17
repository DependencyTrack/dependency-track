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
import org.dependencytrack.v4migrator.testsupport.V4MssqlSource;
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

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class LicensePipelineMssqlIT {

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
    void extractTransformLoadLicensesFromMssql() throws Exception {
        final UUID apacheUuid = UUID.fromString("c5b25734-69ce-4e9b-a4f3-1f0fa5b27d5f");
        final UUID mitUuid = UUID.fromString("8a3a4c1d-5be9-4d2a-9bc1-4d8a8c5d4b3a");
        final byte[] seeAlsoBytes = new byte[]{1, 2, 3, 4, 5};
        source.withIdentityInsert("LICENSE", h -> {
            h.createUpdate("""
                    INSERT INTO [LICENSE]
                        ([ID], [ISDEPRECATED], [ISOSIAPPROVED], [NAME], [LICENSEID], [UUID], [SEEALSO])
                    VALUES (1, 0, 1, 'Apache 2.0', 'Apache-2.0', :u, :sa)
                """).bind("u", apacheUuid.toString()).bind("sa", seeAlsoBytes).execute();
            h.createUpdate("""
                    INSERT INTO [LICENSE]
                        ([ID], [ISDEPRECATED], [ISOSIAPPROVED], [NAME], [LICENSEID], [UUID])
                    VALUES (2, 0, 1, 'MIT License', 'MIT', :u)
                """).bind("u", mitUuid.toString()).execute();
        });

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

        final List<Map<String, Object>> rows = target.jdbi().withHandle(h ->
            h.createQuery("""
                    SELECT "ID", "NAME", "LICENSEID", "UUID", "SEEALSO", "ISDEPRECATED", "ISOSIAPPROVED"
                      FROM "LICENSE"
                     ORDER BY "ID"
                    """)
                .mapToMap()
                .list());

        assertThat(rows).hasSize(2);
        assertThat(rows.get(0)).containsEntry("id", 1L)
            .containsEntry("name", "Apache 2.0")
            .containsEntry("licenseid", "Apache-2.0")
            .containsEntry("uuid", apacheUuid)
            .containsEntry("isdeprecated", false)
            .containsEntry("isosiapproved", true);
        assertThat((byte[]) rows.get(0).get("seealso")).isEqualTo(seeAlsoBytes);
        assertThat(rows.get(1)).containsEntry("id", 2L)
            .containsEntry("name", "MIT License")
            .containsEntry("uuid", mitUuid);
    }
}
