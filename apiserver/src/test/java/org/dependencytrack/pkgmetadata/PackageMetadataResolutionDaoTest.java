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
package org.dependencytrack.pkgmetadata;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class PackageMetadataResolutionDaoTest extends PersistenceCapableTest {

    @Test
    void seedPendingShouldSeedProjectPurlsIncludingMalformedOnes() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentResolved = new Component();
        componentResolved.setProject(project);
        componentResolved.setName("resolved");
        componentResolved.setVersion("1.0.0");
        componentResolved.setPurl("pkg:maven/com.acme/resolved@1.0.0");
        qm.persist(componentResolved);

        final var componentMalformedPurl = new Component();
        componentMalformedPurl.setProject(project);
        componentMalformedPurl.setName("malformed");
        componentMalformedPurl.setVersion("1.0.0");
        componentMalformedPurl.setPurl("pkg:maven/com.acme/malformed%ZZ@1.0.0");
        qm.persist(componentMalformedPurl);

        final var componentNoPurl = new Component();
        componentNoPurl.setProject(project);
        componentNoPurl.setName("no-purl");
        componentNoPurl.setVersion("1.0.0");
        qm.persist(componentNoPurl);

        assertThat(packageMetadataResolutionRows()).isEmpty();

        useJdbiHandle(handle -> new PackageMetadataResolutionDao(handle).seedPending(project.getId()));

        assertThat(packageMetadataResolutionRows())
                .satisfiesExactly(
                        row -> {
                            assertThat(row).containsEntry("purl", "pkg:maven/com.acme/malformed%ZZ@1.0.0");
                            assertThat(row).containsEntry("status", "PENDING");
                        },
                        row -> {
                            assertThat(row).containsEntry("purl", "pkg:maven/com.acme/resolved@1.0.0");
                            assertThat(row).containsEntry("status", "PENDING");
                        });
    }

    private static List<Map<String, Object>> packageMetadataResolutionRows() {
        return withJdbiHandle(
                handle -> handle.createQuery(/* language=SQL */ """
                    SELECT "PURL"
                         , "STATUS"
                      FROM "PACKAGE_METADATA_RESOLUTION"
                     ORDER BY "PURL"
                    """).mapToMap().list());
    }
}
