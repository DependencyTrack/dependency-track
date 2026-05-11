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
package org.dependencytrack.tasks.maintenance;

import com.github.packageurl.PackageURL;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.maintenance.PackageMetadataMaintenanceEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.PackageArtifactMetadata;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.jdbi.PackageArtifactMetadataDao;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class PackageMetadataMaintenanceTaskTest extends PersistenceCapableTest {

    @Test
    public void test() throws Exception {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        qm.persist(component);

        final Instant now = Instant.now();

        useJdbiHandle(handle -> {
            new PackageMetadataDao(handle).upsertAll(List.of(
                    new PackageMetadata(
                            new PackageURL("pkg:maven/com.acme/acme-lib"),
                            "2.0.0",
                            now.minus(20, ChronoUnit.DAYS),
                            now.minus(29, ChronoUnit.DAYS),
                            null,
                            null),
                    new PackageMetadata(
                            new PackageURL("pkg:maven/foo/bar"),
                            "3.2.1",
                            now.minus(20, ChronoUnit.DAYS),
                            now.minus(31, ChronoUnit.DAYS),
                            null,
                            null)));

            new PackageArtifactMetadataDao(handle).upsertAll(List.of(
                    new PackageArtifactMetadata(
                            new PackageURL("pkg:maven/com.acme/acme-lib@1.0.0"),
                            new PackageURL("pkg:maven/com.acme/acme-lib"),
                            null, null, null, null,
                            null,
                            null, null,
                            now),
                    new PackageArtifactMetadata(
                            new PackageURL("pkg:maven/foo/bar@1.2.3"),
                            new PackageURL("pkg:maven/foo/bar"),
                            null, null, null, null,
                            null,
                            null, null,
                            now)));
        });

        final var task = new PackageMetadataMaintenanceTask();
        assertThatNoException().isThrownBy(() -> task.inform(new PackageMetadataMaintenanceEvent()));

        final long acmeLibArtifactCount = withJdbiHandle(handle -> handle
                .createQuery("SELECT COUNT(*) FROM \"PACKAGE_ARTIFACT_METADATA\" WHERE \"PURL\" = :purl")
                .bind("purl", "pkg:maven/com.acme/acme-lib@1.0.0")
                .mapTo(Long.class)
                .one());
        assertThat(acmeLibArtifactCount).isEqualTo(1);

        final long fooBarArtifactCount = withJdbiHandle(handle -> handle
                .createQuery("SELECT COUNT(*) FROM \"PACKAGE_ARTIFACT_METADATA\" WHERE \"PURL\" = :purl")
                .bind("purl", "pkg:maven/foo/bar@1.2.3")
                .mapTo(Long.class)
                .one());
        assertThat(fooBarArtifactCount).isEqualTo(0);

        final PackageMetadata acmeLibMetadata = withJdbiHandle(
                handle -> new PackageMetadataDao(handle).get(
                        new PackageURL("pkg:maven/com.acme/acme-lib")));
        assertThat(acmeLibMetadata).isNotNull();

        final PackageMetadata fooBarMetadata = withJdbiHandle(
                handle -> new PackageMetadataDao(handle).get(
                        new PackageURL("pkg:maven/foo/bar")));
        assertThat(fooBarMetadata).isNull();
    }

}
