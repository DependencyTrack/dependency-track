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
package org.dependencytrack.persistence.jdbi;

import com.github.packageurl.PackageURL;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentMetaInformation;
import org.dependencytrack.model.IntegrityMatchStatus;
import org.dependencytrack.model.PackageArtifactMetadata;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.model.Project;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class ComponentMetaDaoTest extends PersistenceCapableTest {

    @Test
    public void shouldComputeHashMatchPassedWhenSha256Matches() throws Exception {
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        final var component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        component.setSha256("abc123def456");
        qm.persist(component);

        createPackageMetadata("pkg:maven/org.acme/abc");
        useJdbiHandle(handle -> new PackageArtifactMetadataDao(handle).upsertAll(List.of(
                new PackageArtifactMetadata(
                        new PackageURL("pkg:maven/org.acme/abc"),
                        new PackageURL("pkg:maven/org.acme/abc"),
                        null, null, "ABC123DEF456", null,
                        Instant.now(),
                        null, null,
                        Instant.now()))));

        final ComponentMetaInformation result = withJdbiHandle(
                handle -> handle.attach(ComponentMetaDao.class).getComponentMetaInfo(component.getUuid()));
        assertThat(result).isNotNull();
        assertThat(result.integrityMatchStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_PASSED);
        assertThat(result.publishedDate()).isNotNull();
        assertThat(result.lastFetched()).isNotNull();
    }

    @Test
    public void shouldComputeHashMatchFailedWhenSha256Mismatches() throws Exception {
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        final var component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        component.setSha256("abc123def456");
        qm.persist(component);

        createPackageMetadata("pkg:maven/org.acme/abc");
        useJdbiHandle(handle -> new PackageArtifactMetadataDao(handle).upsertAll(List.of(
                new PackageArtifactMetadata(
                        new PackageURL("pkg:maven/org.acme/abc"),
                        new PackageURL("pkg:maven/org.acme/abc"),
                        null, null, "000000000000", null,
                        null,
                        null, null,
                        Instant.now()))));

        final ComponentMetaInformation result = withJdbiHandle(
                handle -> handle.attach(ComponentMetaDao.class).getComponentMetaInfo(component.getUuid()));
        assertThat(result).isNotNull();
        assertThat(result.integrityMatchStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_FAILED);
    }

    @Test
    public void shouldFallBackToSha1WhenSha256Unavailable() throws Exception {
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        final var component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        component.setSha1("aabbccdd");
        qm.persist(component);

        createPackageMetadata("pkg:maven/org.acme/abc");
        useJdbiHandle(handle -> new PackageArtifactMetadataDao(handle).upsertAll(List.of(
                new PackageArtifactMetadata(
                        new PackageURL("pkg:maven/org.acme/abc"),
                        new PackageURL("pkg:maven/org.acme/abc"),
                        null, "AABBCCDD", null, null,
                        null,
                        null, null,
                        Instant.now()))));

        final ComponentMetaInformation result = withJdbiHandle(
                handle -> handle.attach(ComponentMetaDao.class).getComponentMetaInfo(component.getUuid()));
        assertThat(result).isNotNull();
        assertThat(result.integrityMatchStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_PASSED);
    }

    @Test
    public void shouldReturnComponentMissingHashWhenComponentHasNoHashes() throws Exception {
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        final var component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        qm.persist(component);

        createPackageMetadata("pkg:maven/org.acme/abc");
        useJdbiHandle(handle -> new PackageArtifactMetadataDao(handle).upsertAll(List.of(
                new PackageArtifactMetadata(
                        new PackageURL("pkg:maven/org.acme/abc"),
                        new PackageURL("pkg:maven/org.acme/abc"),
                        null, null, "abc123", null,
                        null,
                        null, null,
                        Instant.now()))));

        final ComponentMetaInformation result = withJdbiHandle(
                handle -> handle.attach(ComponentMetaDao.class).getComponentMetaInfo(component.getUuid()));
        assertThat(result).isNotNull();
        assertThat(result.integrityMatchStatus()).isEqualTo(IntegrityMatchStatus.COMPONENT_MISSING_HASH);
    }

    @Test
    public void shouldReturnHashMatchUnknownWhenMetadataHasNoMatchingHash() throws Exception {
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        final var component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        component.setSha256("abc123");
        qm.persist(component);

        createPackageMetadata("pkg:maven/org.acme/abc");
        useJdbiHandle(handle -> new PackageArtifactMetadataDao(handle).upsertAll(List.of(
                new PackageArtifactMetadata(
                        new PackageURL("pkg:maven/org.acme/abc"),
                        new PackageURL("pkg:maven/org.acme/abc"),
                        null, null, null, null,
                        null,
                        null, null,
                        Instant.now()))));

        final ComponentMetaInformation result = withJdbiHandle(
                handle -> handle.attach(ComponentMetaDao.class).getComponentMetaInfo(component.getUuid()));
        assertThat(result).isNotNull();
        assertThat(result.integrityMatchStatus()).isEqualTo(IntegrityMatchStatus.HASH_MATCH_UNKNOWN);
    }

    @Test
    public void shouldReturnNullIntegrityStatusWhenNoVersionMetadata() {
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        final var component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        component.setSha256("abc123");
        qm.persist(component);

        final ComponentMetaInformation result = withJdbiHandle(
                handle -> handle.attach(ComponentMetaDao.class).getComponentMetaInfo(component.getUuid()));
        assertThat(result).isNull();
    }

    private void createPackageMetadata(String purl) throws Exception {
        useJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(List.of(
                new PackageMetadata(
                        new PackageURL(purl),
                        "1.0.0",
                        Instant.now(),
                        Instant.now(),
                        null,
                        null))));
    }

}
