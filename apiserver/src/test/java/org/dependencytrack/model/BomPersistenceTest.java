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
package org.dependencytrack.model;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class BomPersistenceTest extends PersistenceCapableTest {

    @Test
    public void shouldPersistOriginalFileMetadata() throws Exception {
        final var fileMetadata = FileMetadata.newBuilder()
                .setLocation("memory:///bom-upload/test")
                .setMediaType("application/vnd.cyclonedx+json")
                .setSha256Digest("0123456789abcdef")
                .setProviderName("memory")
                .putAdditionalMetadata("encryption-key-id", "test-key")
                .build();
        final byte[] expectedBytes = fileMetadata.toByteArray();

        final var project = new Project();
        project.setName("project");
        qm.persist(project);

        final var bom = new Bom();
        bom.setProject(project);
        bom.setImported(new Date());
        bom.setBomFormat(Bom.Format.CYCLONEDX);
        bom.setSpecVersion("1.6");
        bom.setBomVersion(1);
        bom.setOriginalFileMetadata(expectedBytes);
        qm.persist(bom);

        final long bomId = bom.getId();

        qm.getPersistenceManager().evictAll();

        final Bom reloadedBom = qm.getObjectById(Bom.class, bomId);

        assertThat(reloadedBom.getOriginalFileMetadata()).isEqualTo(expectedBytes);
        assertThat(FileMetadata.parseFrom(reloadedBom.getOriginalFileMetadata()))
                .isEqualTo(fileMetadata);

        final byte[] storedBytes = withJdbiHandle(handle ->
                handle.createQuery("""
                        SELECT "ORIGINAL_FILE_METADATA"
                        FROM "BOM"
                        WHERE "ID" = :bomId
                        """).bind("bomId", bomId).mapTo(byte[].class).one());

        assertThat(storedBytes).containsExactly(expectedBytes);
        assertThat(FileMetadata.parseFrom(storedBytes)).isEqualTo(fileMetadata);
    }

    @Test
    public void shouldPersistNullOriginalFileMetadata() {
        final var project = new Project();
        project.setName("project");
        qm.persist(project);

        final var bom = new Bom();
        bom.setProject(project);
        bom.setImported(new Date());
        bom.setBomFormat(Bom.Format.CYCLONEDX);
        bom.setSpecVersion("1.6");
        bom.setBomVersion(1);
        qm.persist(bom);

        final long bomId = bom.getId();

        qm.getPersistenceManager().evictAll();

        final Bom reloadedBom = qm.getObjectById(Bom.class, bomId);

        assertThat(reloadedBom.getOriginalFileMetadata()).isNull();

        final boolean metadataIsNull = withJdbiHandle(handle -> handle.createQuery("""
                        SELECT "ORIGINAL_FILE_METADATA" IS NULL
                        FROM "BOM"
                        WHERE "ID" = :bomId
                        """)
                .bind("bomId", bomId)
                .mapTo(boolean.class)
                .one());

        assertThat(metadataIsNull).isTrue();
    }
}
