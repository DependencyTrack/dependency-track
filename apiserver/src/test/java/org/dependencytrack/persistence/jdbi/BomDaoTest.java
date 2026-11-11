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

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.jdbi.ProjectDao.OriginalBomFileMetadataRow;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

public class BomDaoTest extends PersistenceCapableTest {

    private Handle jdbiHandle;
    private BomDao dao;

    @BeforeEach
    void beforeEach() {
        jdbiHandle = openJdbiHandle();
        dao = jdbiHandle.attach(BomDao.class);
    }

    @AfterEach
    void afterEach() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }
    }

    @Test
    void isOriginalFileReferencedShouldOnlyMatchSameProjectAndFile() {
        final Project project = qm.createProject("acme-app", null, "1.0", null, null, null, null, false);
        final Project otherProject = qm.createProject("acme-other", null, "1.0", null, null, null, null, false);
        final FileMetadata file = fileMetadata("file");
        persistBom(project, file);

        assertThat(dao.isOriginalFileReferenced(project.getUuid(), file.toByteArray()))
                .isTrue();
        assertThat(dao.isOriginalFileReferenced(otherProject.getUuid(), file.toByteArray()))
                .isFalse();
        assertThat(dao.isOriginalFileReferenced(
                        project.getUuid(), fileMetadata("other").toByteArray()))
                .isFalse();
    }

    @Test
    void clearOlderOriginalFileMetadataShouldOnlyClearOlderFilesOfSameProject() {
        final Project project = qm.createProject("acme-app", null, "1.0", null, null, null, null, false);
        final Project otherProject = qm.createProject("acme-other", null, "1.0", null, null, null, null, false);

        final long olderA = persistBom(project, fileMetadata("older-a"));
        final long olderB = persistBom(project, fileMetadata("older-b"));
        final long notRetained = persistBom(project, null);
        final long otherProjectBom = persistBom(otherProject, fileMetadata("other-project"));
        final long boundary = persistBom(project, fileMetadata("current"));
        final long newer = persistBom(project, fileMetadata("newer"));

        final List<OriginalBomFileMetadataRow> clearedRows = dao.clearOlderOriginalFileMetadata(boundary);

        assertThat(clearedRows)
                .extracting(OriginalBomFileMetadataRow::projectUuid)
                .containsOnly(project.getUuid());
        assertThat(clearedRows)
                .extracting(OriginalBomFileMetadataRow::serializedFileMetadata)
                .containsExactlyInAnyOrder(
                        fileMetadata("older-a").toByteArray(),
                        fileMetadata("older-b").toByteArray());

        assertThat(getOriginalFileMetadata(olderA)).isNull();
        assertThat(getOriginalFileMetadata(olderB)).isNull();
        assertThat(getOriginalFileMetadata(notRetained)).isNull();
        assertThat(getOriginalFileMetadata(boundary))
                .isEqualTo(fileMetadata("current").toByteArray());
        assertThat(getOriginalFileMetadata(newer))
                .isEqualTo(fileMetadata("newer").toByteArray());
        assertThat(getOriginalFileMetadata(otherProjectBom))
                .isEqualTo(fileMetadata("other-project").toByteArray());

        assertThat(countBoms()).isEqualTo(6);
    }

    @Test
    void clearOlderOriginalFileMetadataShouldKeepFileSharedWithBoundary() {
        final Project project = qm.createProject("acme-app", null, "1.0", null, null, null, null, false);
        final FileMetadata current = fileMetadata("current");

        final long duplicate = persistBom(project, current);
        final long boundary = persistBom(project, current);

        assertThat(dao.clearOlderOriginalFileMetadata(boundary)).isEmpty();
        assertThat(getOriginalFileMetadata(duplicate)).isEqualTo(current.toByteArray());
    }

    @Test
    void clearOlderOriginalFileMetadataShouldReturnNothingWhenRepeated() {
        final Project project = qm.createProject("acme-app", null, "1.0", null, null, null, null, false);
        persistBom(project, fileMetadata("older"));
        final long boundary = persistBom(project, fileMetadata("current"));

        assertThat(dao.clearOlderOriginalFileMetadata(boundary)).hasSize(1);
        assertThat(dao.clearOlderOriginalFileMetadata(boundary)).isEmpty();
    }

    @Test
    void clearExpiredOriginalFileMetadataShouldOnlyClearFilesImportedAtOrBeforeCutoff() {
        final Project project = qm.createProject("acme-app", null, "1.0", null, null, null, null, false);
        final Project otherProject = qm.createProject("acme-other", null, "1.0", null, null, null, null, false);
        final Instant cutoff = Instant.parse("2026-01-10T00:00:00Z");

        final long beforeCutoff =
                persistBomImportedAt(project, fileMetadata("before"), cutoff.minus(Duration.ofDays(1)));
        final long atCutoff = persistBomImportedAt(project, fileMetadata("at"), cutoff);
        final long afterCutoff = persistBomImportedAt(project, fileMetadata("after"), cutoff.plusSeconds(1));
        final long notRetained = persistBomImportedAt(project, null, cutoff.minus(Duration.ofDays(1)));
        final long otherProjectExpired =
                persistBomImportedAt(otherProject, fileMetadata("other"), cutoff.minus(Duration.ofDays(1)));

        final List<OriginalBomFileMetadataRow> clearedRows = dao.clearExpiredOriginalFileMetadata(cutoff, 10);

        assertThat(clearedRows)
                .extracting(OriginalBomFileMetadataRow::serializedFileMetadata)
                .containsExactlyInAnyOrder(
                        fileMetadata("before").toByteArray(),
                        fileMetadata("at").toByteArray(),
                        fileMetadata("other").toByteArray());
        assertThat(clearedRows)
                .extracting(OriginalBomFileMetadataRow::projectUuid)
                .containsExactlyInAnyOrder(project.getUuid(), project.getUuid(), otherProject.getUuid());

        assertThat(getOriginalFileMetadata(beforeCutoff)).isNull();
        assertThat(getOriginalFileMetadata(atCutoff)).isNull();
        assertThat(getOriginalFileMetadata(otherProjectExpired)).isNull();
        assertThat(getOriginalFileMetadata(notRetained)).isNull();
        assertThat(getOriginalFileMetadata(afterCutoff))
                .isEqualTo(fileMetadata("after").toByteArray());

        assertThat(countBoms()).isEqualTo(5);
    }

    @Test
    void clearExpiredOriginalFileMetadataShouldClearAtMostBatchSize() {
        final Project project = qm.createProject("acme-app", null, "1.0", null, null, null, null, false);
        final Instant cutoff = Instant.now();
        persistBomImportedAt(project, fileMetadata("expired-1"), cutoff.minus(Duration.ofDays(3)));
        persistBomImportedAt(project, fileMetadata("expired-2"), cutoff.minus(Duration.ofDays(2)));
        persistBomImportedAt(project, fileMetadata("expired-3"), cutoff.minus(Duration.ofDays(1)));

        assertThat(dao.clearExpiredOriginalFileMetadata(cutoff, 2)).hasSize(2);
        assertThat(dao.clearExpiredOriginalFileMetadata(cutoff, 2)).hasSize(1);
        assertThat(dao.clearExpiredOriginalFileMetadata(cutoff, 2)).isEmpty();
    }

    @Test
    void clearExpiredOriginalFileMetadataShouldKeepFileReferencedByNonExpiredBom() {
        final Project project = qm.createProject("acme-app", null, "1.0", null, null, null, null, false);
        final Instant cutoff = Instant.now();
        final FileMetadata shared = fileMetadata("shared");

        final long expired = persistBomImportedAt(project, shared, cutoff.minus(Duration.ofDays(1)));
        persistBomImportedAt(project, shared, cutoff.plusSeconds(60));

        assertThat(dao.clearExpiredOriginalFileMetadata(cutoff, 10)).isEmpty();
        assertThat(getOriginalFileMetadata(expired)).isEqualTo(shared.toByteArray());
    }

    private long persistBom(final Project project, final @Nullable FileMetadata fileMetadata) {
        return persistBomImportedAt(project, fileMetadata, Instant.now());
    }

    private long persistBomImportedAt(
            final Project project, final @Nullable FileMetadata fileMetadata, final Instant importedAt) {
        return jdbiHandle
                .createQuery(/* language=SQL */ """
                        INSERT INTO "BOM" (
                          "PROJECT_ID", "UUID", "BOM_FORMAT", "SPEC_VERSION", "BOM_VERSION", "IMPORTED", "ORIGINAL_FILE_METADATA"
                        )
                        VALUES (:projectId, GEN_RANDOM_UUID(), 'CycloneDX', '1.6', 1, :imported, :originalFileMetadata)
                        RETURNING "ID"
                        """)
                .bind("projectId", project.getId())
                .bind("imported", Date.from(importedAt))
                .bind("originalFileMetadata", fileMetadata != null ? fileMetadata.toByteArray() : null)
                .mapTo(long.class)
                .one();
    }

    private static FileMetadata fileMetadata(final String name) {
        return FileMetadata.newBuilder()
                .setProviderName("test")
                .setLocation("test:///%s.json".formatted(name))
                .setMediaType("application/vnd.cyclonedx+json")
                .setSha256Digest(name)
                .build();
    }

    private byte @Nullable [] getOriginalFileMetadata(final long bomId) {
        return jdbiHandle.createQuery("""
                        SELECT "ORIGINAL_FILE_METADATA" FROM "BOM" WHERE "ID" = :id
                        """).bind("id", bomId).mapTo(byte[].class).one();
    }

    private long countBoms() {
        return jdbiHandle.createQuery("""
                        SELECT COUNT(*) FROM "BOM"
                        """).mapTo(long.class).one();
    }
}
