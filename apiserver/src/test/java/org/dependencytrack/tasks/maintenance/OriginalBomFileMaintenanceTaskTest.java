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

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.BomRetentionPolicy;
import org.dependencytrack.model.Project;
import org.dependencytrack.proto.internal.workflow.v1.DeleteFilesArgument;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_ORIGINAL_EXPIRATION_DAYS;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_ORIGINAL_RETENTION_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_ORIGINAL_RETENTION_POLICY;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class OriginalBomFileMaintenanceTaskTest extends PersistenceCapableTest {

    private final DexEngine dexEngine = mock(DexEngine.class);

    @Test
    void shouldClearExpiredFilesAndScheduleDeletionWithAgeBasedRetention() {
        configureRetention(true, BomRetentionPolicy.AGE_BASED);
        configureExpirationDays(30);
        final Project project = qm.createProject("acme-app", null, "1.0", null, null, null, null, false);
        final FileMetadata expiredFile = fileMetadata("expired");
        final Bom expired =
                persistBomImportedAt(project, expiredFile, Instant.now().minus(Duration.ofDays(40)));
        final Bom recent = persistBomImportedAt(project, fileMetadata("recent"), Instant.now());

        new OriginalBomFileMaintenanceTask(dexEngine).run();

        assertThat(getOriginalFileMetadata(expired)).isNull();
        assertThat(getOriginalFileMetadata(recent))
                .isEqualTo(fileMetadata("recent").toByteArray());
        verify(dexEngine).createRun(argThat(request -> {
            assertThat(request.workflowName()).isEqualTo("delete-files");
            assertThat(((DeleteFilesArgument) request.argument()).getFileMetadataList())
                    .containsExactly(expiredFile);
            return true;
        }));
    }

    @Test
    void shouldUseDefaultExpirationDaysWhenNotConfigured() {
        configureRetention(true, BomRetentionPolicy.AGE_BASED);
        final Project project = qm.createProject("acme-app", null, "1.0", null, null, null, null, false);
        final Bom olderThanDefault = persistBomImportedAt(
                project, fileMetadata("older"), Instant.now().minus(Duration.ofDays(100)));
        final Bom newerThanDefault = persistBomImportedAt(
                project, fileMetadata("newer"), Instant.now().minus(Duration.ofDays(80)));

        new OriginalBomFileMaintenanceTask(dexEngine).run();

        assertThat(getOriginalFileMetadata(olderThanDefault)).isNull();
        assertThat(getOriginalFileMetadata(newerThanDefault))
                .isEqualTo(fileMetadata("newer").toByteArray());
    }

    @ParameterizedTest
    @CsvSource({"false, AGE_BASED", "true, LATEST_ONLY"})
    void shouldDoNothingWhenAgeBasedRetentionIsInactive(boolean retentionEnabled, BomRetentionPolicy policy) {
        configureRetention(retentionEnabled, policy);
        configureExpirationDays(30);
        final Project project = qm.createProject("acme-app", null, "1.0", null, null, null, null, false);
        final Bom expired = persistBomImportedAt(
                project, fileMetadata("expired"), Instant.now().minus(Duration.ofDays(40)));

        new OriginalBomFileMaintenanceTask(dexEngine).run();

        assertThat(getOriginalFileMetadata(expired))
                .isEqualTo(fileMetadata("expired").toByteArray());
        verifyNoInteractions(dexEngine);
    }

    private void configureRetention(boolean enabled, BomRetentionPolicy policy) {
        qm.createConfigProperty(
                BOM_ORIGINAL_RETENTION_ENABLED.getGroupName(),
                BOM_ORIGINAL_RETENTION_ENABLED.getPropertyName(),
                String.valueOf(enabled),
                BOM_ORIGINAL_RETENTION_ENABLED.getPropertyType(),
                BOM_ORIGINAL_RETENTION_ENABLED.getDescription());
        qm.createConfigProperty(
                BOM_ORIGINAL_RETENTION_POLICY.getGroupName(),
                BOM_ORIGINAL_RETENTION_POLICY.getPropertyName(),
                policy.name(),
                BOM_ORIGINAL_RETENTION_POLICY.getPropertyType(),
                BOM_ORIGINAL_RETENTION_POLICY.getDescription());
    }

    private void configureExpirationDays(int days) {
        qm.createConfigProperty(
                BOM_ORIGINAL_EXPIRATION_DAYS.getGroupName(),
                BOM_ORIGINAL_EXPIRATION_DAYS.getPropertyName(),
                String.valueOf(days),
                BOM_ORIGINAL_EXPIRATION_DAYS.getPropertyType(),
                BOM_ORIGINAL_EXPIRATION_DAYS.getDescription());
    }

    private Bom persistBomImportedAt(
            final Project project, final @Nullable FileMetadata fileMetadata, final Instant importedAt) {
        final var bom = new Bom();
        bom.setProject(project);
        bom.setImported(Date.from(importedAt));
        bom.setBomFormat(Bom.Format.CYCLONEDX);
        bom.setSpecVersion("1.6");
        bom.setBomVersion(1);
        if (fileMetadata != null) {
            bom.setOriginalFileMetadata(fileMetadata.toByteArray());
        }
        return qm.persist(bom);
    }

    private static FileMetadata fileMetadata(final String name) {
        return FileMetadata.newBuilder()
                .setProviderName("test")
                .setLocation("test:///%s.json".formatted(name))
                .setMediaType("application/vnd.cyclonedx+json")
                .setSha256Digest(name)
                .build();
    }

    private static byte @Nullable [] getOriginalFileMetadata(final Bom bom) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT "ORIGINAL_FILE_METADATA" FROM "BOM" WHERE "ID" = :id
                        """)
                .bind("id", bom.getId())
                .mapTo(byte[].class)
                .one());
    }
}
