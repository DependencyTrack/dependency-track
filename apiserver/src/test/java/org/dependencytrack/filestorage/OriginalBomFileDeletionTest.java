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
package org.dependencytrack.filestorage;

import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.persistence.jdbi.ProjectDao.OriginalBomFileMetadataRow;
import org.dependencytrack.proto.internal.workflow.v1.DeleteFilesArgument;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class OriginalBomFileDeletionTest {

    private final DexEngine dexEngine = mock(DexEngine.class);

    @Test
    void shouldScheduleDistinctOriginalBomFiles() {
        final FileMetadata firstFileMetadata = fileMetadata("test:///original-bom-first");
        final FileMetadata secondFileMetadata = fileMetadata("test:///original-bom-second");

        final List<OriginalBomFileMetadataRow> originalBomFiles = List.of(
                originalBomFile(firstFileMetadata),
                originalBomFile(firstFileMetadata),
                originalBomFile(secondFileMetadata));

        OriginalBomFileDeletion.scheduleOriginalBomFileDeletion(dexEngine, originalBomFiles);

        verify(dexEngine).createRun(argThat(request -> {
            assertThat(request.workflowName()).isEqualTo("delete-files");
            assertThat(((DeleteFilesArgument) request.argument()).getFileMetadataList())
                    .containsExactly(firstFileMetadata, secondFileMetadata);
            return true;
        }));
    }

    @Test
    void shouldSkipMalformedMetadataAndContinue() {
        final FileMetadata validFileMetadata = fileMetadata("test:///original-bom-valid");

        final List<OriginalBomFileMetadataRow> originalBomFiles = List.of(
                new OriginalBomFileMetadataRow(UUID.randomUUID(), new byte[] {(byte) 0x80}),
                originalBomFile(validFileMetadata));

        assertThatNoException()
                .isThrownBy(() -> OriginalBomFileDeletion.scheduleOriginalBomFileDeletion(dexEngine, originalBomFiles));

        verify(dexEngine).createRun(argThat(request -> {
            assertThat(((DeleteFilesArgument) request.argument()).getFileMetadataList())
                    .containsExactly(validFileMetadata);
            return true;
        }));
    }

    @Test
    void shouldDoNothingWhenNoOriginalBomFilesExist() {
        OriginalBomFileDeletion.scheduleOriginalBomFileDeletion(dexEngine, List.of());

        verifyNoInteractions(dexEngine);
    }

    private static OriginalBomFileMetadataRow originalBomFile(final FileMetadata fileMetadata) {
        return new OriginalBomFileMetadataRow(UUID.randomUUID(), fileMetadata.toByteArray());
    }

    private static FileMetadata fileMetadata(final String location) {
        return FileMetadata.newBuilder()
                .setProviderName("test")
                .setLocation(location)
                .setMediaType("application/vnd.cyclonedx+json")
                .setSha256Digest(location)
                .build();
    }
}
