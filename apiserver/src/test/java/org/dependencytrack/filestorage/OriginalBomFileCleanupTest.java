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

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.persistence.jdbi.ProjectDao.OriginalBomFileMetadataRow;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.slf4j.LoggerFactory.getLogger;

class OriginalBomFileCleanupTest {

    private final FileStorage fileStorage = mock(FileStorage.class);

    @Test
    void shouldDeleteDistinctOriginalBomFiles() throws Exception {
        final FileMetadata firstFileMetadata = fileMetadata(
                "test:///original-bom-first");
        final FileMetadata secondFileMetadata = fileMetadata(
                "test:///original-bom-second");

        final List<OriginalBomFileMetadataRow> originalBomFiles = List.of(
                originalBomFile(firstFileMetadata),
                originalBomFile(firstFileMetadata),
                originalBomFile(secondFileMetadata));

        OriginalBomFileCleanup.deleteOriginalBomFiles(
                fileStorage,
                originalBomFiles);

        verify(fileStorage).delete(firstFileMetadata);
        verify(fileStorage).delete(secondFileMetadata);
    }

    @Test
    void shouldSkipMalformedMetadataAndContinue() throws Exception {
        final FileMetadata validFileMetadata = fileMetadata(
                "test:///original-bom-valid");

        final List<OriginalBomFileMetadataRow> originalBomFiles = List.of(
                new OriginalBomFileMetadataRow(
                        UUID.randomUUID(),
                        new byte[]{(byte) 0x80}),
                originalBomFile(validFileMetadata));

        assertThatNoException().isThrownBy(() ->
                OriginalBomFileCleanup.deleteOriginalBomFiles(
                        fileStorage,
                        originalBomFiles));

        verify(fileStorage).delete(validFileMetadata);
    }

    @Test
    void shouldContinueWhenFileDeletionFails() throws Exception {
        final FileMetadata failingFileMetadata = fileMetadata(
                "test:///original-bom-failing");
        final FileMetadata successfulFileMetadata = fileMetadata(
                "test:///original-bom-successful");

        doThrow(new IOException("Storage unavailable"))
                .when(fileStorage)
                .delete(failingFileMetadata);

        final List<OriginalBomFileMetadataRow> originalBomFiles = List.of(
                originalBomFile(failingFileMetadata),
                originalBomFile(successfulFileMetadata));

        assertThatNoException().isThrownBy(() ->
                OriginalBomFileCleanup.deleteOriginalBomFiles(
                        fileStorage,
                        originalBomFiles));

        verify(fileStorage).delete(failingFileMetadata);
        verify(fileStorage).delete(successfulFileMetadata);
    }

    @Test
    void shouldQuietlyIgnoreMissingFileAndContinue() throws Exception {
        final FileMetadata missingFileMetadata = fileMetadata(
                "test:///original-bom-missing");
        final FileMetadata existingFileMetadata = fileMetadata(
                "test:///original-bom-existing");

        doThrow(new NoSuchFileException(missingFileMetadata.getLocation()))
                .when(fileStorage)
                .delete(missingFileMetadata);

        final Logger logger =
                (Logger) getLogger(OriginalBomFileCleanup.class);
        final var appender = new ListAppender<ILoggingEvent>();
        appender.start();
        logger.addAppender(appender);
        try {
            assertThatNoException().isThrownBy(() ->
                    OriginalBomFileCleanup.deleteOriginalBomFiles(
                            fileStorage,
                            List.of(
                                    originalBomFile(missingFileMetadata),
                                    originalBomFile(existingFileMetadata))));
        } finally {
            logger.detachAppender(appender);
            appender.stop();
        }

        verify(fileStorage).delete(missingFileMetadata);
        verify(fileStorage).delete(existingFileMetadata);
        assertThat(appender.list).isEmpty();
    }

    @Test
    void shouldContinueWhenProviderThrowsRuntimeException() throws Exception {
        final FileMetadata failingFileMetadata = fileMetadata(
                "test:///original-bom-runtime-failure");
        final FileMetadata successfulFileMetadata = fileMetadata(
                "test:///original-bom-after-runtime-failure");

        doThrow(new IllegalStateException("Storage provider failed"))
                .when(fileStorage)
                .delete(failingFileMetadata);

        assertThatNoException().isThrownBy(() ->
                OriginalBomFileCleanup.deleteOriginalBomFiles(
                        fileStorage,
                        List.of(
                                originalBomFile(failingFileMetadata),
                                originalBomFile(successfulFileMetadata))));

        verify(fileStorage).delete(failingFileMetadata);
        verify(fileStorage).delete(successfulFileMetadata);
    }

    @Test
    void shouldDoNothingWhenNoOriginalBomFilesExist() {
        OriginalBomFileCleanup.deleteOriginalBomFiles(
                fileStorage,
                List.of());

        verifyNoInteractions(fileStorage);
    }

    private static OriginalBomFileMetadataRow originalBomFile(
            final FileMetadata fileMetadata) {
        return new OriginalBomFileMetadataRow(
                UUID.randomUUID(),
                fileMetadata.toByteArray());
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
