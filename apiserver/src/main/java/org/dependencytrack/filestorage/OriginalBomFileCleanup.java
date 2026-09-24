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

import com.google.protobuf.InvalidProtocolBufferException;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.persistence.jdbi.ProjectDao.OriginalBomFileMetadataRow;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class OriginalBomFileCleanup {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(OriginalBomFileCleanup.class);

    private OriginalBomFileCleanup() {
    }

    public static void deleteOriginalBomFiles(
            final FileStorage fileStorage,
            final List<OriginalBomFileMetadataRow> originalBomFiles) {
        final Map<FileMetadata, UUID> uniqueFileMetadata =
                new LinkedHashMap<>();

        for (final OriginalBomFileMetadataRow originalBomFile
                : originalBomFiles) {
            final FileMetadata fileMetadata;
            try {
                fileMetadata = FileMetadata.parseFrom(
                        originalBomFile.serializedFileMetadata());
            } catch (InvalidProtocolBufferException e) {
                LOGGER.warn(
                        "Failed to parse original BOM file metadata for "
                                + "deleted project {}; Manual cleanup may "
                                + "be required",
                        originalBomFile.projectUuid(),
                        e);
                continue;
            }

            uniqueFileMetadata.putIfAbsent(
                    fileMetadata,
                    originalBomFile.projectUuid());
        }

        for (final Map.Entry<FileMetadata, UUID> entry
                : uniqueFileMetadata.entrySet()) {
            final FileMetadata fileMetadata = entry.getKey();
            final UUID projectUuid = entry.getValue();

            try {
                fileStorage.delete(fileMetadata);
            } catch (NoSuchFileException e) {
                // Deletion is idempotent. The desired state is already met.
            } catch (IOException | RuntimeException e) {
                LOGGER.warn(
                        "Failed to delete original BOM file {} for deleted "
                                + "project {}; Manual cleanup may be required",
                        fileMetadata.getLocation(),
                        projectUuid,
                        e);
            }
        }
    }
}
