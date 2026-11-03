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
import org.dependencytrack.dex.DeleteFilesWorkflow;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.persistence.jdbi.ProjectDao.OriginalBomFileMetadataRow;
import org.dependencytrack.proto.internal.workflow.v1.DeleteFilesArgument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class OriginalBomFileDeletion {

    private static final Logger LOGGER = LoggerFactory.getLogger(OriginalBomFileDeletion.class);

    private OriginalBomFileDeletion() {}

    public static void scheduleOriginalBomFileDeletion(
            final DexEngine dexEngine, final List<OriginalBomFileMetadataRow> originalBomFiles) {
        final Set<FileMetadata> uniqueFileMetadata = new LinkedHashSet<>();

        for (final OriginalBomFileMetadataRow originalBomFile : originalBomFiles) {
            final FileMetadata fileMetadata;
            try {
                fileMetadata = FileMetadata.parseFrom(originalBomFile.serializedFileMetadata());
            } catch (InvalidProtocolBufferException e) {
                LOGGER.warn(
                        "Failed to parse original BOM file metadata for "
                                + "deleted project {}; Manual cleanup may "
                                + "be required",
                        originalBomFile.projectUuid(),
                        e);
                continue;
            }

            uniqueFileMetadata.add(fileMetadata);
        }

        if (uniqueFileMetadata.isEmpty()) {
            return;
        }

        try {
            dexEngine.createRun(new CreateWorkflowRunRequest<>(DeleteFilesWorkflow.class)
                    .withArgument(DeleteFilesArgument.newBuilder()
                            .addAllFileMetadata(uniqueFileMetadata)
                            .build()));
        } catch (RuntimeException e) {
            LOGGER.warn("Failed to schedule original BOM file deletion; Manual cleanup may be required", e);
        }
    }
}
