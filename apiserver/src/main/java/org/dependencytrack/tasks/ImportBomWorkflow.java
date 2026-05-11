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
package org.dependencytrack.tasks;

import org.dependencytrack.dex.activity.DeleteFilesActivity;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.proto.internal.workflow.v1.DeleteFilesArgument;
import org.dependencytrack.proto.internal.workflow.v1.ImportBomArg;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.MDC;

import java.util.List;

import static org.dependencytrack.common.MdcKeys.MDC_BOM_UPLOAD_TOKEN;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_VERSION;

/**
 * @since 5.0.0
 */
@NullMarked
@WorkflowSpec(name = "import-bom")
public final class ImportBomWorkflow implements Workflow<ImportBomArg, Void> {

    @Override
    public @Nullable Void execute(
            WorkflowContext<ImportBomArg> ctx,
            @Nullable ImportBomArg arg) throws Exception {
        if (arg == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        try (var ignoredMdcProjectUuid = MDC.putCloseable(MDC_PROJECT_UUID, arg.getProjectUuid());
             var ignoredMdcProjectName = MDC.putCloseable(MDC_PROJECT_NAME, arg.getProjectName());
             var ignoredMdcProjectVersion = MDC.putCloseable(MDC_PROJECT_VERSION, arg.getProjectVersion());
             var ignoredMdcBomUploadToken = MDC.putCloseable(MDC_BOM_UPLOAD_TOKEN, arg.getBomUploadToken())) {
            ctx.logger().info("Starting BOM import");

            try {
                ctx.activity(ImportBomActivity.class).call(arg).await();
            } catch (Exception e) {
                tryDeleteBomFile(ctx, arg.getBomFileMetadata());
                throw e;
            }

            tryDeleteBomFile(ctx, arg.getBomFileMetadata());

            ctx.logger().info("BOM import completed");
            return null;
        }
    }

    private void tryDeleteBomFile(WorkflowContext<?> ctx, FileMetadata bomFileMetadata) {
        try {
            ctx.activity(DeleteFilesActivity.class)
                    .call(DeleteFilesArgument.newBuilder()
                            .addAllFileMetadata(List.of(bomFileMetadata))
                            .build())
                    .await();
        } catch (RuntimeException e) {
            ctx.logger().warn(
                    "Failed to delete BOM file {}; Will need manual cleanup",
                    bomFileMetadata.getLocation(),
                    e);
        }
    }

}
