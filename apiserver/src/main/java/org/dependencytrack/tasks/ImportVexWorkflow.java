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
import org.dependencytrack.proto.internal.workflow.v1.ImportVexArg;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.MDC;

import java.util.List;

import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_VERSION;
import static org.dependencytrack.common.MdcKeys.MDC_VEX_UPLOAD_TOKEN;

/**
 * @since 5.0.0
 */
@NullMarked
@WorkflowSpec(name = "import-vex")
public final class ImportVexWorkflow implements Workflow<ImportVexArg, Void> {

    @Override
    public @Nullable Void execute(
            WorkflowContext<ImportVexArg> ctx,
            @Nullable ImportVexArg arg) throws Exception {
        if (arg == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        try (var _ = MDC.putCloseable(MDC_PROJECT_UUID, arg.getProjectUuid());
             var _ = MDC.putCloseable(MDC_PROJECT_NAME, arg.getProjectName());
             var _ = MDC.putCloseable(MDC_PROJECT_VERSION, arg.getProjectVersion());
             var _ = MDC.putCloseable(MDC_VEX_UPLOAD_TOKEN, arg.getVexUploadToken())) {
            ctx.logger().info("Starting VEX import");

            try {
                ctx.activity(ImportVexActivity.class).call(arg).await();
            } catch (Exception e) {
                tryDeleteVexFile(ctx, arg.getVexFileMetadata());
                throw e;
            }

            tryDeleteVexFile(ctx, arg.getVexFileMetadata());

            ctx.logger().info("VEX import completed");
            return null;
        }
    }

    private void tryDeleteVexFile(WorkflowContext<?> ctx, FileMetadata vexFileMetadata) {
        try {
            ctx.activity(DeleteFilesActivity.class)
                    .call(DeleteFilesArgument.newBuilder()
                            .addAllFileMetadata(List.of(vexFileMetadata))
                            .build())
                    .await();
        } catch (RuntimeException e) {
            ctx.logger().warn(
                    "Failed to delete VEX file {}; Will need manual cleanup",
                    vexFileMetadata.getLocation(),
                    e);
        }
    }

}
