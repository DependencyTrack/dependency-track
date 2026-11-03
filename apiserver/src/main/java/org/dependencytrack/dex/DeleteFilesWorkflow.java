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
package org.dependencytrack.dex;

import org.dependencytrack.dex.activity.DeleteFilesActivity;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.proto.internal.workflow.v1.DeleteFilesArgument;
import org.jspecify.annotations.Nullable;

@WorkflowSpec(name = "delete-files")
public final class DeleteFilesWorkflow implements Workflow<DeleteFilesArgument, Void> {

    @Override
    public @Nullable Void execute(WorkflowContext<DeleteFilesArgument> ctx, @Nullable DeleteFilesArgument arg)
            throws Exception {
        ctx.activity(DeleteFilesActivity.class).call(arg).await();
        return null;
    }
}
