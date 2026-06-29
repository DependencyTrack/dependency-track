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
package org.dependencytrack.kevdatasource;

import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.proto.internal.workflow.v1.MirrorKevDataSourceArg;
import org.jspecify.annotations.Nullable;

/// @since 5.1.0
@WorkflowSpec(name = "mirror-kev-data-source")
public final class MirrorKevDataSourceWorkflow implements Workflow<MirrorKevDataSourceArg, Void> {

    @Override
    public @Nullable Void execute(
            WorkflowContext<@Nullable MirrorKevDataSourceArg> ctx,
            @Nullable MirrorKevDataSourceArg arg) throws Exception {
        if (arg == null || arg.getDataSourceName().isEmpty()) {
            throw new TerminalApplicationFailureException("No argument or data source name provided");
        }

        ctx.activity(MirrorKevDataSourceActivity.class).call(arg).await();
        return null;
    }

}
