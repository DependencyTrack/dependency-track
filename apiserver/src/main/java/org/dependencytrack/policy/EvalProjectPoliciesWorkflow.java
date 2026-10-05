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
package org.dependencytrack.policy;

import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.metrics.UpdateProjectMetricsActivity;
import org.dependencytrack.proto.internal.workflow.v1.EvalProjectPoliciesArg;
import org.dependencytrack.proto.internal.workflow.v1.UpdateProjectMetricsArg;
import org.jspecify.annotations.Nullable;

/**
 * Evaluates policies for one project and then updates that project's metrics.
 *
 * @since 5.2.0
 */
@WorkflowSpec(name = "eval-project-policies")
public final class EvalProjectPoliciesWorkflow implements Workflow<EvalProjectPoliciesArg, Void> {

    @Override
    public @Nullable Void execute(
            final WorkflowContext<@Nullable EvalProjectPoliciesArg> ctx, final @Nullable EvalProjectPoliciesArg arg)
            throws Exception {
        if (arg == null || arg.getProjectUuid().isBlank()) {
            throw new TerminalApplicationFailureException("No project UUID provided");
        }

        ctx.activity(EvalProjectPoliciesActivity.class).call(arg).await();

        ctx.activity(UpdateProjectMetricsActivity.class)
                .call(UpdateProjectMetricsArg.newBuilder()
                        .setProjectUuid(arg.getProjectUuid())
                        .build())
                .await();

        return null;
    }
}
