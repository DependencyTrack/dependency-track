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
package org.dependencytrack.metrics;

import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.proto.internal.workflow.v1.UpdateProjectMetricsArg;
import org.jspecify.annotations.Nullable;

import java.util.UUID;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.3.0
 */
@WorkflowSpec(name = "update-project-metrics")
public final class UpdateProjectMetricsWorkflow implements Workflow<UpdateProjectMetricsArg, Void> {

    public static final String NAME = "update-project-metrics";

    @Override
    public @Nullable Void execute(WorkflowContext<UpdateProjectMetricsArg> ctx, @Nullable UpdateProjectMetricsArg arg)
            throws Exception {
        if (arg == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        ctx.activity(UpdateProjectMetricsActivity.class)
                .call(arg)
                .await();

        ctx.activity(RefreshGlobalPortfolioMetricsActivity.class)
                .call()
                .await();

        return null;
    }

    public static String instanceId(UUID projectUuid) {
        requireNonNull(projectUuid, "projectUuid must not be null");
        return "%s:%s".formatted(NAME, projectUuid);
    }
}
