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

import org.dependencytrack.dex.api.ActivityCallOptions;
import org.dependencytrack.dex.api.Awaitable;
import org.dependencytrack.dex.api.ContinueAsNewOptions;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.failure.ActivityFailureException;
import org.dependencytrack.proto.internal.workflow.v1.FetchProjectMetricsUpdateCandidatesRes;
import org.dependencytrack.proto.internal.workflow.v1.UpdateProjectMetricsArg;
import org.jspecify.annotations.Nullable;
import org.slf4j.MDC;

import java.util.LinkedHashMap;
import java.util.List;

import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;

/**
 * @since 5.0.0
 */
@WorkflowSpec(name = "update-portfolio-metrics")
public final class UpdatePortfolioMetricsWorkflow implements Workflow<Void, Void> {

    public static final String INSTANCE_ID = "update-portfolio-metrics";

    @Override
    public @Nullable Void execute(WorkflowContext<Void> ctx, @Nullable Void arg) throws Exception {
        final FetchProjectMetricsUpdateCandidatesRes fetchResult = ctx
                .activity(FetchProjectMetricsUpdateCandidatesActivity.class)
                .call()
                .await();

        final List<String> projectUuids = fetchResult != null
                ? fetchResult.getProjectUuidsList()
                : List.of();

        if (projectUuids.isEmpty()) {
            ctx.logger().info("No more projects due for metrics update; Refreshing portfolio metrics");
            ctx.activity(RefreshGlobalPortfolioMetricsActivity.class)
                    .call()
                    .await();
            return null;
        }

        ctx.logger().debug("Scheduling metrics update for {} projects", projectUuids.size());

        final var awaitableByProjectUuid = new LinkedHashMap<String, Awaitable<Void>>();
        for (final String projectUuid : projectUuids) {
            awaitableByProjectUuid.put(projectUuid, ctx
                    .activity(UpdateProjectMetricsActivity.class)
                    .call(new ActivityCallOptions<UpdateProjectMetricsArg>()
                            .withArgument(UpdateProjectMetricsArg.newBuilder()
                                    .setProjectUuid(projectUuid)
                                    .build())));
        }

        for (final var entry : awaitableByProjectUuid.entrySet()) {
            final String projectUuid = entry.getKey();
            final Awaitable<Void> awaitable = entry.getValue();

            MDC.put(MDC_PROJECT_UUID, projectUuid);
            try {
                awaitable.await();
            } catch (ActivityFailureException e) {
                ctx.logger().warn("Project metrics update failed", e);
            } finally {
                MDC.remove(MDC_PROJECT_UUID);
            }
        }

        ctx.continueAsNew(new ContinueAsNewOptions<>());
        return null;
    }

}
