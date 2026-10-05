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
package org.dependencytrack.pkghealth;

import org.dependencytrack.analysis.AnalyzeProjectWorkflow;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.policy.EvalProjectPoliciesWorkflow;
import org.dependencytrack.policy.cel.persistence.CelPolicyDao;
import org.dependencytrack.proto.internal.workflow.v1.EvalProjectPoliciesArg;
import org.dependencytrack.proto.internal.workflow.v1.ScheduleHealthPolicyEvaluationsArg;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * Starts policy evaluation for projects whose components use packages whose policy-visible health changed.
 *
 * @since 5.2.0
 */
@ActivitySpec(name = "schedule-health-policy-evaluations", defaultTaskQueue = "package-health-metadata-resolutions")
public final class ScheduleHealthPolicyEvaluationsActivity
        implements Activity<ScheduleHealthPolicyEvaluationsArg, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ScheduleHealthPolicyEvaluationsActivity.class);

    private final DexEngine dexEngine;

    public ScheduleHealthPolicyEvaluationsActivity(final DexEngine dexEngine) {
        this.dexEngine = requireNonNull(dexEngine, "dexEngine must not be null");
    }

    @Override
    public @Nullable Void execute(final ActivityContext ctx, final @Nullable ScheduleHealthPolicyEvaluationsArg arg) {
        if (arg == null || arg.getPurlsList().isEmpty()) {
            return null;
        }

        final List<UUID> projectUuids = withJdbiHandle(
                handle -> new CelPolicyDao(handle).findProjectUuidsForPackageHealthPolicies(arg.getPurlsList()));
        if (projectUuids.isEmpty()) {
            return null;
        }

        final var requests = new ArrayList<CreateWorkflowRunRequest<?>>(projectUuids.size());
        for (final UUID projectUuid : projectUuids) {
            requests.add(new CreateWorkflowRunRequest<>(EvalProjectPoliciesWorkflow.class)
                    .withConcurrencyKey(AnalyzeProjectWorkflow.concurrencyKeyForProject(projectUuid))
                    .withArgument(EvalProjectPoliciesArg.newBuilder()
                            .setProjectUuid(projectUuid.toString())
                            .build()));
        }

        dexEngine.createRuns(requests);
        LOGGER.info(
                "Scheduled policy evaluation for {} projects from workflow run {}",
                requests.size(),
                ctx.workflowRunId());
        return null;
    }
}
