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
package org.dependencytrack.analysis;

import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowCallOptions;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.metrics.UpdateProjectMetricsActivity;
import org.dependencytrack.policy.EvalProjectPoliciesActivity;
import org.dependencytrack.proto.internal.workflow.v1.AnalyzeProjectWorkflowArg;
import org.dependencytrack.proto.internal.workflow.v1.EvalProjectPoliciesArg;
import org.dependencytrack.proto.internal.workflow.v1.UpdateProjectMetricsArg;
import org.dependencytrack.proto.internal.workflow.v1.VulnAnalysisWorkflowArg;
import org.dependencytrack.vulnanalysis.VulnAnalysisWorkflow;
import org.jspecify.annotations.Nullable;
import org.slf4j.MDC;

import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;

/**
 * @since 5.0.0
 */
@WorkflowSpec(name = "analyze-project")
public final class AnalyzeProjectWorkflow implements Workflow<AnalyzeProjectWorkflowArg, Void> {

    @Override
    public @Nullable Void execute(
            WorkflowContext<AnalyzeProjectWorkflowArg> ctx,
            @Nullable AnalyzeProjectWorkflowArg arg) throws Exception {
        if (arg == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        try (var _ = MDC.putCloseable(MDC_PROJECT_UUID, arg.getProjectUuid())) {
            ctx.logger().info("Starting project analysis");

            final var vulnAnalysisArgBuilder = VulnAnalysisWorkflowArg.newBuilder()
                    .setProjectUuid(arg.getProjectUuid())
                    .setTrigger(arg.getTrigger());
            if (arg.hasContextFileMetadata()) {
                vulnAnalysisArgBuilder.setContextFileMetadata(arg.getContextFileMetadata());
            }
            ctx.workflow(VulnAnalysisWorkflow.class)
                    .call(new WorkflowCallOptions<VulnAnalysisWorkflowArg>()
                            .withConcurrencyKey("vuln-analysis:" + arg.getProjectUuid())
                            .withArgument(vulnAnalysisArgBuilder.build()))
                    .await();

            ctx.activity(EvalProjectPoliciesActivity.class)
                    .call(EvalProjectPoliciesArg.newBuilder()
                            .setProjectUuid(arg.getProjectUuid())
                            .build())
                    .await();

            ctx.activity(UpdateProjectMetricsActivity.class)
                    .call(UpdateProjectMetricsArg.newBuilder()
                            .setProjectUuid(arg.getProjectUuid())
                            .build())
                    .await();

            ctx.logger().info("Project analysis completed");
            return null;
        }
    }

}
