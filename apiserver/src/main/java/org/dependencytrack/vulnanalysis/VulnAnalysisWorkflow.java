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
package org.dependencytrack.vulnanalysis;

import org.dependencytrack.dex.activity.DeleteFilesActivity;
import org.dependencytrack.dex.api.ActivityCallOptions;
import org.dependencytrack.dex.api.Awaitable;
import org.dependencytrack.dex.api.RetryPolicy;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.failure.ActivityFailureException;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.proto.internal.workflow.v1.AnalysisTrigger;
import org.dependencytrack.proto.internal.workflow.v1.DeleteFilesArgument;
import org.dependencytrack.proto.internal.workflow.v1.InvokeVulnAnalyzerArg;
import org.dependencytrack.proto.internal.workflow.v1.InvokeVulnAnalyzerRes;
import org.dependencytrack.proto.internal.workflow.v1.PrepareVulnAnalysisArg;
import org.dependencytrack.proto.internal.workflow.v1.PrepareVulnAnalysisRes;
import org.dependencytrack.proto.internal.workflow.v1.ReconcileVulnAnalysisResultsArg;
import org.dependencytrack.proto.internal.workflow.v1.ReconcileVulnAnalysisResultsArg.AnalyzerResult;
import org.dependencytrack.proto.internal.workflow.v1.VulnAnalysisWorkflowArg;
import org.jspecify.annotations.Nullable;
import org.slf4j.MDC;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_VULN_ANALYZER_NAME;

/**
 * @since 5.0.0
 */
@WorkflowSpec(name = "vuln-analysis")
public final class VulnAnalysisWorkflow implements Workflow<VulnAnalysisWorkflowArg, Void> {

    private static final RetryPolicy ANALYZER_RETRY_POLICY =
            new RetryPolicy(
                    /* initialDelay */ Duration.ofSeconds(5),
                    /* delayMultiplier */ 2.0,
                    /* randomizationFactor */ 0.3,
                    /* maxDelay */ Duration.ofMinutes(1),
                    /* maxAttempts */ 5);

    @Override
    public @Nullable Void execute(
            WorkflowContext<VulnAnalysisWorkflowArg> ctx,
            @Nullable VulnAnalysisWorkflowArg arg) throws Exception {
        if (arg == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        try (var _ = MDC.putCloseable(MDC_PROJECT_UUID, arg.getProjectUuid())) {
            ctx.logger().info("Starting vulnerability analysis");

            final PrepareVulnAnalysisRes preparationResult = prepare(ctx, arg.getProjectUuid());
            if (preparationResult.getAnalyzersCount() == 0) {
                ctx.logger().info("No applicable analyzers; Skipping analysis");
                return null;
            }
            if (!preparationResult.hasBomFileMetadata()) {
                ctx.logger().info("No analyzable components; Skipping analysis");
                return null;
            }

            final FileMetadata contextFileMetadata =
                    arg.hasContextFileMetadata()
                            ? arg.getContextFileMetadata()
                            : null;

            var analyzerResults = List.<AnalyzerResult>of();
            try {
                final Map<String, Awaitable<InvokeVulnAnalyzerRes>> awaitableByAnalyzerName =
                        invokeAnalyzers(
                                ctx,
                                arg.getProjectUuid(),
                                preparationResult.getAnalyzersList(),
                                preparationResult.getBomFileMetadata());

                analyzerResults = awaitAnalyzerResults(ctx, awaitableByAnalyzerName);
                if (analyzerResults.stream().noneMatch(AnalyzerResult::getSuccessful)) {
                    throw new TerminalApplicationFailureException("All analyzers failed");
                }

                reconcileResults(ctx, arg.getProjectUuid(), arg.getTrigger(), analyzerResults, contextFileMetadata);
            } catch (Exception e) {
                deleteFiles(ctx, preparationResult.getBomFileMetadata(), analyzerResults, contextFileMetadata);
                throw e;
            }

            deleteFiles(ctx, preparationResult.getBomFileMetadata(), analyzerResults, contextFileMetadata);

            ctx.logger().info("Vulnerability analysis completed");
            return null;
        }
    }

    private PrepareVulnAnalysisRes prepare(WorkflowContext<?> ctx, String projectUuid) {
        final PrepareVulnAnalysisRes result = ctx
                .activity(PrepareVulnAnalysisActivity.class)
                .call(PrepareVulnAnalysisArg.newBuilder()
                        .setProjectUuid(projectUuid)
                        .build())
                .await();
        if (result == null) {
            throw new TerminalApplicationFailureException("Preparation did not return a result");
        }

        return result;
    }

    private Map<String, Awaitable<InvokeVulnAnalyzerRes>> invokeAnalyzers(
            WorkflowContext<?> ctx,
            String projectUuid,
            List<String> analyzerNames,
            FileMetadata bomFileMetadata) {
        final var awaitableByAnalyzerName = new LinkedHashMap<String, Awaitable<InvokeVulnAnalyzerRes>>();

        for (final String analyzerName : analyzerNames) {
            try (var _ = MDC.putCloseable(MDC_VULN_ANALYZER_NAME, analyzerName)) {
                ctx.logger().debug("Invoking analyzer");
                final Awaitable<InvokeVulnAnalyzerRes> awaitable =
                        invokeAnalyzer(ctx, projectUuid, analyzerName, bomFileMetadata);

                awaitableByAnalyzerName.put(analyzerName, awaitable);
            }
        }

        return awaitableByAnalyzerName;
    }

    private Awaitable<@Nullable InvokeVulnAnalyzerRes> invokeAnalyzer(
            WorkflowContext<?> ctx,
            String projectUuid,
            String analyzerName,
            FileMetadata bomFileMetadata) {
        final var arg = InvokeVulnAnalyzerArg.newBuilder()
                .setProjectUuid(projectUuid)
                .setAnalyzerName(analyzerName)
                .setBomFileMetadata(bomFileMetadata)
                .build();

        return ctx.activity(InvokeVulnAnalyzerActivity.class).call(
                new ActivityCallOptions<InvokeVulnAnalyzerArg>()
                        .withRetryPolicy(ANALYZER_RETRY_POLICY)
                        .withArgument(arg));
    }

    private List<AnalyzerResult> awaitAnalyzerResults(
            WorkflowContext<?> ctx,
            Map<String, Awaitable<InvokeVulnAnalyzerRes>> awaitableByAnalyzerName) {
        final var results = new ArrayList<AnalyzerResult>(awaitableByAnalyzerName.size());

        for (final var entry : awaitableByAnalyzerName.entrySet()) {
            final String analyzerName = entry.getKey();
            final Awaitable<InvokeVulnAnalyzerRes> awaitable = entry.getValue();

            try (var _ = MDC.putCloseable(MDC_VULN_ANALYZER_NAME, analyzerName)) {
                ctx.logger().debug("Waiting for analyzer to complete");

                final var result = awaitable.await();
                if (result == null) {
                    ctx.logger().warn("Analyzer completed but did not return a result; Assuming it to have failed");
                    results.add(AnalyzerResult.newBuilder()
                            .setAnalyzerName(analyzerName)
                            .setSuccessful(false)
                            .build());
                    continue;
                }

                ctx.logger().debug("Analyzer completed");
                final var analyzerResultBuilder = AnalyzerResult.newBuilder()
                        .setAnalyzerName(analyzerName)
                        .setSuccessful(true);
                if (result.hasVdrFileMetadata()) {
                    // Analyzer may not have created a VDR file if it didn't
                    // identify any vulnerabilities.
                    analyzerResultBuilder.setVdrFileMetadata(result.getVdrFileMetadata());
                }
                results.add(analyzerResultBuilder.build());
            } catch (ActivityFailureException e) {
                ctx.logger().warn("Analyzer failed", e);
                results.add(AnalyzerResult.newBuilder()
                        .setAnalyzerName(analyzerName)
                        .setSuccessful(false)
                        .build());
            }
        }

        return results;
    }

    private void reconcileResults(
            WorkflowContext<?> ctx,
            String projectUuid,
            AnalysisTrigger analysisTrigger,
            List<AnalyzerResult> results,
            @Nullable FileMetadata contextFileMetadata) {
        final var argBuilder = ReconcileVulnAnalysisResultsArg.newBuilder()
                .setProjectUuid(projectUuid)
                .setAnalysisTrigger(analysisTrigger)
                .addAllAnalyzerResults(results);
        if (contextFileMetadata != null) {
            argBuilder.setContextFileMetadata(contextFileMetadata);
        }
        ctx.activity(ReconcileVulnAnalysisResultsActivity.class)
                .call(argBuilder.build())
                .await();
    }

    private void deleteFiles(
            WorkflowContext<?> ctx,
            FileMetadata bomFileMetadata,
            List<AnalyzerResult> analyzerResults,
            @Nullable FileMetadata contextFileMetadata) {
        final var filesToDelete = new ArrayList<FileMetadata>();
        filesToDelete.add(bomFileMetadata);
        analyzerResults.stream()
                .filter(AnalyzerResult::hasVdrFileMetadata)
                .map(AnalyzerResult::getVdrFileMetadata)
                .forEach(filesToDelete::add);
        if (contextFileMetadata != null) {
            filesToDelete.add(contextFileMetadata);
        }

        ctx.activity(DeleteFilesActivity.class)
                .call(DeleteFilesArgument.newBuilder()
                        .addAllFileMetadata(filesToDelete)
                        .build())
                .await();
    }

}
