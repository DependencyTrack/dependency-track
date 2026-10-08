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

import com.google.protobuf.util.Timestamps;
import org.dependencytrack.dex.api.ActivityCallOptions;
import org.dependencytrack.dex.api.ContinueAsNewOptions;
import org.dependencytrack.dex.api.RetryPolicy;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.failure.ActivityFailureException;
import org.dependencytrack.proto.internal.workflow.v1.FetchPackageHealthMetadataCandidatesArg;
import org.dependencytrack.proto.internal.workflow.v1.FetchPackageHealthMetadataCandidatesRes;
import org.dependencytrack.proto.internal.workflow.v1.PackageHealthGitHubFetch;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataActivityArg;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataActivityRes;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataWorkflowArg;
import org.dependencytrack.proto.internal.workflow.v1.ScheduleHealthPolicyEvaluationsArg;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

@WorkflowSpec(name = "resolve-package-health-metadata")
public final class ResolvePackageHealthMetadataWorkflow
        implements Workflow<ResolvePackageHealthMetadataWorkflowArg, Void> {

    public static final String INSTANCE_ID = "resolve-package-health-metadata";

    private static final RetryPolicy RESOLVE_RETRY_POLICY = new RetryPolicy(
            /* initialDelay */ Duration.ofSeconds(5),
            /* delayMultiplier */ 2.0,
            /* randomizationFactor */ 0.3,
            /* maxDelay */ Duration.ofHours(2),
            /* maxAttempts */ 3);

    private static final Duration RATE_LIMIT_RESET_MARGIN = Duration.ofSeconds(2);

    /**
     * Lower bound for a rate limit wait, so that a reset time in the past, for example
     * because of clock skew, does not call the external APIs in a tight loop.
     */
    private static final Duration MIN_RATE_LIMIT_WAIT = Duration.ofSeconds(10);

    private static final int MAX_RATE_LIMIT_WAITS_WITHOUT_PROGRESS = 3;

    @Override
    public @Nullable Void execute(
            final WorkflowContext<@Nullable ResolvePackageHealthMetadataWorkflowArg> ctx,
            final @Nullable ResolvePackageHealthMetadataWorkflowArg arg)
            throws Exception {
        ctx.logger().debug("Scheduling fetch of package health metadata candidates");

        final FetchPackageHealthMetadataCandidatesRes fetchResult = ctx.activity(
                        FetchPackageHealthMetadataCandidatesActivity.class)
                .call(new ActivityCallOptions<FetchPackageHealthMetadataCandidatesArg>()
                        .withArgument(FetchPackageHealthMetadataCandidatesArg.newBuilder()
                                .setCursor(arg != null ? arg.getCursor() : "")
                                .build()))
                .await();

        if (fetchResult == null) {
            ctx.logger().info("No packages due for health metadata resolution");
            return null;
        }

        List<String> pendingPurls = fetchResult.getPurlsList();
        List<PackageHealthGitHubFetch> pendingGitHubFetches = List.of();
        int rateLimitWaitsWithoutProgress = 0;
        while (!pendingPurls.isEmpty() || !pendingGitHubFetches.isEmpty()) {
            ctx.logger()
                    .debug(
                            "Resolving health metadata for {} packages and GitHub data for {} packages",
                            pendingPurls.size(),
                            pendingGitHubFetches.size());

            final ResolvePackageHealthMetadataActivityRes resolveResult;
            try {
                resolveResult = ctx.activity(ResolvePackageHealthMetadataActivity.class)
                        .call(new ActivityCallOptions<ResolvePackageHealthMetadataActivityArg>()
                                .withRetryPolicy(RESOLVE_RETRY_POLICY)
                                .withArgument(ResolvePackageHealthMetadataActivityArg.newBuilder()
                                        .addAllPurls(pendingPurls)
                                        .addAllGithubFetches(pendingGitHubFetches)
                                        .build()))
                        .await();
            } catch (ActivityFailureException e) {
                ctx.logger().warn("Package health metadata resolution failed", e);
                break;
            }

            if (resolveResult == null) {
                break;
            }

            if (resolveResult.getChangedPurlsCount() > 0) {
                ctx.activity(ScheduleHealthPolicyEvaluationsActivity.class)
                        .call(ScheduleHealthPolicyEvaluationsArg.newBuilder()
                                .addAllPurls(resolveResult.getChangedPurlsList())
                                .build())
                        .await();
            }

            final int remaining =
                    resolveResult.getUnresolvedPurlsCount() + resolveResult.getPendingGithubFetchesCount();
            if (remaining == 0) {
                break;
            }

            if (remaining < pendingPurls.size() + pendingGitHubFetches.size()) {
                rateLimitWaitsWithoutProgress = 0;
            } else if (rateLimitWaitsWithoutProgress == MAX_RATE_LIMIT_WAITS_WITHOUT_PROGRESS) {
                ctx.logger()
                        .warn(
                                "External API rate limit still reached after {} waits; Skipping {} packages until the next run",
                                rateLimitWaitsWithoutProgress,
                                remaining);
                break;
            }
            rateLimitWaitsWithoutProgress++;

            // Wait in the workflow, not through activity retries, so that waiting
            // for a rate limit does not use up the attempts meant for real failures.
            final Instant resumeAt = Instant.ofEpochMilli(Timestamps.toMillis(resolveResult.getRateLimitResetAt()))
                    .plus(RATE_LIMIT_RESET_MARGIN);
            final Duration wait = Duration.between(ctx.currentTime(), resumeAt);
            ctx.logger().info("External API rate limit reached; Resuming {} packages at {}", remaining, resumeAt);
            ctx.createTimer("rate-limit-reset", wait.compareTo(MIN_RATE_LIMIT_WAIT) > 0 ? wait : MIN_RATE_LIMIT_WAIT)
                    .await();

            pendingPurls = resolveResult.getUnresolvedPurlsList();
            pendingGitHubFetches = resolveResult.getPendingGithubFetchesList();
        }

        if (fetchResult.getHasMore()) {
            ctx.continueAsNew(new ContinueAsNewOptions<ResolvePackageHealthMetadataWorkflowArg>()
                    .withArgument(ResolvePackageHealthMetadataWorkflowArg.newBuilder()
                            .setCursor(fetchResult.getNextCursor())
                            .build()));
        } else {
            ctx.logger().info("No more packages due for health metadata resolution");
        }

        return null;
    }
}
