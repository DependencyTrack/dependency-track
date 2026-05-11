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
package org.dependencytrack.pkgmetadata;

import org.dependencytrack.dex.api.ActivityCallOptions;
import org.dependencytrack.dex.api.Awaitable;
import org.dependencytrack.dex.api.ContinueAsNewOptions;
import org.dependencytrack.dex.api.RetryPolicy;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.failure.ActivityFailureException;
import org.dependencytrack.proto.internal.workflow.v1.FetchPackageMetadataResolutionCandidatesRes;
import org.dependencytrack.proto.internal.workflow.v1.PackageMetadataResolutionCandidateGroup;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageMetadataActivityArg;
import org.jspecify.annotations.Nullable;
import org.slf4j.MDC;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;

import static org.dependencytrack.common.MdcKeys.MDC_PKG_METADATA_RESOLVER_NAME;

/**
 * @since 5.0.0
 */
@WorkflowSpec(name = "resolve-package-metadata")
public final class ResolvePackageMetadataWorkflow implements Workflow<Void, Void> {

    // This workflow is intended to be a singleton.
    // Always use this instance ID when creating runs for it.
    public static final String INSTANCE_ID = "resolve-package-metadata";

    private static final RetryPolicy RESOLVE_RETRY_POLICY =
            new RetryPolicy(
                    /* initialDelay */ Duration.ofSeconds(5),
                    /* delayMultiplier */ 2.0,
                    /* randomizationFactor */ 0.3,
                    /* maxDelay */ Duration.ofMinutes(1),
                    /* maxAttempts */ 3);

    @Override
    public @Nullable Void execute(WorkflowContext<Void> ctx, @Nullable Void arg) throws Exception {
        ctx.logger().debug("Scheduling fetch of resolution candidates");
        final FetchPackageMetadataResolutionCandidatesRes fetchResult = ctx
                .activity(FetchPackageMetadataResolutionCandidatesActivity.class)
                .call()
                .await();

        final List<PackageMetadataResolutionCandidateGroup> candidateGroups = fetchResult != null
                ? fetchResult.getCandidateGroupsList()
                : List.of();
        if (candidateGroups.isEmpty()) {
            ctx.logger().info("No more packages due for metadata resolution");
            return null;
        }

        final int totalPurls = candidateGroups.stream()
                .mapToInt(PackageMetadataResolutionCandidateGroup::getPurlsCount)
                .sum();
        ctx.logger().debug(
                "Resolving metadata for {} packages with resolvers {}",
                totalPurls,
                candidateGroups.stream()
                        .map(PackageMetadataResolutionCandidateGroup::getResolverName)
                        .sorted()
                        .toList());

        final var awaitableByResolverName = new LinkedHashMap<String, Awaitable<Void>>();
        for (final PackageMetadataResolutionCandidateGroup group : candidateGroups) {
            final String resolverName = group.getResolverName();
            ctx.logger().debug(
                    "Scheduling metadata resolution for {} PURLs with resolver '{}'",
                    group.getPurlsCount(), resolverName);

            final Awaitable<Void> awaitable = ctx
                    .activity(ResolvePackageMetadataActivity.class)
                    .call(new ActivityCallOptions<ResolvePackageMetadataActivityArg>()
                            .withRetryPolicy(RESOLVE_RETRY_POLICY)
                            .withArgument(ResolvePackageMetadataActivityArg.newBuilder()
                                    .addAllPurls(group.getPurlsList())
                                    .setResolverName(resolverName)
                                    .build()));
            awaitableByResolverName.put(resolverName, awaitable);
        }

        for (final var entry : awaitableByResolverName.entrySet()) {
            final String resolverName = entry.getKey();
            final Awaitable<Void> awaitable = entry.getValue();

            MDC.put(MDC_PKG_METADATA_RESOLVER_NAME, resolverName);
            try {
                awaitable.await();
                ctx.logger().debug("Metadata resolution completed");
            } catch (ActivityFailureException e) {
                ctx.logger().warn("Metadata resolution failed", e);
            } finally {
                MDC.remove(MDC_PKG_METADATA_RESOLVER_NAME);
            }
        }

        ctx.continueAsNew(new ContinueAsNewOptions<>());

        return null;
    }

}
