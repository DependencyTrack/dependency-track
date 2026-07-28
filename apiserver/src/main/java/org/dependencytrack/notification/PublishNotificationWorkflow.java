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
package org.dependencytrack.notification;

import org.dependencytrack.dex.activity.DeleteFilesActivity;
import org.dependencytrack.dex.api.ActivityCallOptions;
import org.dependencytrack.dex.api.Awaitable;
import org.dependencytrack.dex.api.RetryPolicy;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.failure.ActivityFailureException;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.proto.internal.workflow.v1.DeleteFilesArgument;
import org.dependencytrack.proto.internal.workflow.v1.PublishNotificationActivityArg;
import org.dependencytrack.proto.internal.workflow.v1.PublishNotificationWorkflowArg;
import org.jspecify.annotations.Nullable;
import org.slf4j.MDC;

import java.time.Duration;
import java.util.LinkedHashMap;

import static org.dependencytrack.common.MdcKeys.MDC_NOTIFICATION_ID;

/**
 * @since 5.0.0
 */
@WorkflowSpec(name = "publish-notification")
public final class PublishNotificationWorkflow implements Workflow<PublishNotificationWorkflowArg, Void> {

    @Override
    public @Nullable Void execute(
            WorkflowContext<PublishNotificationWorkflowArg> ctx,
            @Nullable PublishNotificationWorkflowArg arg) {
        if (arg == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }
        if (!arg.hasNotification() && !arg.hasNotificationFileMetadata()) {
            throw new TerminalApplicationFailureException(
                    "Neither notification nor notification file metadata provided");
        }

        try (var _ = MDC.putCloseable(MDC_NOTIFICATION_ID, arg.getNotificationId())) {
            final var awaitableByRuleName =
                    new LinkedHashMap<String, Awaitable<?>>(arg.getNotificationRuleNamesCount());

            // Schedule publishing activities for all applicable notification rules concurrently.
            for (final String ruleName : arg.getNotificationRuleNamesList()) {
                final PublishNotificationActivityArg activityArg = createActivityArg(arg, ruleName);

                ctx.logger().debug("Scheduling publish for rule '{}'", ruleName);
                final Awaitable<?> awaitable = ctx
                        .activity(PublishNotificationActivity.class)
                        .call(new ActivityCallOptions<PublishNotificationActivityArg>()
                                .withArgument(activityArg));

                awaitableByRuleName.put(ruleName, awaitable);
            }

            // Wait for all scheduled activities to complete.
            int activitiesFailed = 0;
            for (final var entry : awaitableByRuleName.entrySet()) {
                final String ruleName = entry.getKey();
                final Awaitable<?> awaitable = entry.getValue();

                ctx.logger().debug("Waiting for notification publishing to complete for rule '{}'", ruleName);
                try {
                    awaitable.await();
                    ctx.logger().debug("Successfully published notification for rule '{}'", ruleName);
                } catch (ActivityFailureException e) {
                    ctx.logger().warn("Failed to publish notification for rule '{}'", ruleName, e.getCause());
                    activitiesFailed++;
                }
            }

            maybeDeleteNotificationFile(ctx, arg);

            // Fail the workflow run only when *all* publishing activities failed.
            if (activitiesFailed > 0 && activitiesFailed == awaitableByRuleName.size()) {
                throw new TerminalApplicationFailureException(
                        "Publishing failed for all applicable rules");
            }
        }

        return null;
    }

    private PublishNotificationActivityArg createActivityArg(
            PublishNotificationWorkflowArg arg,
            String ruleName) {
        final var activityArgBuilder = PublishNotificationActivityArg.newBuilder()
                .setNotificationId(arg.getNotificationId())
                .setNotificationRuleName(ruleName)
                .setRuleTest(arg.getRuleTest());

        if (arg.hasNotification()) {
            activityArgBuilder.setNotification(arg.getNotification());
        } else {
            activityArgBuilder.setNotificationFileMetadata(arg.getNotificationFileMetadata());
        }

        return activityArgBuilder.build();
    }

    private void maybeDeleteNotificationFile(
            WorkflowContext<?> ctx,
            PublishNotificationWorkflowArg argument) {
        if (!argument.hasNotificationFileMetadata()) {
            return;
        }

        ctx.logger().debug("Scheduling notification file for deletion");

        try {
            ctx.activity(DeleteFilesActivity.class).call(
                    new ActivityCallOptions<DeleteFilesArgument>()
                            .withRetryPolicy(RetryPolicy.ofDefault()
                                    .withInitialDelay(Duration.ofSeconds(1))
                                    .withMaxDelay(Duration.ofSeconds(10))
                                    .withMaxAttempts(3))
                            .withArgument(DeleteFilesArgument.newBuilder()
                                    .addFileMetadata(argument.getNotificationFileMetadata())
                                    .build())).await();
        } catch (ActivityFailureException e) {
            ctx.logger().warn("Failed to delete notification file", e.getCause());
        }
    }

}
