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

import org.dependencytrack.dex.api.ActivityCallOptions;
import org.dependencytrack.dex.api.Awaitable;
import org.dependencytrack.dex.api.RetryPolicy;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.failure.ActivityFailureException;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.proto.internal.workflow.v1.ProcessScheduledNotificationRuleArg;
import org.dependencytrack.proto.internal.workflow.v1.ProcessScheduledNotificationsWorkflowArg;
import org.jspecify.annotations.Nullable;
import org.slf4j.MDC;

import java.time.Duration;
import java.util.LinkedHashMap;

import static org.dependencytrack.common.MdcKeys.MDC_NOTIFICATION_RULE_NAME;

/**
 * @since 5.0.0
 */
@WorkflowSpec(name = "process-scheduled-notifications")
public final class ProcessScheduledNotificationsWorkflow
        implements Workflow<ProcessScheduledNotificationsWorkflowArg, Void> {

    public static final String INSTANCE_ID = "process-scheduled-notifications";

    private static final RetryPolicy PROCESS_RULE_RETRY_POLICY =
            new RetryPolicy(
                    Duration.ofSeconds(5),
                    2.0,
                    0.3,
                    Duration.ofMinutes(1),
                    3);

    @Override
    public @Nullable Void execute(
            WorkflowContext<ProcessScheduledNotificationsWorkflowArg> ctx,
            @Nullable ProcessScheduledNotificationsWorkflowArg arg) throws Exception {
        if (arg == null || arg.getRuleNamesCount() == 0) {
            throw new TerminalApplicationFailureException("No rule names provided");
        }

        ctx.logger().info("Processing {} due scheduled notification rules", arg.getRuleNamesCount());

        final var awaitableByRuleName =
                new LinkedHashMap<String, Awaitable<@Nullable Void>>(arg.getRuleNamesCount());
        for (final String ruleName : arg.getRuleNamesList()) {
            final Awaitable<@Nullable Void> awaitable = ctx
                    .activity(ProcessScheduledNotificationRuleActivity.class)
                    .call(new ActivityCallOptions<ProcessScheduledNotificationRuleArg>()
                            .withRetryPolicy(PROCESS_RULE_RETRY_POLICY)
                            .withArgument(ProcessScheduledNotificationRuleArg.newBuilder()
                                    .setRuleName(ruleName)
                                    .build()));
            awaitableByRuleName.put(ruleName, awaitable);
        }

        int failureCount = 0;
        for (final var entry : awaitableByRuleName.entrySet()) {
            final String ruleName = entry.getKey();
            final Awaitable<?> awaitable = entry.getValue();

            MDC.put(MDC_NOTIFICATION_RULE_NAME, ruleName);
            try {
                awaitable.await();
                ctx.logger().debug("Successfully processed rule");
            } catch (ActivityFailureException e) {
                failureCount++;
                ctx.logger().warn("Failed to process rule", e.getCause());
            } finally {
                MDC.remove(MDC_NOTIFICATION_RULE_NAME);
            }
        }

        if (failureCount > 0 && failureCount == awaitableByRuleName.size()) {
            throw new TerminalApplicationFailureException(
                    "All %d scheduled notification rules failed".formatted(failureCount));
        }

        return null;
    }
}
