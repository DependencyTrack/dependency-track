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
package org.dependencytrack.dex.api;

import org.dependencytrack.dex.api.failure.CancellationFailureException;
import org.dependencytrack.dex.api.failure.SideEffectFailureException;
import org.dependencytrack.dex.api.payload.PayloadConverter;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Supplier;

import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;

/**
 * Context available to {@link Workflow}s.
 *
 * @param <A> Type of the workflow's argument.
 */
public interface WorkflowContext<A extends @Nullable Object> {

    UUID runId();

    String workflowName();

    int workflowVersion();

    Map<String, String> labels();

    /**
     * @return The current, deterministic time within the workflow execution.
     */
    Instant currentTime();

    /**
     * @return Whether the workflow is currently replaying past events.
     */
    boolean isReplaying();

    /**
     * @return A {@link Logger} to be used for logging within the workflow execution.
     * The {@link Logger} omits log events if the workflow is currently replaying past events,
     * avoiding redundant log emission.
     * @see #isReplaying()
     */
    Logger logger();

    /**
     * Get a handle on an activity that can be used for invocations.
     *
     * @param activityClass Class of the activity.
     * @param <AA>          Type of the activity's argument.
     * @param <AR>          Type of the activity's result.
     * @return An {@link ActivityHandle}.
     * @throws java.util.NoSuchElementException When the activity is not known to the engine.
     */
    <AA, AR> ActivityHandle<AA, AR> activity(Class<? extends Activity<AA, AR>> activityClass);

    /**
     * Get a handle on a workflow that can be used for invocations.
     *
     * @param workflowClass Class of the workflow.
     * @param <WA>          Type of the workflow's argument.
     * @param <WR>          Type of the workflow's result.
     * @return A {@link WorkflowHandle}.
     */
    <WA, WR> WorkflowHandle<WA, WR> workflow(Class<? extends Workflow<WA, WR>> workflowClass);

    /**
     * Create a durable timer.
     *
     * @param name  Name of the timer. Purely descriptive to make it recognizable in the history.
     * @param delay {@link Duration} for how far in the future the timer shall elapse.
     * @return An {@link Awaitable} for when the timer elapses.
     */
    Awaitable<Void> createTimer(String name, Duration delay);

    /**
     * Set a custom status for the workflow run.
     * <p>
     * Does not overwrite the runtime status of the workflow run.
     * <p>
     * May be useful for workflows that are observed by end users, requiring more descriptive
     * and more granular statuses.
     *
     * @param status The status to set. May be {@code null} to reset the custom status.
     */
    void setStatus(@Nullable String status);

    /**
     * Execute a side effect and record its result in the event history.
     * <p>
     * Calling {@link Awaitable#await()} on the {@link Awaitable} returned by this method
     * will throw an {@link SideEffectFailureException} if the side effect failed.
     *
     * @param name               Name of the side effect. Purely descriptive to make it recognizable in the history.
     * @param argument           Argument to pass to {@code function}.
     * @param resultConverter    {@link PayloadConverter} to use for the side effect's result.
     * @param function The side effect to execute.
     * @param <SA>               Type of the side effect's argument.
     * @param <SR>               Type of the side effect's result.
     * @return An {@link Awaitable} wrapping the side effect's result, if any.
     */
    <SA, SR> Awaitable<SR> executeSideEffect(
            String name,
            @Nullable SA argument,
            PayloadConverter<SR> resultConverter,
            Function<SA, SR> function);

    default <SR> Awaitable<SR> executeSideEffect(
            String name,
            PayloadConverter<SR> resultConverter,
            Supplier<SR> supplier) {
        return executeSideEffect(name, null, resultConverter, _ -> supplier.get());
    }

    default Awaitable<Void> executeSideEffect(String name, Runnable runnable) {
        return executeSideEffect(name, null, voidConverter(), _ -> {
            runnable.run();
            return null;
        });
    }

    /**
     * Wait for an external event.
     * <p>
     * Calling {@link Awaitable#await()} on the {@link Awaitable} returned by this method
     * will throw a {@link CancellationFailureException} if the event is not received before
     * {@code timeout} elapses.
     *
     * @param externalEventId ID of the external event.
     * @param resultConverter {@link PayloadConverter} for the external event's content.
     * @param timeout         {@link Duration} to wait at most for the external event to arrive.
     * @param <ER>            Type of the external event's content.
     * @return An {@link Awaitable} wrapping the external event's content, if any.
     */
    <ER> Awaitable<ER> waitForExternalEvent(
            String externalEventId,
            PayloadConverter<ER> resultConverter,
            Duration timeout);

    /**
     * Restart this workflow with a truncated history.
     * <p>
     * May be used to prevent the history from growing too large.
     *
     * @param options Options for the restarted workflow.
     */
    void continueAsNew(ContinueAsNewOptions<A> options);

}
