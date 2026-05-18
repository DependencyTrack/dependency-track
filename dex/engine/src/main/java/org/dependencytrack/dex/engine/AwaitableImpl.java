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
package org.dependencytrack.dex.engine;

import org.dependencytrack.dex.api.Awaitable;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowRunBlockedError;
import org.dependencytrack.dex.api.failure.CancellationFailureException;
import org.dependencytrack.dex.api.failure.FailureException;
import org.dependencytrack.dex.api.payload.PayloadConverter;
import org.dependencytrack.dex.proto.payload.v1.Payload;
import org.jspecify.annotations.Nullable;

import java.util.function.Consumer;

import static java.util.Objects.requireNonNull;

/**
 * Implementation of {@link Awaitable}.
 * <p>
 * An {@link Awaitable} is always bound to a {@link WorkflowContext}.
 * <p>
 * Awaiting works by replaying events from the workflow run history.
 * Event handling is facilitated by {@link WorkflowContext}. It is responsible for initiating
 * state transitions of {@link Awaitable}s.
 * <p>
 * If after no more events can be replayed, the awaitable remains in {@link State.Pending} state,
 * the workflow is blocked and a {@link WorkflowRunBlockedError} is thrown.
 */
final class AwaitableImpl<T> implements Awaitable<T> {

    private sealed interface State<R> {

        record Pending<R>() implements State<R> {
        }

        record Completed<R>(@Nullable R result) implements State<R> {
        }

        record Failed<R>(FailureException exception) implements State<R> {
        }

        record Canceled<R>(String reason) implements State<R> {
        }

    }

    // This error is thrown very frequently, it is used for control flow,
    // and we don't care about stack traces for them. Having a single shared
    // instance avoids garbage, and overhead of filling stack traces.
    private static final WorkflowRunBlockedError BLOCKED_ERROR = new WorkflowRunBlockedError();

    private final WorkflowContextImpl<?, ?> workflowContext;
    private final PayloadConverter<T> resultConverter;
    private State<T> state = new State.Pending<>();
    private @Nullable Consumer<@Nullable T> completeCallback;

    AwaitableImpl(
            final WorkflowContextImpl<?, ?> workflowContext,
            final PayloadConverter<T> resultConverter) {
        this.workflowContext = workflowContext;
        this.resultConverter = resultConverter;
    }

    @Override
    public @Nullable T await() {
        while (state instanceof State.Pending<T>) {
            if (workflowContext.processNextEvent() == null) {
                throw BLOCKED_ERROR;
            }
        }

        return switch (state) {
            case State.Completed<T> it -> it.result();
            case State.Failed<T> it -> throw it.exception();
            case State.Canceled<T> it -> throw new CancellationFailureException(it.reason());
            case State.Pending<T> _ -> throw new AssertionError("unreachable");
        };
    }

    boolean complete(final @Nullable Payload resultPayload) {
        if (!(state instanceof State.Pending<T>)) {
            return false;
        }

        final T result = resultConverter.convertFromPayload(resultPayload);
        state = new State.Completed<>(result);

        if (completeCallback != null) {
            completeCallback.accept(result);
        }

        return true;
    }

    boolean completeExceptionally(final FailureException exception) {
        requireNonNull(exception, "exception must not be null");

        if (!(state instanceof State.Pending<T>)) {
            return false;
        }

        state = new State.Failed<>(exception);

        return true;
    }

    boolean cancel(final String reason) {
        requireNonNull(reason, "reason must not be null");

        if (!(state instanceof State.Pending<T>)) {
            return false;
        }

        state = new State.Canceled<>(reason);

        return true;
    }

    void onComplete(final Consumer<T> callback) {
        this.completeCallback = callback;
    }

}
