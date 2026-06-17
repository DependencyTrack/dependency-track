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

import com.google.protobuf.DebugFormat;
import org.dependencytrack.dex.api.failure.ActivityFailureException;
import org.dependencytrack.dex.api.failure.ApplicationFailureException;
import org.dependencytrack.dex.api.failure.CancellationFailureException;
import org.dependencytrack.dex.api.failure.ChildWorkflowFailureException;
import org.dependencytrack.dex.api.failure.FailureException;
import org.dependencytrack.dex.api.failure.InternalFailureException;
import org.dependencytrack.dex.api.failure.SideEffectFailureException;
import org.dependencytrack.dex.proto.failure.v1.ActivityFailureDetails;
import org.dependencytrack.dex.proto.failure.v1.ApplicationFailureDetails;
import org.dependencytrack.dex.proto.failure.v1.CancellationFailureDetails;
import org.dependencytrack.dex.proto.failure.v1.ChildWorkflowFailureDetails;
import org.dependencytrack.dex.proto.failure.v1.Failure;
import org.dependencytrack.dex.proto.failure.v1.InternalFailureDetails;
import org.dependencytrack.dex.proto.failure.v1.SideEffectFailureDetails;
import org.jspecify.annotations.Nullable;

import java.util.StringJoiner;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class that converts {@link Throwable}s into {@link Failure}s and vice versa.
 */
final class FailureConverter {

    private FailureConverter() {
    }

    static FailureException toException(final Failure failure) {
        final FailureException cause = failure.hasCause()
                ? toException(failure.getCause())
                : null;

        final FailureException exception = switch (failure.getFailureDetailsCase()) {
            case ACTIVITY_FAILURE_DETAILS -> {
                final ActivityFailureDetails details = failure.getActivityFailureDetails();
                yield new ActivityFailureException(details.getActivityName(), cause);
            }
            case APPLICATION_FAILURE_DETAILS -> {
                final ApplicationFailureDetails details = failure.getApplicationFailureDetails();
                yield new ApplicationFailureException(failure.getMessage(), cause, details.getIsTerminal());
            }
            case CANCELLATION_FAILURE_DETAILS -> {
                final CancellationFailureDetails details = failure.getCancellationFailureDetails();
                yield new CancellationFailureException(details.getReason());
            }
            case CHILD_WORKFLOW_FAILURE_DETAILS -> {
                final ChildWorkflowFailureDetails details = failure.getChildWorkflowFailureDetails();
                yield new ChildWorkflowFailureException(
                        UUID.fromString(details.getWorkflowRunId()),
                        details.getWorkflowName(),
                        details.getWorkflowVersion(),
                        cause);
            }
            case INTERNAL_FAILURE_DETAILS -> new InternalFailureException(failure.getMessage(), cause);
            case SIDE_EFFECT_FAILURE_DETAILS -> {
                final SideEffectFailureDetails details = failure.getSideEffectFailureDetails();
                yield new SideEffectFailureException(details.getSideEffectName(), cause);
            }
            default -> throw new IllegalArgumentException(
                    "Unknown details type %s for failure: %s".formatted(
                            failure.getFailureDetailsCase(),
                            DebugFormat.singleLine().toString(failure)));
        };

        if (failure.hasStackTrace()) {
            exception.setStackTrace(deserializeStackTrace(failure.getStackTrace()));
        }

        return exception;
    }

    static Failure toFailure(final Throwable throwable) {
        final Failure.Builder failureBuilder = Failure.newBuilder();

        switch (throwable) {
            case final ActivityFailureException activityException -> {
                if (activityException.getOriginalMessage() != null) {
                    failureBuilder.setMessage(activityException.getOriginalMessage());
                }
                failureBuilder
                        .setActivityFailureDetails(
                                ActivityFailureDetails.newBuilder()
                                        .setActivityName(activityException.getActivityName())
                                        .build());
            }
            case final ApplicationFailureException applicationException -> {
                if (applicationException.getOriginalMessage() != null) {
                    failureBuilder.setMessage(applicationException.getOriginalMessage());
                }
                failureBuilder
                        .setApplicationFailureDetails(
                                ApplicationFailureDetails.newBuilder()
                                        .setIsTerminal(applicationException.isTerminal())
                                        .build());
            }
            case final CancellationFailureException cancellationException -> {
                if (cancellationException.getOriginalMessage() != null) {
                    failureBuilder.setMessage(cancellationException.getOriginalMessage());
                }
                failureBuilder
                        .setCancellationFailureDetails(
                                CancellationFailureDetails.newBuilder()
                                        .setReason(cancellationException.getReason())
                                        .build());
            }
            case final ChildWorkflowFailureException childWorkflowException -> {
                if (childWorkflowException.getOriginalMessage() != null) {
                    failureBuilder.setMessage(childWorkflowException.getOriginalMessage());
                }
                failureBuilder
                        .setChildWorkflowFailureDetails(
                                ChildWorkflowFailureDetails.newBuilder()
                                        .setWorkflowRunId(childWorkflowException.getRunId().toString())
                                        .setWorkflowName(childWorkflowException.getWorkflowName())
                                        .setWorkflowVersion(childWorkflowException.getWorkflowVersion())
                                        .build());
            }
            case final InternalFailureException internalFailureException -> {
                if (internalFailureException.getMessage() != null) {
                    failureBuilder.setMessage(internalFailureException.getMessage());
                }
                failureBuilder.setInternalFailureDetails(InternalFailureDetails.getDefaultInstance());
            }
            case final SideEffectFailureException sideEffectException -> {
                if (sideEffectException.getOriginalMessage() != null) {
                    failureBuilder.setMessage(sideEffectException.getOriginalMessage());
                }
                failureBuilder
                        .setSideEffectFailureDetails(
                                SideEffectFailureDetails.newBuilder()
                                        .setSideEffectName(sideEffectException.getSideEffectName())
                                        .build());
            }
            default -> {
                if (throwable.getMessage() != null) {
                    failureBuilder.setMessage(throwable.getMessage());
                }

                failureBuilder.setApplicationFailureDetails(
                        ApplicationFailureDetails.newBuilder()
                                .setIsTerminal(false)
                                .build());
            }
        }

        if (throwable.getStackTrace() != null && throwable.getStackTrace().length > 0) {
            failureBuilder.setStackTrace(serializeStackTrace(throwable.getStackTrace()));
        }

        if (throwable.getCause() != null) {
            failureBuilder.setCause(toFailure(throwable.getCause()));
        }

        return failureBuilder.build();
    }

    private static @Nullable String serializeStackTrace(final StackTraceElement @Nullable [] stackTrace) {
        if (stackTrace == null || stackTrace.length == 0) {
            return null;
        }

        final var serializedStackTraceJoiner = new StringJoiner("\n");
        for (final StackTraceElement element : stackTrace) {
            // Cut the stack trace off before it enters engine internals.
            // These are not necessary for communicating failures in user code.
            if (element.getClassName().equals(ActivityTaskWorker.class.getName())
                    || element.getClassName().equals(WorkflowTaskWorker.class.getName())) {
                break;
            }

            var serializedElement = "%s.%s".formatted(element.getClassName(), element.getMethodName());
            if (element.getFileName() != null) {
                serializedElement += "(%s:%d)".formatted(element.getFileName(), element.getLineNumber());
            }

            serializedStackTraceJoiner.add(serializedElement);
        }

        return serializedStackTraceJoiner.toString();
    }

    private static final Pattern STACK_TRACE_ELEMENT_PATTERN = Pattern.compile(
            "^(?<className>[\\w.$:/]+)\\.(?<methodName>[\\w.$]+|<\\w+>)(?:\\((?<fileName>[\\w.]+):(?<lineNumber>-?\\d+)\\))?$");

    private static StackTraceElement @Nullable [] deserializeStackTrace(final @Nullable String stackTrace) {
        if (stackTrace == null || stackTrace.isEmpty()) {
            return null;
        }

        return stackTrace.lines()
                .map(serializedElement -> {
                    final Matcher matcher = STACK_TRACE_ELEMENT_PATTERN.matcher(serializedElement);
                    if (!matcher.find()) {
                        throw new IllegalArgumentException("Malformed stack trace element: " + serializedElement);
                    }

                    return new StackTraceElement(
                            matcher.group("className"),
                            matcher.group("methodName"),
                            matcher.group("fileName"),
                            matcher.group("lineNumber") != null
                                    ? Integer.parseInt(matcher.group("lineNumber"))
                                    : -1);
                })
                .toArray(StackTraceElement[]::new);
    }

}
