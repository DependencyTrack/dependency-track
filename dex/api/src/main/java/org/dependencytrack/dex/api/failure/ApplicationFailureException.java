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
package org.dependencytrack.dex.api.failure;

import org.jspecify.annotations.Nullable;

import java.time.Duration;

/**
 * A {@link FailureException} thrown by application code.
 */
public non-sealed class ApplicationFailureException extends FailureException {

    private final boolean isTerminal;
    private final @Nullable Duration retryAfter;

    private ApplicationFailureException(
            @Nullable String message,
            @Nullable Throwable cause,
            boolean isTerminal,
            @Nullable Duration retryAfter) {
        super(message, null, cause);
        if (isTerminal && retryAfter != null) {
            throw new IllegalArgumentException("retryAfter must not be set for terminal failures");
        }
        if (retryAfter != null && (retryAfter.isZero() || retryAfter.isNegative())) {
            throw new IllegalArgumentException("retryAfter must be positive, but was: " + retryAfter);
        }
        this.isTerminal = isTerminal;
        this.retryAfter = retryAfter;
    }

    public ApplicationFailureException(
            @Nullable String message,
            @Nullable Throwable cause,
            boolean isTerminal) {
        this(message, cause, isTerminal, null);
    }

    public ApplicationFailureException(
            @Nullable String message,
            @Nullable Throwable cause,
            @Nullable Duration retryAfter) {
        this(message, cause, false, retryAfter);
    }

    public ApplicationFailureException(
            @Nullable String message,
            @Nullable Throwable cause) {
        this(message, cause, false);
    }

    public boolean isTerminal() {
        return isTerminal;
    }

    public @Nullable Duration retryAfter() {
        return retryAfter;
    }

}
