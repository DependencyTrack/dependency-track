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

import org.jspecify.annotations.Nullable;

/**
 * {@link Error} that may be thrown during a workflow execution.
 * <p>
 * Errors of this type <strong>must not</strong> be caught,
 * as they are expected to be handled by the engine.
 */
public abstract sealed class WorkflowRunError extends Error permits
        WorkflowRunBlockedError,
        WorkflowRunCanceledError,
        WorkflowRunContinuedAsNewError,
        WorkflowRunDeterminismError {

    WorkflowRunError(final @Nullable String message) {
        super(message);
    }

    WorkflowRunError(
            final @Nullable String message,
            final @Nullable Throwable cause,
            final boolean enableSuppression,
            final boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
