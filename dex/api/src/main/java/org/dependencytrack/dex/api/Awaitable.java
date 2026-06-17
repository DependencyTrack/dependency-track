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

import org.dependencytrack.dex.api.failure.ActivityFailureException;
import org.dependencytrack.dex.api.failure.CancellationFailureException;
import org.dependencytrack.dex.api.failure.ChildWorkflowFailureException;
import org.dependencytrack.dex.api.failure.SideEffectFailureException;
import org.jspecify.annotations.Nullable;

/**
 * A deferred result than can be awaited.
 *
 * @param <T> Type of the result.
 */
public interface Awaitable<T extends @Nullable Object> {

    /**
     * Await completion and retrieve the result.
     *
     * @return The result, if any.
     * @throws WorkflowRunError              When a condition was encountered that should be handled by the engine.
     *                                       <strong>Must not</strong> be caught.
     * @throws CancellationFailureException  When the awaitable was canceled before it could complete.
     * @throws ActivityFailureException      When awaiting an activity result, and the activity failed.
     * @throws ChildWorkflowFailureException When awaiting a child workflow result, and the workflow failed.
     * @throws SideEffectFailureException    When awaiting a side effect result, and the side effect failed.
     */
    @Nullable
    T await();

}
