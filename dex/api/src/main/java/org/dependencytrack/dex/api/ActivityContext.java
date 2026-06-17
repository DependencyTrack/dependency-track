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

import java.util.UUID;

/**
 * Context available to {@link Activity}s.
 */
public interface ActivityContext {

    /**
     * @return ID of the workflow run that this activity execution is part of.
     */
    UUID workflowRunId();

    /**
     * Emit a heartbeat to signal to the engine that the activity is still being worked on.
     * <p>
     * This method is safe to call frequently. It is up to the engine to decide
     * whether a heartbeat is actually emitted or dropped if deemed unnecessary.
     *
     * @return {@code true} when a heartbeat was emitted and succeeded,
     * or {@code false} when no heartbeat was emitted.
     */
    boolean maybeHeartbeat();

}
