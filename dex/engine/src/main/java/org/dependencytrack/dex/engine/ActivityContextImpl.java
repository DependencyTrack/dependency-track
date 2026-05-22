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

import org.dependencytrack.dex.api.ActivityContext;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

final class ActivityContextImpl implements ActivityContext {

    private final DexEngineImpl engine;
    private final ActivityTask task;
    private final Duration lockTimeout;

    ActivityContextImpl(
            final DexEngineImpl engine,
            final ActivityTask task,
            final Duration lockTimeout) {
        this.engine = engine;
        this.task = task;
        this.lockTimeout = lockTimeout;
    }

    @Override
    public UUID workflowRunId() {
        return task.id().workflowRunId();
    }

    @Override
    public boolean maybeHeartbeat() {
        // Debounce heartbeats such that they're only emitted if the current
        // lock is almost expired. "Almost" in this case referring to 1/3 of
        // or less of the lock timeout remaining.
        final Instant now = Instant.now();
        final Instant threshold = task.lock().expiresAt().minus(lockTimeout.dividedBy(3));
        if (now.isBefore(threshold)) {
            return false;
        }

        final CompletableFuture<TaskLock> newLockFuture =
                engine.heartbeatActivityTask(task.id(), task.lock(), lockTimeout);

        final TaskLock newLock;
        try {
            newLock = newLockFuture.join();
        } catch (CompletionException e) {
            // The completion exception has no meaning to callers of this method.
            // Unwrap its cause if possible.
            switch (e.getCause()) {
                case RuntimeException re -> throw re;
                case Error err -> throw err;
                case null -> throw e;
                default -> throw new IllegalStateException(e.getCause());
            }
        }

        task.setLock(newLock);
        return true;
    }

}
