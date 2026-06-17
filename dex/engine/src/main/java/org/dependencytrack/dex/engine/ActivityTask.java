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

import org.dependencytrack.dex.api.RetryPolicy;
import org.dependencytrack.dex.engine.persistence.model.PolledActivityTask;
import org.dependencytrack.dex.proto.payload.v1.Payload;
import org.jspecify.annotations.Nullable;

public final class ActivityTask implements Task {

    private final String activityName;
    private final ActivityTaskId id;
    private final @Nullable Payload argument;
    private final RetryPolicy retryPolicy;
    private final int attempt;
    private TaskLock lock;

    private ActivityTask(
            final String activityName,
            final ActivityTaskId id,
            final @Nullable Payload argument,
            final RetryPolicy retryPolicy,
            final int attempt,
            final TaskLock lock) {
        this.activityName = activityName;
        this.id = id;
        this.argument = argument;
        this.retryPolicy = retryPolicy;
        this.attempt = attempt;
        this.lock = lock;
    }

    static ActivityTask of(final PolledActivityTask polledTask) {
        return new ActivityTask(
                polledTask.activityName(),
                new ActivityTaskId(
                        polledTask.queueName(),
                        polledTask.workflowRunId(),
                        polledTask.createdEventId()),
                polledTask.argument(),
                RetryPolicy.fromProto(polledTask.retryPolicy()),
                polledTask.attempt(),
                new TaskLock(
                        polledTask.lockedUntil(),
                        polledTask.lockVersion()));
    }

    @Override
    public String queueName() {
        return id.queueName();
    }

    public String activityName() {
        return activityName;
    }

    public ActivityTaskId id() {
        return id;
    }

    public @Nullable Payload argument() {
        return argument;
    }

    public RetryPolicy retryPolicy() {
        return retryPolicy;
    }

    public int attempt() {
        return attempt;
    }

    public TaskLock lock() {
        return lock;
    }

    void setLock(final TaskLock lock) {
        this.lock = lock;
    }

}
