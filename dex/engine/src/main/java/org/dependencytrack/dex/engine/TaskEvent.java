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

import org.dependencytrack.dex.proto.payload.v1.Payload;
import org.jspecify.annotations.Nullable;

import java.time.Instant;

sealed interface TaskEvent {

    record ActivityTaskAbandonedEvent(
            ActivityTask task,
            Instant timestamp) implements TaskEvent {

        ActivityTaskAbandonedEvent(ActivityTask task) {
            this(task, Instant.now());
        }

    }

    record ActivityTaskCompletedEvent(
            ActivityTask task,
            @Nullable Payload result,
            Instant timestamp) implements TaskEvent {

        ActivityTaskCompletedEvent(ActivityTask task, @Nullable Payload result) {
            this(task, result, Instant.now());
        }

    }

    record ActivityTaskFailedEvent(
            ActivityTask task,
            Throwable exception,
            @Nullable Instant retryAt,
            Instant timestamp) implements TaskEvent {

        ActivityTaskFailedEvent(ActivityTask task, Throwable exception, @Nullable Instant retryAt) {
            this(task, exception, retryAt, Instant.now());
        }

    }

    record WorkflowTaskAbandonedEvent(WorkflowTask task) implements TaskEvent {
    }

    record WorkflowTaskCompletedEvent(
            WorkflowTask task,
            WorkflowRunState workflowRunState) implements TaskEvent {
    }

}
