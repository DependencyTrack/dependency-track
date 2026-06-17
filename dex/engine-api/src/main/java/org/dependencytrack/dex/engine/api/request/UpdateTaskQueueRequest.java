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
package org.dependencytrack.dex.engine.api.request;

import org.dependencytrack.dex.engine.api.TaskQueueStatus;
import org.dependencytrack.dex.engine.api.TaskType;
import org.jspecify.annotations.Nullable;

import static java.util.Objects.requireNonNull;

public record UpdateTaskQueueRequest(
        TaskType type,
        String name,
        @Nullable TaskQueueStatus status,
        @Nullable Integer capacity) {

    public UpdateTaskQueueRequest {
        requireNonNull(type, "type must not be null");
        requireNonNull(name, "name must not be null");
        if (capacity != null && capacity <= 0) {
            throw new IllegalArgumentException("capacity must not be negative or zero");
        }
    }

}
