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

import org.dependencytrack.dex.engine.api.TaskType;
import org.jspecify.annotations.Nullable;

import static java.util.Objects.requireNonNull;

public record ListTaskQueuesRequest(TaskType type, @Nullable String pageToken, int limit) {

    public ListTaskQueuesRequest {
        requireNonNull(type, "type must not be null");
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be greater than 0");
        }
    }

    public ListTaskQueuesRequest(final TaskType type) {
        this(type, null, 10);
    }

    public ListTaskQueuesRequest withPageToken(final @Nullable String pageToken) {
        return new ListTaskQueuesRequest(this.type, pageToken, this.limit);
    }

    public ListTaskQueuesRequest withLimit(final int limit) {
        return new ListTaskQueuesRequest(this.type, this.pageToken, limit);
    }

}
