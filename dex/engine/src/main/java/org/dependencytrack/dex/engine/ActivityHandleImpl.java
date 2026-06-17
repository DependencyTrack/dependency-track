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

import org.dependencytrack.dex.api.ActivityCallOptions;
import org.dependencytrack.dex.api.ActivityHandle;
import org.dependencytrack.dex.api.Awaitable;
import org.dependencytrack.dex.api.payload.PayloadConverter;

import static java.util.Objects.requireNonNull;

final class ActivityHandleImpl<A, R> implements ActivityHandle<A, R> {

    private final WorkflowContextImpl<?, ?> workflowContext;
    private final String activityName;
    private final String defaultTaskQueueName;
    private final PayloadConverter<A> argumentConverter;
    private final PayloadConverter<R> resultConverter;

    ActivityHandleImpl(
            final WorkflowContextImpl<?, ?> workflowContext,
            final String activityName,
            final String defaultTaskQueueName,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter) {
        this.workflowContext = requireNonNull(workflowContext, "workflowContext must not be null");
        this.activityName = requireNonNull(activityName, "activityName must not be null");
        this.defaultTaskQueueName = requireNonNull(defaultTaskQueueName, "defaultTaskQueueName must not be null");
        this.argumentConverter = requireNonNull(argumentConverter, "argumentConverter must not be null");
        this.resultConverter = requireNonNull(resultConverter, "resultConverter must not be null");
    }

    @Override
    public Awaitable<R> call(final ActivityCallOptions<A> options) {
        requireNonNull(options, "options must not be null");

        return workflowContext.callActivity(
                this.activityName,
                options.taskQueueName() != null
                        ? options.taskQueueName()
                        : this.defaultTaskQueueName,
                options.argument(),
                this.argumentConverter,
                this.resultConverter,
                options.retryPolicy());
    }

}
