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
package org.dependencytrack.dex.engine.api;

import io.github.resilience4j.core.IntervalFunction;

import java.time.Duration;

import static java.util.Objects.requireNonNull;

public record TaskWorkerOptions(
        TaskType type,
        String name,
        String queueName,
        int maxConcurrency,
        Duration minPollInterval,
        IntervalFunction pollBackoffFunction) {

    public static final IntervalFunction DEFAULT_POLL_BACKOFF_FUNCTION =
            IntervalFunction.ofExponentialRandomBackoff(200, 2.0, 0.2, 2_000);

    public TaskWorkerOptions {
        requireNonNull(type, "type must not be null");
        requireNonNull(name, "name must not be null");
        requireNonNull(queueName, "queueName must not be null");
        if (maxConcurrency <= 0) {
            throw new IllegalArgumentException("maxConcurrency must not be negative or zero");
        }
        requireNonNull(minPollInterval, "minPollInterval must not be null");
        requireNonNull(pollBackoffFunction, "pollBackoffFunction must not be null");
    }

    public TaskWorkerOptions(TaskType taskType, String name, String queueName, int maxConcurrency) {
        this(taskType, name, queueName, maxConcurrency, Duration.ofMillis(100), DEFAULT_POLL_BACKOFF_FUNCTION);
    }

    public TaskWorkerOptions withMinPollInterval(Duration minPollInterval) {
        return new TaskWorkerOptions(
                this.type,
                this.name,
                this.queueName,
                this.maxConcurrency,
                minPollInterval,
                this.pollBackoffFunction);
    }

    public TaskWorkerOptions withPollBackoffFunction(IntervalFunction pollBackoffFunction) {
        return new TaskWorkerOptions(
                this.type,
                this.name,
                this.queueName,
                this.maxConcurrency,
                this.minPollInterval,
                pollBackoffFunction);
    }

}
