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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.common;

import alpine.common.logging.Logger;

import javax.annotation.Nullable;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.Semaphore;

/**
 * An {@link Executor} that ensures that only a limited amount of tasks
 * is being executed concurrently by a delegate {@link Executor}.
 * <p>
 * This is used to prevent scenarios where an {@link Executor} must be shut down
 * but still has multiple hundreds or thousands of tasks queued.
 *
 * @since 4.6.0
 */
public final class LimitingExecutor implements Executor {

    private static final Logger LOGGER = Logger.getLogger(LimitingExecutor.class);

    private final Semaphore semaphore;
    private final Executor delegateExecutor;

    /**
     * @param delegateExecutor The {@link Executor} to delegate tasks to
     * @param limit The limit of concurrent tasks
     */
    public LimitingExecutor(final Executor delegateExecutor, final int limit) {
        this.delegateExecutor = delegateExecutor;
        this.semaphore = new Semaphore(limit);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void execute(@Nullable final Runnable command) {
        Objects.requireNonNull(command);

        try {
            semaphore.acquire();
        } catch (InterruptedException e) {
            LOGGER.debug("Interrupted while waiting for permit to be acquired from semaphore", e);
            return;
        }

        delegateExecutor.execute(() -> {
            try {
                command.run();
            } finally {
                semaphore.release();
            }
        });
    }

}
