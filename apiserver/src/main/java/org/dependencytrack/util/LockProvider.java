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
package org.dependencytrack.util;

import alpine.event.framework.Subscriber;
import net.javacrumbs.shedlock.core.DefaultLockingTaskExecutor;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import net.javacrumbs.shedlock.core.LockingTaskExecutor.Task;
import net.javacrumbs.shedlock.core.LockingTaskExecutor.TaskWithResult;
import net.javacrumbs.shedlock.provider.jdbc.JdbcLockProvider;
import org.dependencytrack.common.datasource.DataSourceRegistry;

public class LockProvider {

    /**
     * @since 5.0.0
     */
    public static void executeWithLock(final LockConfiguration lockConfiguration, final Runnable runnable) {
        newLockingTaskExecutor().executeWithLock(runnable, lockConfiguration);
    }

    /**
     * @since 5.0.0
     */
    public static void executeWithLock(final LockConfiguration lockConfiguration, final Task task) throws Throwable {
        newLockingTaskExecutor().executeWithLock(task, lockConfiguration);
    }

    /**
     * @since 5.0.0
     */
    public static <T> T executeWithLock(final LockConfiguration lockConfiguration, final TaskWithResult<T> task) throws Throwable {
        return newLockingTaskExecutor().executeWithLock(task, lockConfiguration).getResult();
    }

    /**
     * @since 5.0.0
     */
    public static boolean isTaskLockToBeExtended(long cumulativeDurationInMillis, final Class<? extends Subscriber> taskClass) {
        final LockConfiguration lockConfiguration = TaskUtil.getLockConfigForTask(taskClass);
        return cumulativeDurationInMillis >= (lockConfiguration.getLockAtMostFor().minus(lockConfiguration.getLockAtLeastFor())).toMillis();
    }

    private static LockingTaskExecutor newLockingTaskExecutor() {
        return new DefaultLockingTaskExecutor(
                new JdbcLockProvider(DataSourceRegistry.getInstance().getDefault()));
    }

}
