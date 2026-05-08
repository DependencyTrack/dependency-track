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
package org.dependencytrack.init;

import org.eclipse.microprofile.config.Config;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.ServiceLoader;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Predicate;

import static java.util.Comparator.comparing;
import static java.util.Comparator.reverseOrder;
import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public final class InitTaskExecutor {

    private static final Logger LOGGER = LoggerFactory.getLogger(InitTaskExecutor.class);
    private static final long ADVISORY_LOCK_KEY = "dependency-track-init-tasks".hashCode();

    private final Config config;
    private final DataSource dataSource;
    private final List<InitTask> tasks;
    private final @Nullable InitTaskListener listener;

    public InitTaskExecutor(Config config, DataSource dataSource, @Nullable InitTaskListener listener) {
        this(config, dataSource, loadInitTasks(), listener);
    }

    InitTaskExecutor(Config config, DataSource dataSource, List<InitTask> tasks, @Nullable InitTaskListener listener) {
        this.config = requireNonNull(config, "config must not be null");
        this.dataSource = requireNonNull(dataSource, "dataSource must not be null");
        this.tasks = requireNonNull(tasks, "tasks must not be null");
        this.listener = listener;
    }

    public void execute() {
        final List<InitTask> orderedTasks = this.tasks.stream()
                .peek(requireUniqueName())
                .peek(requireValidPriority())
                .filter(isTaskEnabled())
                .sorted(comparing(InitTask::priority, reverseOrder())
                        .thenComparing(InitTask::name))
                .toList();

        final long startTimeNanos = System.nanoTime();

        // We're using session-level advisory locks here,
        // which won't work when using PgBouncer in "transaction" mode.
        // We can't use transaction-level locking because that would
        // block some DDL statements executed by database migrations,
        // such as "CREATE INDEX CONCURRENTLY".
        //
        // This GitLab issue describes the problem well:
        // https://gitlab.com/gitlab-com/support/support-training/-/issues/3823#locks-block-a-gitlab-database-migration
        //
        // The intended workaround is to use a separate set of connection
        // details specifically for init tasks, which bypasses PgBouncer.
        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement lockStatement = connection.prepareStatement("""
                     SELECT PG_TRY_ADVISORY_LOCK(?)
                     """);
             final PreparedStatement unlockStatement = connection.prepareStatement("""
                     SELECT PG_ADVISORY_UNLOCK(?)
                     """)) {
            boolean lockAcquired = false;

            while (!lockAcquired && !Thread.currentThread().isInterrupted()) {
                LOGGER.debug("Trying to acquire lock {}", ADVISORY_LOCK_KEY);
                lockStatement.setLong(1, ADVISORY_LOCK_KEY);

                try (final ResultSet rs = lockStatement.executeQuery()) {
                    lockAcquired = rs.next() && rs.getBoolean(1);
                }

                if (!lockAcquired) {
                    LOGGER.debug("Could not acquire lock {}, trying again in 1s", ADVISORY_LOCK_KEY);
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }

            final long lockWaitMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTimeNanos);
            if (!lockAcquired) {
                throw new IllegalStateException(
                        "Failed to acquire lock %d after %dms".formatted(
                                ADVISORY_LOCK_KEY, lockWaitMillis));
            }
            LOGGER.debug("Lock {} acquired after {}ms", ADVISORY_LOCK_KEY, lockWaitMillis);

            final var taskContext = new InitTaskContext(config, dataSource);

            try {
                long taskStartTimeNanos;
                for (final InitTask task : orderedTasks) {
                    taskStartTimeNanos = System.nanoTime();
                    LOGGER.info("Executing init task {}", task.name());
                    if (listener != null) {
                        listener.onTaskStarted(task.name());
                    }
                    try {
                        task.execute(taskContext);
                        LOGGER.info(
                                "Completed init task {} in {}ms",
                                task.name(),
                                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - taskStartTimeNanos));
                        if (listener != null) {
                            listener.onTaskCompleted(task.name());
                        }
                    } catch (Exception e) {
                        if (listener != null) {
                            listener.onTaskFailed(task.name());
                        }
                        throw new IllegalStateException("Failed to execute init task " + task.name(), e);
                    }
                }
            } finally {
                LOGGER.debug("Releasing lock {}", ADVISORY_LOCK_KEY);
                unlockStatement.setLong(1, ADVISORY_LOCK_KEY);
                final ResultSet rs = unlockStatement.executeQuery();
                if (!rs.next() || !rs.getBoolean(1)) {
                    LOGGER.warn("""
                            Lock {} could not be released, likely because a connection pooler \
                            in "transaction" mode is being used. Ensure that a direct database connection \
                            is provided when executing init tasks.""", ADVISORY_LOCK_KEY);
                }
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to acquire or release lock " + ADVISORY_LOCK_KEY, e);
        }

        LOGGER.info(
                "All init tasks completed in {}ms",
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTimeNanos));
    }

    private static List<InitTask> loadInitTasks() {
        return ServiceLoader.load(InitTask.class).stream()
                .map(ServiceLoader.Provider::get)
                .toList();
    }

    private Consumer<InitTask> requireUniqueName() {
        final var seenTaskClassesByTaskName =
                new HashMap<String, Class<? extends InitTask>>(this.tasks.size());

        return task -> {
            final Class<? extends InitTask> previousClass =
                    seenTaskClassesByTaskName.put(task.name(), task.getClass());
            if (previousClass != null) {
                throw new IllegalStateException(
                        "Duplicate task name %s: Registered by %s and %s".formatted(
                                task.name(), previousClass.getName(), task.getClass().getName()));
            }
        };
    }

    private Consumer<InitTask> requireValidPriority() {
        return task -> {
            if (task.priority() < InitTask.PRIORITY_LOWEST
                    || task.priority() > InitTask.PRIORITY_HIGHEST) {
                throw new IllegalStateException(
                        "Invalid priority of task %s: Must be within [%d..%d] but is %d".formatted(
                                task.name(), InitTask.PRIORITY_LOWEST, InitTask.PRIORITY_HIGHEST, task.priority()));
            }
        };
    }

    private Predicate<InitTask> isTaskEnabled() {
        return task -> config.getOptionalValue(
                "dt.init.task.%s.enabled".formatted(task.name()), Boolean.class).orElse(true);
    }

}
