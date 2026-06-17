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

import io.smallrye.config.SmallRyeConfigBuilder;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@Testcontainers
class InitTaskExecutorTest {

    @Container
    private static final PostgreSQLContainer postgresContainer =
            new PostgreSQLContainer(DockerImageName.parse("postgres:14-alpine"));

    private static DataSource dataSource;
    private static Config config;

    @BeforeAll
    static void beforeAll() {
        final var pgDataSource = new PGSimpleDataSource();
        pgDataSource.setUrl(postgresContainer.getJdbcUrl());
        pgDataSource.setUser(postgresContainer.getUsername());
        pgDataSource.setPassword(postgresContainer.getPassword());
        dataSource = pgDataSource;

        config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.of())
                .build();
    }

    @Test
    void shouldExecuteTasksInPriorityOrder() {
        final var executedTaskNames = new ArrayList<String>(3);

        final var executor = new InitTaskExecutor(config, dataSource, List.of(
                new TestInitTask(1, "a", () -> executedTaskNames.add("a")),
                new TestInitTask(5, "b", () -> executedTaskNames.add("b")),
                new TestInitTask(3, "c", () -> executedTaskNames.add("c"))), null);
        executor.execute();

        assertThat(executedTaskNames).containsExactly("b", "c", "a");
    }

    @Test
    void shouldNotifyListenerOnTaskCompletion() {
        final var listener = mock(InitTaskListener.class);

        final var executor = new InitTaskExecutor(config, dataSource, List.of(
                new TestInitTask(2, "first"),
                new TestInitTask(1, "second")), listener);
        executor.execute();

        verify(listener).onTaskCompleted("first");
        verify(listener).onTaskCompleted("second");
    }

    @Test
    void shouldNotifyListenerOnTaskFailure() {
        final var listener = mock(InitTaskListener.class);
        final var cause = new IllegalStateException("boom");

        final var executor = new InitTaskExecutor(config, dataSource, List.of(
                new TestInitTask(1, "test", () -> {
                    throw cause;
                })), listener);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(executor::execute);

        verify(listener).onTaskFailed("test");
    }

    @Test
    void shouldThrowWhenTaskExecutionFails() {
        final var executor = new InitTaskExecutor(config, dataSource, List.of(
                new TestInitTask(1, "test", () -> {
                    throw new IllegalStateException("boom");
                })), null);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(executor::execute)
                .withMessage("Failed to execute init task test")
                .withCauseInstanceOf(IllegalStateException.class);
    }

    @Test
    void shouldThrowOnDuplicateTaskName() {
        final var executor = new InitTaskExecutor(config, dataSource, List.of(
                new TestInitTask(1, "test"),
                new TestInitTask(2, "test")), null);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(executor::execute)
                // NB: In a real-world scenario, the class names would be different.
                .withMessage("""
                        Duplicate task name test: Registered by \
                        org.dependencytrack.init.InitTaskExecutorTest$TestInitTask and \
                        org.dependencytrack.init.InitTaskExecutorTest$TestInitTask""");
    }

    @Test
    void shouldThrowOnInvalidTaskPriority() {
        final var executor = new InitTaskExecutor(config, dataSource, List.of(
                new TestInitTask(-1, "test")), null);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(executor::execute)
                .withMessage("Invalid priority of task test: Must be within [0..100] but is -1");
    }

    private static final class TestInitTask implements InitTask {

        private final int priority;
        private final String name;
        private final Runnable runnable;

        private TestInitTask(final int priority, final String name) {
            this(priority, name, null);
        }

        private TestInitTask(final int priority, final String name, final Runnable runnable) {
            this.priority = priority;
            this.name = name;
            this.runnable = runnable;
        }

        @Override
        public int priority() {
            return priority;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public void execute(final InitTaskContext ctx) {
            if (runnable != null) {
                runnable.run();
            }
        }

    }

}
