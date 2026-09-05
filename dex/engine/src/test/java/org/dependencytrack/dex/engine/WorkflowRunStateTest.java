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

import com.google.protobuf.util.Timestamps;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.proto.event.v1.RunCreated;
import org.dependencytrack.dex.proto.event.v1.WorkflowEvent;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;
import java.util.function.Function;

import static com.fasterxml.uuid.Generators.timeBasedEpochRandomGenerator;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class WorkflowRunStateTest {

    @Test
    void shouldNotBeCreatedWhenHistoryIsEmpty() {
        final var runState =
                new WorkflowRunState(timeBasedEpochRandomGenerator().generate(), List.of());

        assertThat(runState.isCreated()).isFalse();
    }

    @Test
    void shouldBeCreatedAfterApplyingRunCreatedEvent() {
        final UUID runId = timeBasedEpochRandomGenerator().generate();
        final var runState = new WorkflowRunState(runId, List.of(runCreatedEvent()));

        assertThat(runState.isCreated()).isTrue();
        assertThat(runState.workflowName()).isEqualTo("foo");
        assertThat(runState.workflowVersion()).isEqualTo(1);
        assertThat(runState.taskQueueName()).isEqualTo("default");
        assertThat(runState.priority()).isEqualTo(5);
        assertThat(runState.status()).isEqualTo(WorkflowRunStatus.CREATED);
        assertThat(runState.createdAt()).isNotNull();
    }

    @Test
    void shouldThrowWhenAccessingRunCreatedFieldsBeforeRunWasCreated() {
        final var runState =
                new WorkflowRunState(timeBasedEpochRandomGenerator().generate(), List.of());

        record Accessor(String field, Function<WorkflowRunState, Object> get) {}

        final List<Accessor> accessors = List.of(
                new Accessor("workflowName", WorkflowRunState::workflowName),
                new Accessor("workflowVersion", WorkflowRunState::workflowVersion),
                new Accessor("taskQueueName", WorkflowRunState::taskQueueName),
                new Accessor("priority", WorkflowRunState::priority),
                new Accessor("status", WorkflowRunState::status),
                new Accessor("createdAt", WorkflowRunState::createdAt));

        for (final Accessor accessor : accessors) {
            assertThatExceptionOfType(NullPointerException.class)
                    .as("accessor %s", accessor.field())
                    .isThrownBy(() -> accessor.get().apply(runState))
                    .withMessage("%s is not set because no RunCreated event was applied".formatted(accessor.field()));
        }
    }

    private static WorkflowEvent runCreatedEvent() {
        return WorkflowEvent.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.now())
                .setRunCreated(RunCreated.newBuilder()
                        .setWorkflowName("foo")
                        .setWorkflowVersion(1)
                        .setTaskQueueName("default")
                        .setPriority(5)
                        .build())
                .build();
    }
}
