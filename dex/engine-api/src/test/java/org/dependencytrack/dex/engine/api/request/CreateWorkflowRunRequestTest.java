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

import org.dependencytrack.dex.proto.payload.v1.Payload;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class CreateWorkflowRunRequestTest {

    @Test
    void shouldThrowWhenWorkflowNameIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new CreateWorkflowRunRequest<>(null, 1))
                .withMessage("workflowName must not be null");
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0, 101})
    void shouldThrowWhenWorkflowVersionIsInvalid(final int workflowVersion) {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new CreateWorkflowRunRequest<>("workflowName", workflowVersion))
                .withMessage("workflowVersion must be between 1 and 100, but is " + workflowVersion);
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 101})
    void shouldThrowWhenPriorityIsInvalid(final int priority) {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new CreateWorkflowRunRequest<>("workflowName", 1)
                        .withPriority(priority))
                .withMessage("priority must be between 0 and 100, but is " + priority);
    }

    @Test
    void shouldPopulateFieldsUsingWithers() {
        final var request = new CreateWorkflowRunRequest<>("workflowName", 1)
                .withTaskQueueName("taskQueueName")
                .withPriority(66)
                .withConcurrencyKey("concurrencyKey")
                .withLabels(Map.of("foo", "bar"))
                .withArgument(Payload.getDefaultInstance());

        assertThat(request.workflowName()).isEqualTo("workflowName");
        assertThat(request.workflowVersion()).isEqualTo(1);
        assertThat(request.taskQueueName()).isEqualTo("taskQueueName");
        assertThat(request.priority()).isEqualTo(66);
        assertThat(request.concurrencyKey()).isEqualTo("concurrencyKey");
        assertThat(request.labels()).containsEntry("foo", "bar");
        assertThat(request.argument()).isEqualTo(Payload.getDefaultInstance());
    }

}