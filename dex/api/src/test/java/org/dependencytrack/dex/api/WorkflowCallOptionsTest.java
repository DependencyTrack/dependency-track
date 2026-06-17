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
package org.dependencytrack.dex.api;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class WorkflowCallOptionsTest {

    @Test
    void shouldHaveExpectedDefaults() {
        final var callOptions = new WorkflowCallOptions<>();
        assertThat(callOptions.taskQueueName()).isNull();
        assertThat(callOptions.argument()).isNull();
        assertThat(callOptions.concurrencyKey()).isNull();
    }

    @Test
    void withArgumentShouldAddArgument() {
        final var callOptions = new WorkflowCallOptions<>().withArgument("foo");
        assertThat(callOptions.argument()).isEqualTo("foo");
    }

    @Test
    void withConcurrencyKeyShouldAddConcurrencyKey() {
        final var callOptions = new WorkflowCallOptions<>().withConcurrencyKey("foo");
        assertThat(callOptions.concurrencyKey()).isEqualTo("foo");
    }

}