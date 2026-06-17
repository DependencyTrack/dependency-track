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

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class WorkflowRunStatusTest {

    @ParameterizedTest
    @CsvSource(value = {
            "CREATED, CREATED, false",
            "CREATED, RUNNING, true",
            "CREATED, SUSPENDED, false",
            "CREATED, CANCELLED, true",
            "CREATED, COMPLETED, false",
            "CREATED, FAILED, false",
            "RUNNING, CREATED, false",
            "RUNNING, RUNNING, false",
            "RUNNING, SUSPENDED, true",
            "RUNNING, CANCELLED, true",
            "RUNNING, COMPLETED, true",
            "RUNNING, FAILED, true",
            "SUSPENDED, CREATED, false",
            "SUSPENDED, RUNNING, true",
            "SUSPENDED, SUSPENDED, false",
            "SUSPENDED, CANCELLED, true",
            "SUSPENDED, COMPLETED, false",
            "SUSPENDED, FAILED, false",
            "CANCELLED, CREATED, false",
            "CANCELLED, RUNNING, false",
            "CANCELLED, SUSPENDED, false",
            "CANCELLED, CANCELLED, false",
            "CANCELLED, COMPLETED, false",
            "CANCELLED, FAILED, false",
            "COMPLETED, CREATED, false",
            "COMPLETED, RUNNING, false",
            "COMPLETED, SUSPENDED, false",
            "COMPLETED, CANCELLED, false",
            "COMPLETED, COMPLETED, false",
            "COMPLETED, FAILED, false",
            "FAILED, CREATED, false",
            "FAILED, RUNNING, false",
            "FAILED, SUSPENDED, false",
            "FAILED, CANCELLED, false",
            "FAILED, COMPLETED, false",
            "FAILED, FAILED, false",
    })
    void shouldOnlyAllowValidTransitions(
            final WorkflowRunStatus from,
            final WorkflowRunStatus to,
            final boolean allowed) {
        assertThat(from.canTransitionTo(to)).isEqualTo(allowed);
    }

    @ParameterizedTest
    @CsvSource(value = {
            "CREATED, false",
            "RUNNING, false",
            "SUSPENDED, false",
            "CANCELLED, true",
            "COMPLETED, true",
            "FAILED, true"
    })
    void shouldDeclareTerminalStatuses(final WorkflowRunStatus status, final boolean terminal) {
        assertThat(status.isTerminal()).isEqualTo(terminal);
    }

}