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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class WorkflowSpecsTest {

    @Test
    void shouldReturnSpec() {
        final WorkflowSpec spec = WorkflowSpecs.of(SpeccedWorkflow.class);
        assertThat(spec.name()).isEqualTo("specced");
        assertThat(spec.version()).isEqualTo(3);
    }

    @Test
    void shouldThrowWhenClassIsNotAnnotated() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> WorkflowSpecs.of(UnspeccedWorkflow.class))
                .withMessage("Class %s is not annotated with @%s"
                        .formatted(UnspeccedWorkflow.class.getName(), WorkflowSpec.class.getName()));
    }

    @WorkflowSpec(name = "specced", version = 3)
    private static final class SpeccedWorkflow implements Workflow<Void, Void> {

        @Override
        public @Nullable Void execute(@NonNull WorkflowContext<Void> ctx, Void arg) {
            return null;
        }
    }

    private static final class UnspeccedWorkflow implements Workflow<Void, Void> {

        @Override
        public @Nullable Void execute(@NonNull WorkflowContext<Void> ctx, Void arg) {
            return null;
        }
    }
}
