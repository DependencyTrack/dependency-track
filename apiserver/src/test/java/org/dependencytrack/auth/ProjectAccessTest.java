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
package org.dependencytrack.auth;

import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ProjectAccessTest {

    @Test
    void shouldNotBeUnrestrictedByDefault() {
        assertThat(ProjectAccess.isUnrestricted()).isFalse();
    }

    @Test
    void shouldBeUnrestrictedInsideBlock() {
        final boolean observed = ProjectAccess.unrestricted(ProjectAccess::isUnrestricted);

        assertThat(observed).isTrue();
    }

    @Test
    void shouldRestoreStateAfterReturn() {
        ProjectAccess.unrestricted(() -> "result");

        assertThat(ProjectAccess.isUnrestricted()).isFalse();
    }

    @Test
    void shouldRestoreStateAfterException() {
        assertThatThrownBy(() -> ProjectAccess.unrestricted(() -> {
            throw new IllegalStateException("boom");
        })).isInstanceOf(IllegalStateException.class);

        assertThat(ProjectAccess.isUnrestricted()).isFalse();
    }

    @Test
    void shouldRemainUnrestrictedInNestedInvocation() {
        ProjectAccess.unrestricted(() -> {
            assertThat(ProjectAccess.isUnrestricted()).isTrue();

            ProjectAccess.unrestricted(() -> {
                assertThat(ProjectAccess.isUnrestricted()).isTrue();
                return null;
            });

            assertThat(ProjectAccess.isUnrestricted()).isTrue();
            return null;
        });

        assertThat(ProjectAccess.isUnrestricted()).isFalse();
    }

    @Test
    void shouldNotLeakAcrossThreads() {
        final var otherThreadObserved = new AtomicBoolean();

        ProjectAccess.unrestricted(() -> {
            try {
                CompletableFuture.runAsync(
                        () -> otherThreadObserved.set(ProjectAccess.isUnrestricted())).get();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            return null;
        });

        assertThat(otherThreadObserved).isFalse();
    }

}
