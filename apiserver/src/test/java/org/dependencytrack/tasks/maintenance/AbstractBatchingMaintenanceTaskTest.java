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
package org.dependencytrack.tasks.maintenance;

import org.dependencytrack.PersistenceCapableTest;
import org.jdbi.v3.core.Handle;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class AbstractBatchingMaintenanceTaskTest extends PersistenceCapableTest {

    @Test
    void testAfterCommitCallbackRunsOutsideTransaction() {
        final var task = new TestBatchingMaintenanceTask();
        final var transactionHandle = new AtomicReference<Handle>();
        final var callbackResult = new AtomicReference<BatchResult>();

        final int totalProcessed = task.runBatched(
                2,
                handle -> {
                    assertThat(handle.isInTransaction()).isTrue();
                    transactionHandle.set(handle);
                    return new BatchResult(1);
                },
                BatchResult::processedCount,
                result -> {
                    assertThat(transactionHandle.get()).isNotNull();
                    assertThat(transactionHandle.get().isClosed()).isTrue();
                    callbackResult.set(result);
                });

        assertThat(totalProcessed).isEqualTo(1);
        assertThat(callbackResult.get()).isEqualTo(new BatchResult(1));
    }

    private record BatchResult(int processedCount) {}

    private static final class TestBatchingMaintenanceTask extends AbstractBatchingMaintenanceTask {

        private TestBatchingMaintenanceTask() {
            super(2);
        }

        @Override
        public void run() {}
    }
}
