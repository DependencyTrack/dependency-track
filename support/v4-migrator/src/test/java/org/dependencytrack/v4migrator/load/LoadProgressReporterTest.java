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
package org.dependencytrack.v4migrator.load;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BooleanSupplier;

import static org.assertj.core.api.Assertions.assertThat;

class LoadProgressReporterTest {

    @Test
    void formatsElapsedAcrossUnits() {
        assertThat(LoadProgressReporter.formatElapsed(750)).isEqualTo("0s");
        assertThat(LoadProgressReporter.formatElapsed(12_000)).isEqualTo("12s");
        assertThat(LoadProgressReporter.formatElapsed(125_000)).isEqualTo("2m 5s");
        assertThat(LoadProgressReporter.formatElapsed(3_725_000)).isEqualTo("1h 2m 5s");
    }

    @Test
    void heartbeatFiresUntilDoneAndIncludesExpectedRows() throws Exception {
        final List<String> log = new CopyOnWriteArrayList<>();
        try (final LoadProgressReporter reporter = new LoadProgressReporter(Duration.ofMillis(50), log::add)) {
            reporter.start("PROJECT", 1234L);
            awaitUntil(() -> log.stream().anyMatch(s -> s.contains("still loading") && s.contains("expected 1234 rows")));
            reporter.done(1230L);
        }
        assertThat(log).anyMatch(s -> s.contains("-> PROJECT: 1230 rows"));
    }

    @Test
    void heartbeatOmitsExpectedRowsWhenUnknown() throws Exception {
        final List<String> log = new CopyOnWriteArrayList<>();
        try (final LoadProgressReporter reporter = new LoadProgressReporter(Duration.ofMillis(50), log::add)) {
            reporter.start("PROJECT_ACCESS_USERS", -1L);
            awaitUntil(() -> log.stream().anyMatch(s -> s.contains("still loading after")));
            reporter.done(7L);
        }
        assertThat(log).noneMatch(s -> s.contains("expected"));
    }

    @Test
    void failStopsHeartbeatWithoutSummary() throws Exception {
        final List<String> log = new CopyOnWriteArrayList<>();
        try (final LoadProgressReporter reporter = new LoadProgressReporter(Duration.ofMillis(50), log::add)) {
            reporter.start("PROJECT", 100L);
            awaitUntil(() -> !log.isEmpty());
            reporter.fail();
            final int countAtFail = log.size();
            Thread.sleep(200);
            assertThat(log).hasSize(countAtFail);
            assertThat(log).noneMatch(s -> s.contains("rows in"));
        }
    }

    private static void awaitUntil(final BooleanSupplier cond) throws InterruptedException {
        final long deadline = System.currentTimeMillis() + 2_000L;
        while (System.currentTimeMillis() < deadline) {
            if (cond.getAsBoolean()) {
                return;
            }
            Thread.sleep(20);
        }
        throw new AssertionError("Condition not met within 2s");
    }
}
