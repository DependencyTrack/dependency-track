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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.util;

import org.junit.Test;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

public class RoundRobinAccessorTest {

    @Test
    public void testGet() {
        final var accessor = new RoundRobinAccessor<>(List.of("foo", "bar", "baz"));

        for (int i = 0; i < 3_000_000; i += 3) {
            assertThat(accessor.get()).isEqualTo("foo");
            assertThat(accessor.get()).isEqualTo("bar");
            assertThat(accessor.get()).isEqualTo("baz");
        }
    }

    @Test
    public void testGetConcurrently() throws Exception {
        final var accessor = new RoundRobinAccessor<>(List.of("foo", "bar", "baz"));

        final var countDownLatch = new CountDownLatch(3_000_000);

        final var fooCounter = new AtomicInteger();
        final var barCounter = new AtomicInteger();
        final var bazCounter = new AtomicInteger();

        final var executor = Executors.newFixedThreadPool(10);
        try {
            for (int i = 0; i < 3_000_000; i++) {
                executor.submit(() -> {
                    switch (accessor.get()) {
                        case "foo" -> fooCounter.incrementAndGet();
                        case "bar" -> barCounter.incrementAndGet();
                        case "baz" -> bazCounter.incrementAndGet();
                    }

                    countDownLatch.countDown();
                });
            }

            assertThat(countDownLatch.await(15, TimeUnit.SECONDS)).isTrue();
        } finally {
            executor.shutdownNow();
        }

        // Verify that the values have been evenly distributed.
        // Unsure as to how to best test the order here...
        assertThat(fooCounter.get()).isEqualTo(1_000_000);
        assertThat(barCounter.get()).isEqualTo(1_000_000);
        assertThat(bazCounter.get()).isEqualTo(1_000_000);
    }

    @Test
    public void testGetOnUnderflow() {
        final var accessor = new RoundRobinAccessor<>(List.of("foo", "bar", "baz"), new AtomicInteger(Integer.MAX_VALUE - 1));

        // The round-robin currently doesn't repeat cleanly when the underlying index exceeds Integer.MAX_VALUE.
        assertThat(accessor.get()).isEqualTo("foo"); // Integer.MAX_VALUE - 1
        assertThat(accessor.get()).isEqualTo("bar"); // Integer.MAX_VALUE
        assertThat(accessor.get()).isEqualTo("foo"); // 0
        assertThat(accessor.get()).isEqualTo("bar"); // 1
        assertThat(accessor.get()).isEqualTo("baz"); // 2
    }

}