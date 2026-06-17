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
package org.dependencytrack.plugin.api.storage;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class KeyValueStoreTest {

    @Test
    void putShouldThrowWhenKeyIsNull() {
        final var kvStore = new DummyKVStore();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> kvStore.put(null, "someValue"))
                .withMessage("key must not be null");
    }

    @Test
    void putShouldThrowWhenValueIsNull() {
        final var kvStore = new DummyKVStore();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> kvStore.put("someKey", null))
                .withMessage("value must not be null");
    }

    @Test
    void getShouldThrowWhenKeyIsNull() {
        final var kvStore = new DummyKVStore();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> kvStore.get(null))
                .withMessage("key must not be null");
    }

    @Test
    void deleteShouldThrowWhenKeyIsNull() {
        final var kvStore = new DummyKVStore();

        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> kvStore.delete(null))
                .withMessage("key must not be null");
    }

    @Nested
    class EntryTest {

        @Test
        void shouldThrowWhenKeyIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> new KeyValueStore.Entry(null, "value", Instant.now(), Instant.now(), 0))
                    .withMessage("key must not be null");
        }

        @Test
        void shouldThrowWhenValueIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> new KeyValueStore.Entry("key", null, Instant.now(), Instant.now(), 0))
                    .withMessage("value must not be null");
        }

        @Test
        void shouldThrowWhenCreatedAtIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> new KeyValueStore.Entry("key", "value", null, Instant.now(), 0))
                    .withMessage("createdAt must not be null");
        }

        @Test
        void shouldNotThrowWhenUpdatedAtIsNull() {
            assertThatNoException()
                    .isThrownBy(() -> new KeyValueStore.Entry("key", "value", Instant.now(), null, 0));
        }

        @Test
        void shouldThrowWhenVersionIsNegative() {
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> new KeyValueStore.Entry("key", "value", Instant.now(), Instant.now(), -1))
                    .withMessage("version must not be negative");
        }

    }

    private static class DummyKVStore implements KeyValueStore {

        @Override
        public void putMany(final @NonNull Map<String, String> kvPairs) {
            throw new UnsupportedOperationException();
        }

        @Override
        public @NonNull CompareAndPutResult compareAndPut(@NonNull String key, @NonNull String value, Long expectedVersion) {
            throw new UnsupportedOperationException();
        }

        @Override
        public @NonNull List<Entry> getAll() {
            throw new UnsupportedOperationException();
        }

        @Override
        public @NonNull Map<String, Entry> getMany(final @NonNull Collection<String> keys) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void deleteMany(final @NonNull Collection<String> keys) {
            throw new UnsupportedOperationException();
        }

        @Override
        public @NonNull CompareAndDeleteResult compareAndDelete(@NonNull String key, long expectedVersion) {
            throw new UnsupportedOperationException();
        }

    }

}