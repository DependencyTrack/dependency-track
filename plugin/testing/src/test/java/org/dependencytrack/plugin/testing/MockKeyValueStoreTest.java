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
package org.dependencytrack.plugin.testing;

import org.dependencytrack.plugin.api.storage.CompareAndDeleteResult;
import org.dependencytrack.plugin.api.storage.CompareAndPutResult;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class MockKeyValueStoreTest {

    private final ConcurrentMap<String, KeyValueStore.Entry> backingMap = new ConcurrentHashMap<>();
    private final KeyValueStore kvStore = new MockKeyValueStore(backingMap);

    @Nested
    class PutManyTest {

        @Test
        void shouldCreateOrUpdateEntries() {
            kvStore.put("someKey", "someValue");

            assertThat(kvStore.getAll()).satisfiesExactly(entry -> {
                assertThat(entry.key()).isEqualTo("someKey");
                assertThat(entry.value()).isEqualTo("someValue");
                assertThat(entry.createdAt()).isNotNull();
                assertThat(entry.updatedAt()).isNull();
            });

            kvStore.putMany(
                    Map.ofEntries(
                            Map.entry("someKey", "someOtherValue"),
                            Map.entry("abc", "def")));

            assertThat(kvStore.getAll()).satisfiesExactlyInAnyOrder(
                    entry -> {
                        assertThat(entry.key()).isEqualTo("someKey");
                        assertThat(entry.value()).isEqualTo("someOtherValue");
                        assertThat(entry.createdAt()).isNotNull();
                        assertThat(entry.updatedAt()).isNotNull();
                        assertThat(entry.version()).isOne();
                    },
                    entry -> {
                        assertThat(entry.key()).isEqualTo("abc");
                        assertThat(entry.value()).isEqualTo("def");
                        assertThat(entry.createdAt()).isNotNull();
                        assertThat(entry.updatedAt()).isNull();
                        assertThat(entry.version()).isZero();
                    });
        }

        @Test
        void shouldDoNothingWhenKvPairsIsEmpty() {
            assertThatNoException()
                    .isThrownBy(() -> kvStore.putMany(Collections.emptyMap()));
            assertThat(kvStore.getAll()).isEmpty();
        }

        @Test
        void shouldThrowWhenKvPairsIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> kvStore.putMany(null))
                    .withMessage("kvPairs must not be null");
        }

    }

    @Nested
    class CompareAndPutTest {

        @Test
        void shouldReturnSuccessWhenVersionIsNullAndEntryDoesNotExist() {
            final CompareAndPutResult result = kvStore.compareAndPut("abc", "def", null);
            assertThat(result).isInstanceOf(CompareAndPutResult.Success.class);

            final var successResult = (CompareAndPutResult.Success) result;
            assertThat(successResult.newVersion()).isZero();

            final KeyValueStore.Entry entry = kvStore.get("abc");
            assertThat(entry).isNotNull();
            assertThat(entry.value()).isEqualTo("def");
            assertThat(entry.createdAt()).isNotNull();
            assertThat(entry.updatedAt()).isNull();
            assertThat(entry.version()).isZero();
        }

        @Test
        void shouldReturnFailureWhenVersionIsNullAndEntryAlreadyExists() {
            kvStore.put("abc", "def");

            final CompareAndPutResult result = kvStore.compareAndPut("abc", "xyz", null);
            assertThat(result).isInstanceOf(CompareAndPutResult.Failure.class);

            final var failureResult = (CompareAndPutResult.Failure) result;
            assertThat(failureResult.reason()).isEqualTo(CompareAndPutResult.Failure.Reason.ALREADY_EXISTS);
        }

        @Test
        void shouldReturnSuccessWhenVersionIsNotNullAndEntryExistsAndVersionMatches() {
            kvStore.put("abc", "def");

            final KeyValueStore.Entry existingEntry = kvStore.get("abc");
            assertThat(existingEntry).isNotNull();

            final CompareAndPutResult result = kvStore.compareAndPut("abc", "xyz", existingEntry.version());
            assertThat(result).isInstanceOf(CompareAndPutResult.Success.class);

            final var successResult = (CompareAndPutResult.Success) result;
            assertThat(successResult.newVersion()).isGreaterThan(0);

            final KeyValueStore.Entry updatedEntry = kvStore.get("abc");
            assertThat(updatedEntry).isNotNull();
            assertThat(updatedEntry.value()).isEqualTo("xyz");
            assertThat(updatedEntry.createdAt()).isEqualTo(existingEntry.createdAt());
            assertThat(updatedEntry.updatedAt()).isNotNull();
            assertThat(updatedEntry.version()).isNotEqualTo(existingEntry.version());
        }

        @Test
        void shouldReturnFailureWhenVersionIsNotNullAndEntryExistsAndVersionDoesNotMatch() {
            kvStore.put("abc", "def");

            final CompareAndPutResult result = kvStore.compareAndPut("abc", "xyz", 666L);
            assertThat(result).isInstanceOf(CompareAndPutResult.Failure.class);

            final var failureResult = (CompareAndPutResult.Failure) result;
            assertThat(failureResult.reason()).isEqualTo(CompareAndPutResult.Failure.Reason.VERSION_MISMATCH);
        }

        @Test
        void shouldReturnFailureWhenVersionIsNotNullAndEntryDoesNotExist() {
            final CompareAndPutResult result = kvStore.compareAndPut("abc", "xyz", 666L);
            assertThat(result).isInstanceOf(CompareAndPutResult.Failure.class);

            final var failureResult = (CompareAndPutResult.Failure) result;
            assertThat(failureResult.reason()).isEqualTo(CompareAndPutResult.Failure.Reason.VERSION_MISMATCH);
        }

    }

    @Nested
    class GetAllTest {

        @Test
        void shouldReturnAllEntries() {
            kvStore.putMany(
                    Map.ofEntries(
                            Map.entry("abc", "def"),
                            Map.entry("123", "456")));

            assertThat(kvStore.getAll()).satisfiesExactlyInAnyOrder(
                    entry -> {
                        assertThat(entry.key()).isEqualTo("abc");
                        assertThat(entry.value()).isEqualTo("def");
                        assertThat(entry.createdAt()).isNotNull();
                        assertThat(entry.updatedAt()).isNull();
                        assertThat(entry.version()).isZero();
                    },
                    entry -> {
                        assertThat(entry.key()).isEqualTo("123");
                        assertThat(entry.value()).isEqualTo("456");
                        assertThat(entry.createdAt()).isNotNull();
                        assertThat(entry.updatedAt()).isNull();
                        assertThat(entry.version()).isZero();
                    }
            );
        }

    }

    @Nested
    class GetManyTest {

        @Test
        void shouldReturnOfRequestedKeys() {
            kvStore.putMany(
                    Map.ofEntries(
                            Map.entry("abc", "def"),
                            Map.entry("123", "456"),
                            Map.entry("xxx", "yyy")));

            assertThat(kvStore.getMany(List.of("123", "abc", "000")).entrySet()).satisfiesExactlyInAnyOrder(
                    mapEntry -> {
                        assertThat(mapEntry.getKey()).isEqualTo("abc");
                        assertThat(mapEntry.getValue().value()).isEqualTo("def");
                        assertThat(mapEntry.getValue().createdAt()).isNotNull();
                        assertThat(mapEntry.getValue().updatedAt()).isNull();
                    },
                    mapEntry -> {
                        assertThat(mapEntry.getKey()).isEqualTo("123");
                        assertThat(mapEntry.getValue().value()).isEqualTo("456");
                        assertThat(mapEntry.getValue().createdAt()).isNotNull();
                        assertThat(mapEntry.getValue().updatedAt()).isNull();
                    });
        }

        @Test
        void shouldReturnEmptyMapWhenKeysDoNotExist() {
            assertThat(kvStore.getMany(List.of("123"))).isEmpty();
        }

        @Test
        void shouldReturnEmptyMapWhenKeysAreEmpty() {
            assertThat(kvStore.getMany(Collections.emptyList())).isEmpty();
        }

        @Test
        void shouldThrowWhenKeysIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> kvStore.getMany(null))
                    .withMessage("keys must not be null");
        }

    }

    @Nested
    class DeleteManyTest {

        @Test
        void shouldDeleteEntriesWithMatchingKeys() {
            kvStore.put("abc", "def");
            kvStore.put("123", "456");

            kvStore.deleteMany(List.of("abc", "123", "000"));

            assertThat(kvStore.getAll()).isEmpty();
        }

        @Test
        void shouldDoNothingWhenKeysIsEmpty() {
            assertThatNoException()
                    .isThrownBy(() -> kvStore.deleteMany(Collections.emptyList()));
        }

    }

    @Nested
    class CompareAndDeleteTest {

        @Test
        void shouldReturnSuccessWhenEntryWasDeleted() {
            kvStore.put("abc", "def");

            final KeyValueStore.Entry entry = kvStore.get("abc");
            assertThat(entry).isNotNull();

            final CompareAndDeleteResult result = kvStore.compareAndDelete("abc", entry.version());
            assertThat(result).isInstanceOf(CompareAndDeleteResult.Success.class);

            assertThat(kvStore.get("abc")).isNull();
        }

        @Test
        void shouldReturnFailureWhenEntryDoesNotExist() {
            final CompareAndDeleteResult result = kvStore.compareAndDelete("abc", 0);
            assertThat(result).isInstanceOf(CompareAndDeleteResult.Failure.class);

            final var failureResult = (CompareAndDeleteResult.Failure) result;
            assertThat(failureResult.reason()).isEqualTo(CompareAndDeleteResult.Failure.Reason.VERSION_MISMATCH);
        }

        @Test
        void shouldReturnFailureWhenEntryExistsAndVersionDoesNotMatch() {
            kvStore.put("abc", "def");

            final CompareAndDeleteResult result = kvStore.compareAndDelete("abc", 666L);
            assertThat(result).isInstanceOf(CompareAndDeleteResult.Failure.class);

            final var failureResult = (CompareAndDeleteResult.Failure) result;
            assertThat(failureResult.reason()).isEqualTo(CompareAndDeleteResult.Failure.Reason.VERSION_MISMATCH);
        }

    }

}
