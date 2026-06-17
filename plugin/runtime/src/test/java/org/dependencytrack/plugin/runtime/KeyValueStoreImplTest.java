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
package org.dependencytrack.plugin.runtime;

import org.dependencytrack.plugin.api.storage.CompareAndDeleteResult;
import org.dependencytrack.plugin.api.storage.CompareAndPutResult;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class KeyValueStoreImplTest extends AbstractDatabaseTest {

    private final KeyValueStore kvStore = new KeyValueStoreImpl(jdbi, "foo", "bar");

    @Test
    void constructorShouldThrowWhenExtensionPointNameIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new KeyValueStoreImpl(jdbi, null, "extension"))
                .withMessage("extensionPointName must not be null");
    }

    @Test
    void constructorShouldThrowWhenExtensionNameIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new KeyValueStoreImpl(jdbi, "extensionPoint", null))
                .withMessage("extensionName must not be null");
    }

    @Test
    void putManyShouldCreateOrUpdateEntries() {
        kvStore.put("someKey", "someValue");

        assertThat(getAllStoreEntries()).satisfiesExactly(entry -> {
            assertThat(entry.extensionPoint()).isEqualTo("foo");
            assertThat(entry.extension()).isEqualTo("bar");
            assertThat(entry.key()).isEqualTo("someKey");
            assertThat(entry.value()).isEqualTo("someValue");
            assertThat(entry.createdAt()).isNotNull();
            assertThat(entry.updatedAt()).isNull();
        });

        kvStore.putMany(
                Map.ofEntries(
                        Map.entry("someKey", "someOtherValue"),
                        Map.entry("abc", "def")));

        assertThat(getAllStoreEntries()).satisfiesExactlyInAnyOrder(
                entry -> {
                    assertThat(entry.extensionPoint()).isEqualTo("foo");
                    assertThat(entry.extension()).isEqualTo("bar");
                    assertThat(entry.key()).isEqualTo("someKey");
                    assertThat(entry.value()).isEqualTo("someOtherValue");
                    assertThat(entry.createdAt()).isNotNull();
                    assertThat(entry.updatedAt()).isNotNull();
                },
                entry -> {
                    assertThat(entry.extensionPoint()).isEqualTo("foo");
                    assertThat(entry.extension()).isEqualTo("bar");
                    assertThat(entry.key()).isEqualTo("abc");
                    assertThat(entry.value()).isEqualTo("def");
                    assertThat(entry.createdAt()).isNotNull();
                    assertThat(entry.updatedAt()).isNull();
                });
    }

    @Test
    void putManyShouldDoNothingWhenKvPairsIsEmpty() {
        assertThatNoException()
                .isThrownBy(() -> kvStore.putMany(Collections.emptyMap()));
        assertThat(getAllStoreEntries()).isEmpty();
    }

    @Test
    void putManyShouldThrowWhenKvPairsIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> kvStore.putMany(null))
                .withMessage("kvPairs must not be null");
    }

    @Test
    void compareAndPutShouldReturnSuccessWhenVersionIsNullAndEntryDoesNotExist() {
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
    void compareAndPutShouldReturnFailureWhenVersionIsNullAndEntryAlreadyExists() {
        kvStore.put("abc", "def");

        final CompareAndPutResult result = kvStore.compareAndPut("abc", "xyz", null);
        assertThat(result).isInstanceOf(CompareAndPutResult.Failure.class);

        final var failureResult = (CompareAndPutResult.Failure) result;
        assertThat(failureResult.reason()).isEqualTo(CompareAndPutResult.Failure.Reason.ALREADY_EXISTS);
    }

    @Test
    void compareAndPutShouldReturnSuccessWhenVersionIsNotNullAndEntryExistsAndVersionMatches() {
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
    void compareAndPutShouldReturnFailureWhenVersionIsNotNullAndEntryExistsAndVersionDoesNotMatch() {
        kvStore.put("abc", "def");

        final CompareAndPutResult result = kvStore.compareAndPut("abc", "xyz", 666L);
        assertThat(result).isInstanceOf(CompareAndPutResult.Failure.class);

        final var failureResult = (CompareAndPutResult.Failure) result;
        assertThat(failureResult.reason()).isEqualTo(CompareAndPutResult.Failure.Reason.VERSION_MISMATCH);
    }

    @Test
    void compareAndPutShouldReturnFailureWhenVersionIsNotNullAndEntryDoesNotExist() {
        final CompareAndPutResult result = kvStore.compareAndPut("abc", "xyz", 666L);
        assertThat(result).isInstanceOf(CompareAndPutResult.Failure.class);

        final var failureResult = (CompareAndPutResult.Failure) result;
        assertThat(failureResult.reason()).isEqualTo(CompareAndPutResult.Failure.Reason.VERSION_MISMATCH);
    }

    @Test
    void getAllEntriesShouldReturnAll() {
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

    @Test
    void getManyEntriesShouldReturnOfRequestedKeys() {
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
    void getManyShouldReturnEmptyMapWhenKeysDoNotExist() {
        assertThat(kvStore.getMany(List.of("123"))).isEmpty();
    }

    @Test
    void getManyShouldReturnEmptyMapWhenKeysAreEmpty() {
        final var kvStore = new KeyValueStoreImpl(jdbi, "foo", "bar");

        assertThat(kvStore.getMany(Collections.emptyList())).isEmpty();
    }

    @Test
    void getManyShouldThrowWhenKeysIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> kvStore.getMany(null))
                .withMessage("keys must not be null");
    }

    @Test
    void deleteManyShouldDeleteEntriesWithMatchingKeys() {
        kvStore.put("abc", "def");
        kvStore.put("123", "456");

        kvStore.deleteMany(List.of("abc", "123", "000"));

        assertThat(getAllStoreEntries()).isEmpty();
    }

    @Test
    void deleteManyShouldDoNothingWhenKeysIsEmpty() {
        assertThatNoException()
                .isThrownBy(() -> kvStore.deleteMany(Collections.emptyList()));
    }

    @Test
    void compareAndDeleteShouldReturnSuccessWhenEntryWasDeleted() {
        kvStore.put("abc", "def");

        final KeyValueStore.Entry entry = kvStore.get("abc");
        assertThat(entry).isNotNull();

        final CompareAndDeleteResult result = kvStore.compareAndDelete("abc", entry.version());
        assertThat(result).isInstanceOf(CompareAndDeleteResult.Success.class);

        assertThat(kvStore.get("abc")).isNull();
    }

    @Test
    void compareAndDeleteShouldReturnFailureWhenEntryDoesNotExist() {
        final CompareAndDeleteResult result = kvStore.compareAndDelete("abc", 0);
        assertThat(result).isInstanceOf(CompareAndDeleteResult.Failure.class);

        final var failureResult = (CompareAndDeleteResult.Failure) result;
        assertThat(failureResult.reason()).isEqualTo(CompareAndDeleteResult.Failure.Reason.VERSION_MISMATCH);
    }

    @Test
    void compareAndDeleteShouldReturnFailureWhenEntryExistsAndVersionDoesNotMatch() {
        kvStore.put("abc", "def");

        final CompareAndDeleteResult result = kvStore.compareAndDelete("abc", 666L);
        assertThat(result).isInstanceOf(CompareAndDeleteResult.Failure.class);

        final var failureResult = (CompareAndDeleteResult.Failure) result;
        assertThat(failureResult.reason()).isEqualTo(CompareAndDeleteResult.Failure.Reason.VERSION_MISMATCH);
    }

    public record StoreEntryRecord(
            String extensionPoint,
            String extension,
            String key,
            String value,
            Instant createdAt,
            Instant updatedAt) {
    }

    private List<StoreEntryRecord> getAllStoreEntries() {
        return jdbi.withHandle(handle -> handle.createQuery("""
                        SELECT * FROM "EXTENSION_KV_STORE"
                        """)
                .map(ConstructorMapper.of(StoreEntryRecord.class))
                .list());
    }

}
