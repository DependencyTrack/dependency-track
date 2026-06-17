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
package org.dependencytrack.filestorage.memory;

import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.ProxySelector;
import java.nio.file.NoSuchFileException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class MemoryFileStorageTest {

    @Test
    void shouldHaveNameMemory() {
        final var provider = new MemoryFileStorageProvider();
        assertThat(provider.name()).isEqualTo("memory");
    }

    @Test
    @SuppressWarnings("resource")
    void shouldStoreGetAndDeleteFile() throws Exception {
        final FileStorage storage = createStorage();

        final FileMetadata fileMetadata = storage.store("foo/bar", new ByteArrayInputStream("baz".getBytes()));
        assertThat(fileMetadata).isNotNull();
        assertThat(fileMetadata.getProviderName()).isEqualTo("memory");
        assertThat(fileMetadata.getLocation()).isEqualTo("memory:///foo/bar");
        assertThat(fileMetadata.getMediaType()).isEqualTo("application/octet-stream");
        assertThat(fileMetadata.getSha256Digest()).isEqualTo("baa5a0964d3320fbc0c6a922140453c8513ea24ab8fd0577034804a967248096");

        final InputStream fileStream = storage.get(fileMetadata);
        assertThat(fileStream).isNotNull();
        assertThat(fileStream.readAllBytes()).asString().isEqualTo("baz");

        final boolean deleted = storage.delete(fileMetadata);
        assertThat(deleted).isTrue();
        assertThatExceptionOfType(NoSuchFileException.class).isThrownBy(() -> storage.get(fileMetadata));
    }

    @Test
    @SuppressWarnings("resource")
    void storeShouldOverwriteExistingFile() throws Exception {
        final FileStorage storage = createStorage();

        final FileMetadata fileMetadataA = storage.store("foo/bar", new ByteArrayInputStream("baz".getBytes()));
        final FileMetadata fileMetadataB = storage.store("foo/bar", new ByteArrayInputStream("qux".getBytes()));

        assertThat(storage.get(fileMetadataA).readAllBytes()).asString().isEqualTo("qux");
        assertThat(storage.get(fileMetadataB).readAllBytes()).asString().isEqualTo("qux");
    }

    @Test
    @SuppressWarnings("resource")
    void storeShouldThrowWhenFileHasInvalidName() {
        final FileStorage storage = createStorage();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.store("foo$bar", new ByteArrayInputStream("bar".getBytes())))
                .withMessage("fileName 'foo$bar' does not match pattern: [a-zA-Z0-9_/\\-.]+");
    }

    @Test
    @SuppressWarnings("resource")
    void getShouldThrowWhenFileDoesNotExist() {
        final FileStorage storage = createStorage();

        assertThatExceptionOfType(NoSuchFileException.class)
                .isThrownBy(() -> storage.get(
                        FileMetadata.newBuilder()
                                .setLocation("memory:///foo/bar")
                                .setSha256Digest("some-digest")
                                .build()));
    }

    @Test
    @SuppressWarnings("resource")
    void getShouldThrowWhenFileLocationHasInvalidScheme() {
        final FileStorage storage = createStorage();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.get(
                        FileMetadata.newBuilder()
                                .setLocation("foo:///bar")
                                .build()))
                .withMessage("foo:///bar: Unexpected scheme foo, expected memory");
    }

    @Test
    @SuppressWarnings("resource")
    void deleteShouldReturnFalseWhenFileDoesNotExist() throws Exception {
        final FileStorage storage = createStorage();

        final boolean deleted = storage.delete(
                FileMetadata.newBuilder()
                        .setLocation("memory:///foo")
                        .build());
        assertThat(deleted).isFalse();
    }

    @Test
    @SuppressWarnings("resource")
    void deleteShouldThrowWhenFileLocationHasInvalidScheme() {
        final FileStorage storage = createStorage();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.delete(
                        FileMetadata.newBuilder()
                                .setLocation("foo:///bar")
                                .build()))
                .withMessage("foo:///bar: Unexpected scheme foo, expected memory");
    }

    private static FileStorage createStorage() {
        return new MemoryFileStorageProvider().create(
                new SmallRyeConfigBuilder().build(),
                ProxySelector.getDefault());
    }

}
