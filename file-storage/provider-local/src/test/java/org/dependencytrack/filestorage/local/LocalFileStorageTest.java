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
package org.dependencytrack.filestorage.local;

import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.ProxySelector;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class LocalFileStorageTest {

    @TempDir
    private Path tempDirPath;

    @Test
    void shouldHaveNameLocal() {
        final var provider = new LocalFileStorageProvider();
        assertThat(provider.name()).isEqualTo("local");
    }

    @Test
    @SuppressWarnings("resource")
    void shouldStoreGetAndDeleteFile() throws Exception {
        final FileStorage storage = createStorage();

        final FileMetadata fileMetadata = storage.store("foo/bar", new ByteArrayInputStream("baz".getBytes()));
        assertThat(fileMetadata).isNotNull();
        assertThat(fileMetadata.getProviderName()).isEqualTo("local");
        assertThat(fileMetadata.getLocation()).isEqualTo("local:///foo/bar");
        assertThat(fileMetadata.getMediaType()).isEqualTo("application/octet-stream");
        assertThat(fileMetadata.getSha256Digest()).isEqualTo("018e647e32f8c2b320b731ddd7de9842616209d93a3aeeea985a48b7fe0e5eda");

        assertThat(tempDirPath.resolve("foo/bar")).exists();

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
    void storeShouldThrowWhenFileNameAttemptsTraversal() {
        final FileStorage storage = createStorage();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.store("foo/../../../bar", new ByteArrayInputStream("bar".getBytes())))
                .withMessage("""
                        The provided filePath foo/../../../bar does not resolve to a path \
                        within the configured base directory (%s)""", tempDirPath);
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
    void getShouldThrowWhenFileLocationHasInvalidScheme() {
        final FileStorage storage = createStorage();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.get(
                        FileMetadata.newBuilder()
                                .setLocation("foo:///bar")
                                .build()))
                .withMessage("foo:///bar: Unexpected scheme foo, expected local");
    }

    @Test
    @SuppressWarnings("resource")
    void getShouldThrowWhenFileNameAttemptsTraversal() {
        final FileStorage storage = createStorage();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.get(
                        FileMetadata.newBuilder()
                                .setLocation("local:///foo/../../../bar")
                                .setSha256Digest("some-digest")
                                .build()))
                .withMessage("""
                        The provided filePath foo/../../../bar does not resolve to a path \
                        within the configured base directory (%s)""", tempDirPath);
    }

    @Test
    @SuppressWarnings("resource")
    void getShouldThrowWhenFileDoesNotExist() {
        final FileStorage storage = createStorage();

        assertThatExceptionOfType(NoSuchFileException.class)
                .isThrownBy(() -> storage.get(
                        FileMetadata.newBuilder()
                                .setLocation("local:///foo/bar")
                                .setSha256Digest("some-digest")
                                .build()));
    }

    @Test
    @SuppressWarnings("resource")
    void deleteShouldReturnFalseWhenFileDoesNotExist() throws Exception {
        final FileStorage storage = createStorage();

        final boolean deleted = storage.delete(
                FileMetadata.newBuilder()
                        .setLocation("local:///foo")
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
                .withMessage("foo:///bar: Unexpected scheme foo, expected local");
    }

    @Test
    @SuppressWarnings("resource")
    void shouldDeleteEmptyParentDirectoriesOnDelete() throws Exception {
        final FileStorage storage = createStorage();

        final FileMetadata fileMetadata = storage.store("a/b/c", new ByteArrayInputStream("data".getBytes()));
        assertThat(tempDirPath.resolve("a/b/c")).exists();

        assertThat(storage.delete(fileMetadata)).isTrue();
        assertThat(tempDirPath.resolve("a/b/c")).doesNotExist();
        assertThat(tempDirPath.resolve("a/b")).doesNotExist();
        assertThat(tempDirPath.resolve("a")).doesNotExist();
        assertThat(tempDirPath).exists();
    }

    @Test
    @SuppressWarnings("resource")
    void shouldNotDeleteNonEmptyParentDirectoryOnDelete() throws Exception {
        final FileStorage storage = createStorage();

        final FileMetadata fileMetadataC = storage.store("a/b/c", new ByteArrayInputStream("data".getBytes()));
        storage.store("a/b/d", new ByteArrayInputStream("data".getBytes()));

        assertThat(storage.delete(fileMetadataC)).isTrue();
        assertThat(tempDirPath.resolve("a/b/c")).doesNotExist();
        assertThat(tempDirPath.resolve("a/b")).exists();
        assertThat(tempDirPath.resolve("a/b/d")).exists();
    }

    @Test
    @SuppressWarnings("resource")
    void shouldNotDeleteBaseDirOnDelete() throws Exception {
        final FileStorage storage = createStorage();

        final FileMetadata fileMetadata = storage.store("foo", new ByteArrayInputStream("data".getBytes()));
        assertThat(storage.delete(fileMetadata)).isTrue();
        assertThat(tempDirPath).exists();
    }

    @Test
    @SuppressWarnings("resource")
    void shouldHandleConcurrentStoreAndDelete() {
        final FileStorage storage = createStorage();

        final int threads = 8;
        final int iterations = 50;
        final var barrier = new CyclicBarrier(threads);

        try (final ExecutorService executor = Executors.newFixedThreadPool(threads)) {
            final var futures = new ArrayList<Future<?>>();
            for (int t = 0; t < threads; t++) {
                final int threadId = t;
                futures.add(executor.submit(() -> {
                    barrier.await();
                    for (int i = 0; i < iterations; i++) {
                        final String fileName = "shared/dir/%d-%d".formatted(threadId, i);
                        final FileMetadata metadata = storage.store(fileName, new ByteArrayInputStream("foo".getBytes()));
                        storage.delete(metadata);
                    }

                    return null;
                }));
            }

            assertThatNoException().isThrownBy(() -> {
                for (final Future<?> future : futures) {
                    future.get();
                }
            });
        }

        assertThat(tempDirPath).exists();
    }

    private FileStorage createStorage() {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.of("dt.file-storage.local.directory", tempDirPath.toAbsolutePath().toString()))
                .build();
        return new LocalFileStorageProvider().create(config, ProxySelector.getDefault());
    }

}
