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
package org.dependencytrack.filestorage.s3;

import com.adobe.testing.s3mock.testcontainers.S3MockContainer;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.ProxySelector;
import java.nio.file.NoSuchFileException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@Testcontainers
class S3FileStorageTest {

    @Container
    private static final S3MockContainer s3MockContainer =
            new S3MockContainer("5.0.0")
                    .withInitialBuckets("test");

    @Test
    void shouldHaveNameS3() {
        final var provider = new S3FileStorageProvider();
        assertThat(provider.name()).isEqualTo("s3");
    }

    @Test
    void shouldThrowWhenBucketDoesNotExist() {
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> createStorage(Map.ofEntries(
                        Map.entry("dt.file-storage.s3.endpoint", s3MockContainer.getHttpEndpoint()),
                        Map.entry("dt.file-storage.s3.access-key", "foo"),
                        Map.entry("dt.file-storage.s3.secret-key", "bar"),
                        Map.entry("dt.file-storage.s3.bucket", "does-not-exist"))))
                .withMessage("Bucket does-not-exist does not exist");
    }

    @Test
    void shouldThrowWhenBucketExistenceCheckFailed() {
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> createStorage(Map.ofEntries(
                        Map.entry("dt.file-storage.s3.endpoint", "http://localhost:1"),
                        Map.entry("dt.file-storage.s3.access-key", "foo"),
                        Map.entry("dt.file-storage.s3.secret-key", "bar"),
                        Map.entry("dt.file-storage.s3.bucket", "does-not-exist"),
                        Map.entry("dt.file-storage.s3.connect-timeout-ms", "500"))))
                .withMessage("Failed to determine if bucket does-not-exist exists");
    }

    @Test
    void shouldStoreAndGetAndDeleteFile() throws Exception {
        try (final FileStorage storage = createStorage()) {
            final FileMetadata fileMetadata = storage.store("foo/bar", new ByteArrayInputStream("baz".getBytes()));
            assertThat(fileMetadata.getProviderName()).isEqualTo("s3");
            assertThat(fileMetadata.getLocation()).isEqualTo("s3://test/foo/bar");
            assertThat(fileMetadata.getMediaType()).isEqualTo("application/octet-stream");
            assertThat(fileMetadata.getSha256Digest()).isEqualTo("018e647e32f8c2b320b731ddd7de9842616209d93a3aeeea985a48b7fe0e5eda");

            final InputStream fileStream = storage.get(fileMetadata);
            assertThat(fileStream).isNotNull();
            assertThat(fileStream.readAllBytes()).asString().isEqualTo("baz");

            assertThat(storage.delete(fileMetadata)).isTrue();
            assertThatExceptionOfType(NoSuchFileException.class).isThrownBy(() -> storage.get(fileMetadata));
        }
    }

    @Test
    void storeShouldOverwriteExistingFile() throws Exception {
        try (final FileStorage storage = createStorage()) {
            final FileMetadata fileMetadataA = storage.store("foo/bar", new ByteArrayInputStream("baz".getBytes()));
            final FileMetadata fileMetadataB = storage.store("foo/bar", new ByteArrayInputStream("qux".getBytes()));

            assertThat(storage.get(fileMetadataA).readAllBytes()).asString().isEqualTo("qux");
            assertThat(storage.get(fileMetadataB).readAllBytes()).asString().isEqualTo("qux");
        }
    }

    @Test
    void storeShouldThrowWhenFileHasInvalidName() throws Exception {
        try (final FileStorage storage = createStorage()) {
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> storage.store("foo$bar", new ByteArrayInputStream("bar".getBytes())))
                    .withMessage("fileName 'foo$bar' does not match pattern: [a-zA-Z0-9_/\\-.]+");
        }
    }

    @Test
    void getShouldThrowWhenFileDoesNotExist() throws Exception {
        try (final FileStorage storage = createStorage()) {
            assertThatExceptionOfType(NoSuchFileException.class)
                    .isThrownBy(() -> storage.get(
                            FileMetadata.newBuilder()
                                    .setLocation("s3://test/foo/bar")
                                    .setSha256Digest("some-digest")
                                    .build()));
        }
    }

    @Test
    void deleteShouldReturnTrueWhenFileDoesNotExist() throws Exception {
        try (final FileStorage storage = createStorage()) {
            assertThat(storage.delete(
                    FileMetadata.newBuilder()
                            .setLocation("s3://test/foo")
                            .build())).isTrue();
        }
    }

    @Nested
    class WhenHostIsUnavailable {

        @Container
        private final S3MockContainer ephemeralContainer =
                new S3MockContainer("5.0.0")
                        .withInitialBuckets("test");

        @Test
        void storeShouldThrowWhenHostIsUnavailable() throws Exception {
            try (final FileStorage storage = createEphemeralStorage()) {
                ephemeralContainer.stop();

                assertThatExceptionOfType(IOException.class)
                        .isThrownBy(() -> storage.store("foo", new ByteArrayInputStream("bar".getBytes())));
            }
        }

        @Test
        void getShouldThrowWhenHostIsUnavailable() throws Exception {
            try (final FileStorage storage = createEphemeralStorage()) {
                final FileMetadata fileMetadata = storage.store("foo", new ByteArrayInputStream("bar".getBytes()));

                ephemeralContainer.stop();

                assertThatExceptionOfType(IOException.class)
                        .isThrownBy(() -> storage.get(fileMetadata))
                        .withRootCauseInstanceOf(ConnectException.class);
            }
        }

        @Test
        void deleteShouldThrowWhenHostIsUnavailable() throws Exception {
            try (final FileStorage storage = createEphemeralStorage()) {
                final FileMetadata fileMetadata = storage.store("foo", new ByteArrayInputStream("bar".getBytes()));

                ephemeralContainer.stop();

                assertThatExceptionOfType(IOException.class)
                        .isThrownBy(() -> storage.delete(fileMetadata))
                        .withRootCauseInstanceOf(ConnectException.class);
            }
        }

        private FileStorage createEphemeralStorage() {
            return createStorage(Map.ofEntries(
                    Map.entry("dt.file-storage.s3.endpoint", ephemeralContainer.getHttpEndpoint()),
                    Map.entry("dt.file-storage.s3.access-key", "foo"),
                    Map.entry("dt.file-storage.s3.secret-key", "bar"),
                    Map.entry("dt.file-storage.s3.bucket", "test"),
                    Map.entry("dt.file-storage.s3.connect-timeout-ms", "5000"),
                    Map.entry("dt.file-storage.s3.read-timeout-ms", "5000"),
                    Map.entry("dt.file-storage.s3.write-timeout-ms", "5000")));
        }

    }

    private FileStorage createStorage() {
        return createStorage(Map.ofEntries(
                Map.entry("dt.file-storage.s3.endpoint", s3MockContainer.getHttpEndpoint()),
                Map.entry("dt.file-storage.s3.access-key", "foo"),
                Map.entry("dt.file-storage.s3.secret-key", "bar"),
                Map.entry("dt.file-storage.s3.bucket", "test")));
    }

    private static FileStorage createStorage(Map<String, String> configValues) {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValues(configValues)
                .build();
        return new S3FileStorageProvider().create(config, ProxySelector.getDefault());
    }

}
