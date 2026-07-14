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

import com.github.luben.zstd.ZstdInputStream;
import com.github.luben.zstd.ZstdOutputStream;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.filestorage.api.FileStorage.requireValidFileName;

/**
 * @since 5.0.0
 */
final class LocalFileStorage implements FileStorage {

    private static final Logger LOGGER = LoggerFactory.getLogger(LocalFileStorage.class);

    private final Path baseDirPath;
    private final int compressionLevel;

    LocalFileStorage(Path baseDirPath, int compressionLevel) {
        this.baseDirPath = baseDirPath;
        this.compressionLevel = compressionLevel;
    }

    @Override
    public String name() {
        return LocalFileStorageProvider.NAME;
    }

    @Override
    public FileMetadata store(String fileName, String mediaType, InputStream contentStream) throws IOException {
        requireValidFileName(fileName);
        requireNonNull(contentStream, "contentStream must not be null");

        final Path filePath = resolveFilePath(fileName);
        if (Files.isDirectory(filePath)) {
            throw new IOException("Path %s exists, but is a directory".formatted(fileName));
        }

        final Path relativeFilePath = baseDirPath.relativize(filePath);
        final URI locationUri = URI.create(
                "%s:///%s".formatted(
                        LocalFileStorageProvider.NAME,
                        relativeFilePath.toString().replace(relativeFilePath.getFileSystem().getSeparator(), "/")));

        final MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        try (final var fileOutputStream = openOutputStream(filePath);
             final var bufferedOutputStream = new BufferedOutputStream(fileOutputStream);
             final var digestOutputStream = new DigestOutputStream(bufferedOutputStream, messageDigest);
             final var zstdOutputStream = new ZstdOutputStream(digestOutputStream, compressionLevel)) {
            contentStream.transferTo(zstdOutputStream);
        }

        return FileMetadata.newBuilder()
                .setProviderName(LocalFileStorageProvider.NAME)
                .setLocation(locationUri.toString())
                .setMediaType(mediaType)
                .setSha256Digest(HexFormat.of().formatHex(messageDigest.digest()))
                .build();
    }

    @Override
    public InputStream get(FileMetadata fileMetadata) throws IOException {
        requireNonNull(fileMetadata, "fileMetadata must not be null");

        final Path filePath = resolveFilePath(fileMetadata);

        return new ZstdInputStream(Files.newInputStream(filePath, StandardOpenOption.READ));
    }

    @Override
    public boolean delete(FileMetadata fileMetadata) throws IOException {
        requireNonNull(fileMetadata, "fileMetadata must not be null");

        final Path filePath = resolveFilePath(fileMetadata);

        final boolean deleted = Files.deleteIfExists(filePath);
        if (deleted) {
            deleteEmptyParentDirectories(filePath.getParent());
        }

        return deleted;
    }

    @SuppressWarnings("BusyWait")
    private OutputStream openOutputStream(Path filePath) throws IOException {
        final long deadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);

        int attempt = 0;
        while (true) {
            try {
                Files.createDirectories(filePath.getParent());
                return Files.newOutputStream(filePath);
            } catch (FileSystemException e) {
                // It's possible that we're trying to create a file in a directory that was
                // deleted by a concurrent deleteEmptyParentDirectories call.
                // Retry up to 5 seconds with an exponential backoff of 1-16ms.
                //
                // Note that we can't use (arguably more correct) file locks here,
                // because the underlying storage may use a network filesystem.

                if (System.nanoTime() >= deadlineNanos) {
                    throw e;
                }

                final long backoffCapMillis = Math.min(16L, 1L << Math.min(attempt++, 4));
                final long backoffMillis = ThreadLocalRandom.current().nextLong(1, backoffCapMillis + 1);

                try {
                    Thread.sleep(backoffMillis);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw e;
                }
            }
        }
    }

    private void deleteEmptyParentDirectories(@Nullable Path dirPath) {
        while (dirPath != null && dirPath.startsWith(baseDirPath) && !dirPath.equals(baseDirPath)) {
            try {
                Files.delete(dirPath);
            } catch (DirectoryNotEmptyException | NoSuchFileException e) {
                break;
            } catch (IOException e) {
                LOGGER.warn("Failed to delete empty directory {}", dirPath, e);
                break;
            }

            dirPath = dirPath.getParent();
        }
    }

    private Path resolveFilePath(String filePath) {
        final Path resolvedFilePath = baseDirPath.resolve(filePath).normalize().toAbsolutePath();
        if (!resolvedFilePath.startsWith(baseDirPath)) {
            throw new IllegalArgumentException("""
                    The provided filePath %s does not resolve to a path within the \
                    configured base directory (%s)""".formatted(filePath, baseDirPath));
        }

        return resolvedFilePath;
    }

    Path resolveFilePath(FileMetadata fileMetadata) {
        final URI locationUri = URI.create(fileMetadata.getLocation());
        if (!LocalFileStorageProvider.NAME.equals(locationUri.getScheme())) {
            throw new IllegalArgumentException("%s: Unexpected scheme %s, expected %s".formatted(
                    locationUri, locationUri.getScheme(), LocalFileStorageProvider.NAME));
        }
        if (locationUri.getHost() != null) {
            throw new IllegalArgumentException(
                    "%s: Host portion is not allowed for scheme %s".formatted(locationUri, LocalFileStorageProvider.NAME));
        }
        if (locationUri.getPath() == null || locationUri.getPath().equals("/")) {
            throw new IllegalArgumentException(
                    "%s: Path portion not set; Unable to determine file name".formatted(locationUri));
        }

        // The value returned by URI#getPath always has a leading slash.
        // Remove it to prevent the path from erroneously be interpreted as absolute.
        return resolveFilePath(locationUri.getPath().replaceFirst("^/", ""));
    }

}
