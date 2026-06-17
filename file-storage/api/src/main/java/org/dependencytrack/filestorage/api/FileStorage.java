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
package org.dependencytrack.filestorage.api;

import org.dependencytrack.filestorage.proto.v1.FileMetadata;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.NoSuchFileException;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public interface FileStorage extends Closeable {

    String name();

    Pattern VALID_NAME_PATTERN = Pattern.compile("[a-zA-Z0-9_/\\-.]+");

    /**
     * Persist data to a file in storage.
     * <p>
     * Implementations may transparently perform additional steps,
     * such as encryption and compression.
     *
     * @param fileName      Name of the file. This fileName is not guaranteed to be reflected
     *                      in storage as-is. It may be modified or changed entirely.
     * @param mediaType     Media type of the file.
     * @param contentStream Data stream to store.
     * @return Metadata of the stored file.
     * @throws IOException When storing the file failed.
     * @see <a href="https://www.iana.org/assignments/media-types/media-types.xhtml">IANA Media Types</a>
     */
    FileMetadata store(String fileName, String mediaType, InputStream contentStream) throws IOException;

    /**
     * Persist data to a file in storage, assuming the media type to be {@code application/octet-stream}.
     *
     * @see #store(String, String, InputStream)
     */
    default FileMetadata store(String fileName, InputStream contentStream) throws IOException {
        return store(fileName, "application/octet-stream", contentStream);
    }

    /**
     * Retrieves a file from storage.
     * <p>
     * Implementations may transparently perform additional steps,
     * such as integrity verification, decryption and decompression.
     * <p>
     * Trying to retrieve a file from a different storage implementation
     * is an illegal operation and yields an exception.
     *
     * @param fileMetadata Metadata of the file to retrieve.
     * @return The file's content stream.
     * @throws IOException         When retrieving the file failed.
     * @throws NoSuchFileException When the requested file was not found.
     */
    InputStream get(FileMetadata fileMetadata) throws IOException;

    /**
     * Deletes a file from storage.
     * <p>
     * Trying to delete a file from a different storage implementation
     * is an illegal operation and yields an exception.
     *
     * @param fileMetadata Metadata of the file to delete.
     * @return {@code true} when the file was deleted, otherwise {@code false}.
     * @throws IOException When deleting the file failed.
     */
    boolean delete(FileMetadata fileMetadata) throws IOException;

    // TODO: deleteMany. Some remote storage backends support batch deletes.
    //  https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjects.html

    @Override
    default void close() throws IOException {
    }

    static void requireValidFileName(String fileName) {
        requireNonNull(fileName, "fileName must not be null");

        if (!VALID_NAME_PATTERN.matcher(fileName).matches()) {
            throw new IllegalArgumentException(
                    "fileName '%s' does not match pattern: %s".formatted(
                            fileName, VALID_NAME_PATTERN.pattern()));
        }
    }

}
