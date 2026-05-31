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

import com.github.luben.zstd.Zstd;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.api.FileStorageProvider;
import org.eclipse.microprofile.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.ProxySelector;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * @since 5.0.0
 */
public final class LocalFileStorageProvider implements FileStorageProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(LocalFileStorageProvider.class);
    static final String NAME = "local";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public FileStorage create(Config config, ProxySelector proxySelector) {
        final Path directoryPath = config.getValue("dt.file-storage.local.directory", Path.class);

        try {
            Files.createDirectories(directoryPath);
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Failed to create directory for file storage at %s".formatted(directoryPath), e);
        }

        final boolean canRead = directoryPath.toFile().canRead();
        final boolean canWrite = directoryPath.toFile().canWrite();
        if (!canRead || !canWrite) {
            throw new IllegalStateException(
                    "Insufficient permissions for directory %s (canRead=%s, canWrite=%s)".formatted(
                            directoryPath, canRead, canWrite));
        }

        final int compressionLevel = config
                .getOptionalValue("dt.file-storage.local.compression-level", int.class)
                .orElse(5);
        if (compressionLevel < Zstd.minCompressionLevel() || compressionLevel > Zstd.maxCompressionLevel()) {
            throw new IllegalStateException(
                    "Invalid compression level: must be between %d and %d, but is %d".formatted(
                            Zstd.minCompressionLevel(),
                            Zstd.maxCompressionLevel(),
                            compressionLevel));
        }

        LOGGER.debug("Files will be stored in {}", directoryPath);
        return new LocalFileStorage(directoryPath, compressionLevel);
    }

}
