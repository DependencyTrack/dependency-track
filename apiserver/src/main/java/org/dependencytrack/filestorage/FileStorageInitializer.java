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
package org.dependencytrack.filestorage;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.common.ProxySelector;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.api.FileStorageProvider;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ServiceLoader;

/**
 * @since 5.0.0
 */
public final class FileStorageInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(FileStorageInitializer.class);

    private final Config config;
    private @Nullable FileStorage fileStorage;

    FileStorageInitializer(Config config) {
        this.config = config;
    }

    @SuppressWarnings("unused") // Used by servlet container.
    public FileStorageInitializer() {
        this(ConfigProvider.getConfig());
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        final String providerName = config.getValue(ConfigKeys.FILE_STORAGE_PROVIDER, String.class);
        LOGGER.info("Initializing file storage for provider '{}'", providerName);

        final FileStorageProvider fileStorageProvider =
                ServiceLoader.load(FileStorageProvider.class).stream()
                        .map(ServiceLoader.Provider::get)
                        .filter(provider -> providerName.equals(provider.name()))
                        .findAny()
                        .orElseThrow(() -> new IllegalStateException(
                                "No file storage provider found for name: " + providerName));

        fileStorage = fileStorageProvider.create(config, new ProxySelector());
        event.getServletContext().setAttribute(
                FileStorage.class.getName(),
                fileStorage);
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        if (fileStorage != null) {
            LOGGER.info("Closing file storage");
            try {
                fileStorage.close();
            } catch (IOException e) {
                LOGGER.warn("Failed to close file storage", e);
            }
            fileStorage = null;
        }
    }

}
