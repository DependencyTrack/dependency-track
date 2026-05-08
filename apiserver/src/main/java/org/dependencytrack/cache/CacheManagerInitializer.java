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
package org.dependencytrack.cache;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.api.CacheProvider;
import org.dependencytrack.common.ConfigKeys;
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
public final class CacheManagerInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(CacheManagerInitializer.class);

    private final Config config;
    private @Nullable CacheManager cacheManager;

    CacheManagerInitializer(Config config) {
        this.config = config;
    }

    @SuppressWarnings("unused") // Used by servlet container.
    public CacheManagerInitializer() {
        this(ConfigProvider.getConfig());
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        final String providerName = config.getValue(ConfigKeys.CACHE_PROVIDER, String.class);
        LOGGER.info("Initializing cache manager for provider '{}'", providerName);

        final CacheProvider cacheProvider =
                ServiceLoader.load(CacheProvider.class).stream()
                        .map(ServiceLoader.Provider::get)
                        .filter(factory -> providerName.equals(factory.name()))
                        .findAny()
                        .orElseThrow(() -> new IllegalStateException(
                                "No cache provider found for name: " + providerName));

        cacheManager = cacheProvider.create();
        event.getServletContext().setAttribute(
                CacheManager.class.getName(),
                cacheManager);
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        if (cacheManager != null) {
            LOGGER.info("Closing cache manager");
            try {
                cacheManager.close();
            } catch (IOException e) {
                LOGGER.warn("Failed to close cache manager", e);
            }
            cacheManager = null;
        }
    }

}
