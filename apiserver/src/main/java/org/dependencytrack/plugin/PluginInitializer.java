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
package org.dependencytrack.plugin;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.common.HttpClient;
import org.dependencytrack.kevdatasource.api.KevDataSource;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.plugin.api.Plugin;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.List;
import java.util.ServiceLoader;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public class PluginInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(PluginInitializer.class);

    private final Config config;
    private @Nullable PluginManager pluginManager;

    PluginInitializer(Config config) {
        this.config = config;
    }

    @SuppressWarnings("unused") // Used by servlet container.
    public PluginInitializer() {
        this(ConfigProvider.getConfig());
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        LOGGER.info("Initializing plugin system");

        final var cacheManager = (CacheManager) event.getServletContext().getAttribute(CacheManager.class.getName());
        requireNonNull(cacheManager, "cacheManager has not been initialized");

        final var secretManager = (SecretManager) event.getServletContext().getAttribute(SecretManager.class.getName());
        requireNonNull(secretManager, "secretManager has not been initialized");

        final var extensionPoints = List.of(
                KevDataSource.class,
                NotificationPublisher.class,
                PackageMetadataResolver.class,
                VulnAnalyzer.class,
                VulnDataSource.class);

        pluginManager = new PluginManager(
                config,
                cacheManager,
                secretManager::getSecretValue,
                JdbiFactory.createJdbi(),
                HttpClient.INSTANCE,
                extensionPoints);

        LOGGER.info("Discovering plugins");
        final Collection<Plugin> plugins =
                ServiceLoader.load(Plugin.class).stream()
                        .map(ServiceLoader.Provider::get)
                        .toList();
        for (final Plugin plugin : plugins) {
            LOGGER.debug("Discovered plugin {}", plugin.getClass().getName());
        }

        LOGGER.info("Loading plugins");
        pluginManager.loadPlugins(plugins);

        event.getServletContext().setAttribute(PluginManager.class.getName(), pluginManager);
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        if (pluginManager != null) {
            LOGGER.info("Closing plugin manager");
            pluginManager.close();
        }

        event.getServletContext().removeAttribute(PluginManager.class.getName());
    }

}
