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
package org.dependencytrack.secret;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.common.pagination.SimplePageTokenEncoder;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.secret.management.SecretManagerProvider;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ServiceLoader;

/**
 * @since 5.0.0
 */
public final class SecretManagerInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecretManagerInitializer.class);

    private final Config config;
    static @Nullable SecretManager secretManager;

    SecretManagerInitializer(final Config config) {
        this.config = config;
    }

    @SuppressWarnings("unused")
    public SecretManagerInitializer() {
        this(ConfigProvider.getConfig());
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        final String providerName = config.getValue(ConfigKeys.SECRET_MANAGEMENT_PROVIDER, String.class);
        LOGGER.info("Initializing secret manager for provider '{}'", providerName);

        final var secretManagerProvider =
                ServiceLoader.load(SecretManagerProvider.class).stream()
                        .map(ServiceLoader.Provider::get)
                        .filter(factory -> providerName.equals(factory.name()))
                        .findAny()
                        .orElseThrow(() -> new IllegalStateException(
                                "No secret management provider found for name: " + providerName));

        secretManager = secretManagerProvider.create(config, new SimplePageTokenEncoder());

        event.getServletContext().setAttribute(
                SecretManager.class.getName(),
                secretManager);
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        if (secretManager != null) {
            LOGGER.info("Closing secret manager");
            secretManager.close();
            secretManager = null;
        }
    }

}
