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
package org.dependencytrack.notification;

import io.micrometer.core.instrument.Metrics;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.filestorage.api.FileStorage;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public final class NotificationSubsystemInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationSubsystemInitializer.class);

    private final Config config = ConfigProvider.getConfig();
    private @Nullable NotificationOutboxRelay relay;

    @Override
    public void contextInitialized(ServletContextEvent event) {
        if (!config.getValue(ConfigKeys.NOTIFICATION_OUTBOX_RELAY_ENABLED, boolean.class)) {
            LOGGER.info("Not starting outbox relay because it is disabled");
            return;
        }

        final ServletContext servletContext = event.getServletContext();

        final var fileStorage = (FileStorage) servletContext.getAttribute(FileStorage.class.getName());
        requireNonNull(fileStorage, "fileStorage has not been initialized");

        final var dexEngine = (DexEngine) servletContext.getAttribute(DexEngine.class.getName());
        requireNonNull(dexEngine, "dexEngine has not been initialized");

        LOGGER.info("Starting outbox relay");
        relay = new NotificationOutboxRelay(
                dexEngine,
                fileStorage,
                handle -> new NotificationRouter(handle, Metrics.globalRegistry),
                Metrics.globalRegistry,
                config.getValue(ConfigKeys.NOTIFICATION_OUTBOX_RELAY_POLL_INTERVAL_MS, long.class),
                config.getValue(ConfigKeys.NOTIFICATION_OUTBOX_RELAY_BATCH_SIZE, int.class),
                config.getValue(ConfigKeys.NOTIFICATION_OUTBOX_RELAY_LARGE_NOTIFICATION_THRESHOLD_BYTES, int.class));
        relay.start();
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        if (relay != null) {
            LOGGER.info("Stopping outbox relay");
            relay.close();
        }
    }
}
