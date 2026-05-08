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

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.api.templating.NotificationTemplate;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.jdbi.v3.core.statement.PreparedBatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

/**
 * @since 5.0.0
 */
public final class DefaultNotificationPublisherInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultNotificationPublisherInitializer.class);

    @Override
    public void contextInitialized(ServletContextEvent event) {
        final var pluginManager = (PluginManager) event.getServletContext().getAttribute(PluginManager.class.getName());
        requireNonNull(pluginManager, "pluginManager has not been initialized");

        seedDefaultPublishers(pluginManager);
    }

    public void seedDefaultPublishers(PluginManager pluginManager) {
        final Collection<NotificationPublisherFactory> extensionFactories =
                pluginManager.getFactories(NotificationPublisher.class);
        if (extensionFactories.isEmpty()) {
            return;
        }

        final var publishers = new ArrayList<org.dependencytrack.model.NotificationPublisher>(extensionFactories.size());
        for (final var extensionFactory : extensionFactories) {
            final var publisher = new org.dependencytrack.model.NotificationPublisher();
            publisher.setName(StringUtils.capitalize(extensionFactory.extensionName()));
            publisher.setDescription("Default %s publisher".formatted(publisher.getName()));
            publisher.setExtensionName(extensionFactory.extensionName());
            publisher.setDefaultPublisher(true);

            final NotificationTemplate template = extensionFactory.defaultTemplate();
            if (template != null) {
                publisher.setTemplate(template.content());
                publisher.setTemplateMimeType(template.mimeType());
            }

            publishers.add(publisher);
        }

        createPublishers(publishers);
    }

    private void createPublishers(Collection<org.dependencytrack.model.NotificationPublisher> publishers) {
        useJdbiTransaction(handle -> {
            final PreparedBatch preparedBatch = handle.prepareBatch("""
                    INSERT INTO "NOTIFICATIONPUBLISHER" (
                      "NAME"
                    , "EXTENSION_NAME"
                    , "DEFAULT_PUBLISHER"
                    , "DESCRIPTION"
                    , "TEMPLATE"
                    , "TEMPLATE_MIME_TYPE"
                    , "UUID"
                    )
                    VALUES (
                      :name
                    , :extensionName
                    , :defaultPublisher
                    , :description
                    , :template
                    , :templateMimeType
                    , GEN_RANDOM_UUID()
                    )
                    ON CONFLICT ("NAME") DO UPDATE
                    SET "EXTENSION_NAME" = EXCLUDED."EXTENSION_NAME"
                      , "DESCRIPTION" = EXCLUDED."DESCRIPTION"
                      , "TEMPLATE" = EXCLUDED."TEMPLATE"
                      , "TEMPLATE_MIME_TYPE" =  EXCLUDED."TEMPLATE_MIME_TYPE"
                    -- Only update when at least one relevant field has changed.
                    WHERE "NOTIFICATIONPUBLISHER"."EXTENSION_NAME" IS DISTINCT FROM EXCLUDED."EXTENSION_NAME"
                       OR "NOTIFICATIONPUBLISHER"."DESCRIPTION" IS DISTINCT FROM EXCLUDED."DESCRIPTION"
                       OR "NOTIFICATIONPUBLISHER"."TEMPLATE" IS DISTINCT FROM EXCLUDED."TEMPLATE"
                       OR "NOTIFICATIONPUBLISHER"."TEMPLATE_MIME_TYPE" IS DISTINCT FROM EXCLUDED."TEMPLATE_MIME_TYPE"
                    """);

            for (final var publisher : publishers) {
                preparedBatch
                        .bindBean(publisher)
                        .add();
            }

            final int publishersCreatedOrUpdated = Arrays.stream(preparedBatch.execute()).sum();
            LOGGER.debug("Created or updated {} publishers", publishersCreatedOrUpdated);
        });
    }

}
