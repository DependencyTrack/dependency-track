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

import com.fasterxml.jackson.databind.JsonNode;
import org.dependencytrack.common.MdcScope;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.ApplicationFailureException;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.notification.api.publishing.NotificationPublishContext;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.api.publishing.RetryablePublishException;
import org.dependencytrack.notification.api.templating.NotificationTemplate;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.templating.pebble.PebbleNotificationTemplateRendererFactory;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.config.RuntimeConfigMapper;
import org.dependencytrack.plugin.config.UnresolvableSecretException;
import org.dependencytrack.plugin.runtime.NoSuchExtensionException;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.PublishNotificationActivityArg;
import org.jdbi.v3.core.statement.Query;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.NoSuchFileException;
import java.util.Map;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.common.MdcKeys.MDC_NOTIFICATION_ID;
import static org.dependencytrack.common.MdcKeys.MDC_NOTIFICATION_RULE_NAME;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.0.0
 */
@ActivitySpec(name = "publish-notification", defaultTaskQueue = "notifications")
public final class PublishNotificationActivity implements Activity<PublishNotificationActivityArg, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(PublishNotificationActivity.class);

    private final PluginManager pluginManager;
    private final FileStorage fileStorage;
    private final RuntimeConfigMapper configMapper;
    private final Function<String, @Nullable String> secretResolver;
    private final PebbleNotificationTemplateRendererFactory notificationTemplateRendererFactory;

    public PublishNotificationActivity(
            PluginManager pluginManager,
            FileStorage fileStorage,
            Function<String, @Nullable String> secretResolver,
            PebbleNotificationTemplateRendererFactory notificationTemplateRendererFactory) {
        this.pluginManager = pluginManager;
        this.fileStorage = fileStorage;
        this.configMapper = RuntimeConfigMapper.getInstance();
        this.secretResolver = secretResolver;
        this.notificationTemplateRendererFactory = notificationTemplateRendererFactory;
    }

    @Override
    public @Nullable Void execute(
            ActivityContext ctx,
            @Nullable PublishNotificationActivityArg argument) {
        if (argument == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        try (var _ = new MdcScope(Map.ofEntries(
                Map.entry(MDC_NOTIFICATION_ID, argument.getNotificationId()),
                Map.entry(MDC_NOTIFICATION_RULE_NAME, argument.getNotificationRuleName())))) {
            final RuleMetadata ruleMetadata = getRuleMetadata(argument.getNotificationRuleName());
            if (ruleMetadata == null) {
                throw new TerminalApplicationFailureException(
                        "Notification rule '%s' does not exist".formatted(argument.getNotificationRuleName()));
            }

            final NotificationPublisherFactory publisherFactory;
            try {
                publisherFactory = pluginManager.getFactory(NotificationPublisher.class, ruleMetadata.extensionName());
            } catch (NoSuchExtensionException e) {
                throw new TerminalApplicationFailureException(e);
            }

            final Notification notification = getNotification(argument);

            final String templateContent = ruleMetadata.template();
            final var template = templateContent != null
                    ? new NotificationTemplate(
                            templateContent,
                            requireNonNull(
                                    ruleMetadata.templateMimeType(),
                                    "templateMimeType must not be null when template is set"))
                    : null;

            final var publishCtx = new NotificationPublishContext(
                    getRuleConfig(publisherFactory.ruleConfigSpec(), ruleMetadata.publisherConfig()),
                    new NotificationRuleContactsSupplier(argument.getNotificationRuleName()),
                    notificationTemplateRendererFactory.createRenderer(template));

            LOGGER.debug("Publishing notification");
            try (final NotificationPublisher publisher = publisherFactory.create()) {
                publisher.publish(publishCtx, notification);

                if (shouldLogSuccessfulPublish(ruleMetadata.logSuccessfulPublish(), argument.getRuleTest())) {
                    LOGGER.info("Notification published successfully");
                }
            } catch (RuntimeException | IOException e) {
                if (e instanceof final RetryablePublishException rpe) {
                    throw new ApplicationFailureException(
                            "Failed to publish notification with retryable cause", rpe, rpe.retryAfter());
                }

                throw new TerminalApplicationFailureException(
                        "Failed to publish notification with non-retryable cause", e);
            }
        }

        return null;
    }

    static boolean shouldLogSuccessfulPublish(final boolean logSuccessfulPublish, final boolean ruleTest) {
        return logSuccessfulPublish || ruleTest;
    }

    private record RuleMetadata(
            String extensionName,
            @Nullable String publisherConfig,
            @Nullable String template,
            @Nullable String templateMimeType,
            boolean logSuccessfulPublish) {
    }

    private @Nullable RuleMetadata getRuleMetadata(String ruleName) {
        return withJdbiHandle(handle -> {
            final Query query = handle.createQuery("""
                    SELECT p."EXTENSION_NAME"
                         , r."PUBLISHER_CONFIG"
                         , p."TEMPLATE"
                         , p."TEMPLATE_MIME_TYPE"
                         , r."LOG_SUCCESSFUL_PUBLISH"
                      FROM "NOTIFICATIONRULE" AS r
                     INNER JOIN "NOTIFICATIONPUBLISHER" AS p
                        ON p."ID" = r."PUBLISHER"
                     WHERE r."NAME" = :ruleName
                    """);

            return query
                    .bind("ruleName", ruleName)
                    .map((rs, ctx) -> new RuleMetadata(
                            rs.getString(1),
                            rs.getString(2),
                            rs.getString(3),
                            rs.getString(4),
                            rs.getBoolean(5)))
                    .findOne()
                    .orElse(null);
        });
    }

    private Notification getNotification(PublishNotificationActivityArg argument) {
        if (argument.hasNotification()) {
            return argument.getNotification();
        } else if (argument.hasNotificationFileMetadata()) {
            final FileMetadata fileMetadata = argument.getNotificationFileMetadata();
            LOGGER.debug("Retrieving notification from {}", fileMetadata.getLocation());

            try (final InputStream fileInputStream = fileStorage.get(argument.getNotificationFileMetadata())) {
                return Notification.parseFrom(fileInputStream);
            } catch (NoSuchFileException e) {
                throw new TerminalApplicationFailureException("Notification file not found", e);
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to get notification file", e);
            }
        }

        throw new TerminalApplicationFailureException("No notification found");
    }

    private @Nullable RuntimeConfig getRuleConfig(
            @Nullable RuntimeConfigSpec configSpec,
            @Nullable String configJson) {
        if (configSpec == null) {
            // Publisher doesn't support rule-level configuration.
            return null;
        }
        if (configJson == null) {
            throw new TerminalApplicationFailureException("""
                    Notification rule does not specify a publisher configuration, \
                    but the publisher requires one""");
        }

        final RuntimeConfig config;
        try {
            final JsonNode configJsonNode = configMapper.validateJson(configJson, configSpec);

            configMapper.resolveSecretRefs(configJsonNode, configSpec, secretResolver);

            config = configMapper.convert(configJsonNode, configSpec.configClass());

            if (configSpec.validator() != null) {
                configSpec.validator().validate(config);
            }
        } catch (InvalidRuntimeConfigException e) {
            throw new TerminalApplicationFailureException(
                    "Publisher configuration of the notification rule is invalid", e);
        } catch (UnresolvableSecretException e) {
            throw new TerminalApplicationFailureException(
                    "Publisher configuration references an unresolvable secret", e);
        }

        return config;
    }

}
