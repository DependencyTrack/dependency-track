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
package org.dependencytrack.notification.publishing;

import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import org.dependencytrack.notification.api.TestNotificationFactory;
import org.dependencytrack.notification.api.publishing.NotificationPublishContext;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.api.templating.NotificationTemplateRenderer;
import org.dependencytrack.notification.proto.v1.Group;
import org.dependencytrack.notification.proto.v1.Level;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.Scope;
import org.dependencytrack.notification.templating.pebble.PebbleNotificationTemplateRendererFactory;
import org.dependencytrack.plugin.api.MutableServiceRegistry;
import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.config.RuntimeConfigMapper;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThatNoException;

public abstract class AbstractNotificationPublisherTest {

    private static final String NOTIFICATION_ID = "010ba7f2-ab4a-73b6-a87d-7b9041d17016";
    private static final Timestamp NOTIFICATION_TIMESTAMP = Timestamps.fromMillis(1149573966666L);

    protected NotificationPublisherFactory publisherFactory;
    protected NotificationPublisher publisher;
    protected NotificationPublishContext publishContext;

    protected abstract NotificationPublisherFactory createPublisherFactory();

    protected void customizeDeploymentConfig(Map<String, String> deploymentConfig) {
    }

    protected void customizeGlobalConfig(RuntimeConfig globalConfig) {
    }

    protected void customizeRuleConfig(RuntimeConfig ruleConfig) {
    }

    @BeforeEach
    protected void beforeEach() throws Exception {
        publisherFactory = createPublisherFactory();

        final var deploymentConfig = new HashMap<String, String>();
        customizeDeploymentConfig(deploymentConfig);

        RuntimeConfig globalConfig = null;
        final RuntimeConfigSpec globalConfigSpec = publisherFactory instanceof RuntimeConfigurable rc
                ? rc.runtimeConfigSpec()
                : null;
        if (globalConfigSpec != null) {
            globalConfig = globalConfigSpec.defaultConfig();
            customizeGlobalConfig(globalConfig);
        }

        final var configRegistry = new MockConfigRegistry(
                deploymentConfig,
                globalConfigSpec,
                RuntimeConfigMapper.getInstance(),
                globalConfig);

        publisherFactory.init(
                new MutableServiceRegistry()
                        .register(ConfigRegistry.class, configRegistry)
                        .register(HttpClient.class, HttpClient.newHttpClient()));
        publisher = publisherFactory.create();

        final var templateRendererFactory =
                new PebbleNotificationTemplateRendererFactory(
                        Map.of("baseUrl", () -> "https://example.com"));
        final NotificationTemplateRenderer templateRenderer =
                templateRendererFactory.createRenderer(
                        publisherFactory.defaultTemplate());

        RuntimeConfig ruleConfig = null;

        final RuntimeConfigSpec ruleConfigSpec = publisherFactory.ruleConfigSpec();
        if (ruleConfigSpec != null) {
            ruleConfig = ruleConfigSpec.defaultConfig();
            customizeRuleConfig(ruleConfig);
        }

        publishContext = new NotificationPublishContext(ruleConfig, templateRenderer);
    }

    @AfterEach
    protected void afterEach() {
        if (publisher != null) {
            publisher.close();
        }
        if (publisherFactory != null) {
            publisherFactory.close();
        }
    }

    @ParameterizedTest
    @MethodSource("testNotificationPublishArguments")
    void testNotificationPublish(Notification notification) throws Exception {
        assertThatNoException()
                .isThrownBy(() -> publisher.publish(publishContext, notification));

        validateNotificationPublish(notification);
    }

    protected abstract void validateNotificationPublish(Notification notification) throws Exception;

    private static Stream<Arguments> testNotificationPublishArguments() {
        final var notifications = new ArrayList<Notification>();

        for (final var scope : Scope.values()) {
            for (final var group : Group.values()) {
                for (final var level : Level.values()) {
                    final Notification notification =
                            TestNotificationFactory.createTestNotification(scope, group, level);
                    if (notification != null) {
                        notifications.add(notification);
                    }
                }
            }
        }

        return notifications.stream()
                // Ensure notification data is deterministic.
                .map(notification -> notification.toBuilder()
                        .setId(NOTIFICATION_ID)
                        .setTimestamp(NOTIFICATION_TIMESTAMP)
                        .build())
                .map(Arguments::of);
    }

}
