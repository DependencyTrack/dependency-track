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
package org.dependencytrack.notification.publishing.email;

import com.icegreen.greenmail.junit5.GreenMailExtension;
import com.icegreen.greenmail.util.DummySSLSocketFactory;
import com.icegreen.greenmail.util.ServerSetup;
import org.dependencytrack.notification.api.TestNotificationFactory;
import org.dependencytrack.notification.api.publishing.NotificationPublishContext;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.templating.NotificationTemplateRenderer;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.templating.pebble.PebbleNotificationTemplateRendererFactory;
import org.dependencytrack.plugin.api.MutableServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.config.RuntimeConfigMapper;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.Map;
import java.util.Set;

import static com.icegreen.greenmail.configuration.GreenMailConfiguration.aConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

class EmailNotificationPublisherTlsTest {

    @RegisterExtension
    private static final GreenMailExtension GREEN_MAIL =
            new GreenMailExtension(ServerSetup.SMTPS.dynamicPort())
                    .withConfiguration(aConfig().withUser("username", "password"));

    private EmailNotificationPublisherFactory publisherFactory;
    private NotificationPublisher publisher;
    private NotificationPublishContext publishContext;

    @BeforeEach
    void beforeEach() {
        publisherFactory =
                new EmailNotificationPublisherFactory(
                        Map.of("mail.smtp.ssl.checkserveridentity", "false"),
                        DummySSLSocketFactory.class);

        final var emailGlobalConfig = (EmailNotificationPublisherGlobalConfigV1)
                publisherFactory.runtimeConfigSpec().defaultConfig();
        emailGlobalConfig.setEnabled(true);
        emailGlobalConfig.setHost(GREEN_MAIL.getSmtps().getBindTo());
        emailGlobalConfig.setPort(GREEN_MAIL.getSmtps().getPort());
        emailGlobalConfig.setSslEnabled(true);
        emailGlobalConfig.setUsername("username");
        emailGlobalConfig.setPassword("password");
        emailGlobalConfig.setSenderAddress("dependencytrack@example.com");

        final var configRegistry = new MockConfigRegistry(
                Map.of("allow-local-connections", "true"),
                publisherFactory.runtimeConfigSpec(),
                RuntimeConfigMapper.getInstance(),
                emailGlobalConfig);

        publisherFactory.init(new MutableServiceRegistry().register(ConfigRegistry.class, configRegistry));
        publisher = publisherFactory.create();

        final var templateRendererFactory =
                new PebbleNotificationTemplateRendererFactory(
                        Map.of("baseUrl", () -> "https://example.com"));
        final NotificationTemplateRenderer templateRenderer =
                templateRendererFactory.createRenderer(
                        publisherFactory.defaultTemplate());

        final var emailRuleConfig = (EmailNotificationPublisherRuleConfigV1)
                publisherFactory.ruleConfigSpec().defaultConfig();
        emailRuleConfig.setRecipientAddresses(Set.of("username@example.com"));

        publishContext = new NotificationPublishContext(emailRuleConfig, templateRenderer);
    }

    @AfterEach
    void afterEach() {
        if (publisher != null) {
            publisher.close();
        }
        if (publisherFactory != null) {
            publisherFactory.close();
        }
    }

    @Test
    void test() {
        final Notification notification = TestNotificationFactory.createBomConsumedTestNotification();

        assertThatNoException()
                .isThrownBy(() -> publisher.publish(publishContext, notification));

        assertThat(GREEN_MAIL.getReceivedMessages()).hasSize(1);
    }

}
