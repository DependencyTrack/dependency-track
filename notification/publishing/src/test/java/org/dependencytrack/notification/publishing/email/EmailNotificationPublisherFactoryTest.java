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

import org.dependencytrack.notification.publishing.AbstractNotificationPublisherFactoryTest;
import org.dependencytrack.plugin.api.ExtensionTestResult;
import org.dependencytrack.plugin.testing.ExtensionContextBuilder;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.support.net.OutboundConnectionPolicy;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class EmailNotificationPublisherFactoryTest
        extends AbstractNotificationPublisherFactoryTest<EmailNotificationPublisherFactory> {

    protected EmailNotificationPublisherFactoryTest() {
        super(EmailNotificationPublisherFactory.class);
    }

    @Test
    void createShouldAllowHostAllowedByOutboundConnectionPolicy() {
        try (final var publisherFactory = new EmailNotificationPublisherFactory()) {
            initWithLoopbackHost(publisherFactory, OutboundConnectionPolicy.of(List.of("loopback")));

            assertThat(publisherFactory.create()).isNotNull();
        }
    }

    @Test
    void createShouldRejectHostDeniedByOutboundConnectionPolicy() {
        try (final var publisherFactory = new EmailNotificationPublisherFactory()) {
            initWithLoopbackHost(publisherFactory, OutboundConnectionPolicy.of(List.of("external", "private")));

            assertThatExceptionOfType(IllegalStateException.class)
                    .isThrownBy(publisherFactory::create)
                    .withMessageContaining("127.0.0.1");
        }
    }

    @Test
    void testShouldFailForHostDeniedByOutboundConnectionPolicy() {
        try (final var publisherFactory = new EmailNotificationPublisherFactory()) {
            initWithLoopbackHost(publisherFactory, OutboundConnectionPolicy.of(List.of("external", "private")));

            final ExtensionTestResult testResult = publisherFactory.test(loopbackHostConfig());

            assertThat(testResult.isFailed()).isTrue();
            assertThat(testResult.checks())
                    .satisfiesExactly(check -> assertThat(check.message()).contains("127.0.0.1"));
        }
    }

    @Test
    void defaultTemplateShouldNotReturnNull() {
        try (final var publisherFactory = new EmailNotificationPublisherFactory()) {
            assertThat(publisherFactory.defaultTemplate()).isNotNull();
        }
    }

    private static void initWithLoopbackHost(
            EmailNotificationPublisherFactory publisherFactory, OutboundConnectionPolicy outboundConnectionPolicy) {
        publisherFactory.init(new ExtensionContextBuilder()
                .withConfigRegistry(new MockConfigRegistry(publisherFactory.runtimeConfigSpec(), loopbackHostConfig()))
                .withOutboundConnectionPolicy(outboundConnectionPolicy)
                .build());
    }

    private static EmailNotificationPublisherGlobalConfigV1 loopbackHostConfig() {
        final var config = new EmailNotificationPublisherGlobalConfigV1();
        config.setEnabled(true);
        config.setHost("127.0.0.1");
        config.setPort(25);
        config.setSenderAddress("dependencytrack@example.com");
        return config;
    }
}
