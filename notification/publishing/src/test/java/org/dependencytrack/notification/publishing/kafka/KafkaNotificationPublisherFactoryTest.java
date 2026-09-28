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
package org.dependencytrack.notification.publishing.kafka;

import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.publishing.AbstractNotificationPublisherFactoryTest;
import org.dependencytrack.plugin.api.ExtensionTestResult;
import org.dependencytrack.plugin.testing.ExtensionContextBuilder;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.support.net.OutboundConnectionPolicy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class KafkaNotificationPublisherFactoryTest
        extends AbstractNotificationPublisherFactoryTest<KafkaNotificationPublisherFactory> {

    protected KafkaNotificationPublisherFactoryTest() {
        super(KafkaNotificationPublisherFactory.class);
    }

    @Test
    void createShouldAllowBootstrapServerAllowedByOutboundConnectionPolicy() throws Exception {
        try (final var publisherFactory = new KafkaNotificationPublisherFactory()) {
            init(publisherFactory, "127.0.0.1:9092", OutboundConnectionPolicy.of(List.of("loopback")));

            try (final NotificationPublisher publisher = publisherFactory.create()) {
                assertThat(publisher).isNotNull();
            }
        }
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', textBlock = """
            [::1]:9092           | ::1
            100.100.100.200:9092 | 100.100.100.200
            """)
    void createShouldRejectBootstrapServerDeniedByOutboundConnectionPolicy(String bootstrapServer, String host) {
        try (final var publisherFactory = new KafkaNotificationPublisherFactory()) {
            init(publisherFactory, bootstrapServer, OutboundConnectionPolicy.of(List.of("external", "private")));

            assertThatExceptionOfType(IllegalStateException.class)
                    .isThrownBy(publisherFactory::create)
                    .withMessageContaining(host);
        }
    }

    @Test
    void testShouldFailForBootstrapServerDeniedByOutboundConnectionPolicy() {
        try (final var publisherFactory = new KafkaNotificationPublisherFactory()) {
            init(publisherFactory, "100.100.100.200:9092", OutboundConnectionPolicy.of(List.of("external", "private")));

            final ExtensionTestResult testResult = publisherFactory.test(config("100.100.100.200:9092"));

            assertThat(testResult.isFailed()).isTrue();
            assertThat(testResult.checks())
                    .satisfiesExactly(check -> assertThat(check.message()).contains("100.100.100.200"));
        }
    }

    @Test
    void defaultTemplateShouldReturnNull() {
        try (final var publisherFactory = new KafkaNotificationPublisherFactory()) {
            assertThat(publisherFactory.defaultTemplate()).isNull();
        }
    }

    private static void init(
            KafkaNotificationPublisherFactory publisherFactory,
            String bootstrapServer,
            OutboundConnectionPolicy outboundConnectionPolicy) {
        publisherFactory.init(new ExtensionContextBuilder()
                .withConfigRegistry(
                        new MockConfigRegistry(publisherFactory.runtimeConfigSpec(), config(bootstrapServer)))
                .withOutboundConnectionPolicy(outboundConnectionPolicy)
                .build());
    }

    private static KafkaNotificationPublisherGlobalConfigV1 config(String bootstrapServer) {
        return new KafkaNotificationPublisherGlobalConfigV1()
                .withEnabled(true)
                .withBootstrapServers(Set.of(bootstrapServer));
    }
}
