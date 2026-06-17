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

import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.header.internals.RecordHeader;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.proto.v1.Group;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.Scope;
import org.dependencytrack.notification.publishing.AbstractNotificationPublisherTest;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.kafka.KafkaContainer;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.apache.kafka.clients.CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.AUTO_OFFSET_RESET_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.GROUP_ID_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
class KafkaNotificationPublisherTest extends AbstractNotificationPublisherTest {

    @Container
    private static final KafkaContainer kafkaContainer = new KafkaContainer("apache/kafka:4.1.1");

    @Override
    protected NotificationPublisherFactory createPublisherFactory() {
        return new KafkaNotificationPublisherFactory();
    }

    @Override
    protected void customizeDeploymentConfig(Map<String, String> deploymentConfig) {
        deploymentConfig.put("allow-local-connections", "true");
    }

    @Override
    protected void customizeGlobalConfig(RuntimeConfig globalConfig) {
        final var kafkaGlobalConfig = (KafkaNotificationPublisherGlobalConfigV1) globalConfig;
        kafkaGlobalConfig.setEnabled(true);
        kafkaGlobalConfig.setBootstrapServers(Set.of(kafkaContainer.getBootstrapServers()));
    }

    @BeforeEach
    @Override
    protected void beforeEach() throws Exception {
        try (final var adminClient = AdminClient.create(Map.of(
                BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBootstrapServers()))) {
            adminClient.createTopics(List.of(new NewTopic("dependencytrack-notifications", 1, (short) 1))).all().get();
        }

        super.beforeEach();
    }

    @AfterEach
    protected void afterEach() {
        try (final var adminClient = AdminClient.create(Map.of(
                BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBootstrapServers()))) {
            adminClient.deleteTopics(List.of("dependencytrack-notifications"));
        }

        super.afterEach();
    }

    @Override
    protected void validateNotificationPublish(Notification notification) throws Exception {
        final ConsumerRecord<String, byte[]> record = pollNotificationRecord();
        if (notification.getGroup() == Group.GROUP_NEW_VULNERABILITIES_SUMMARY
                || notification.getGroup() == Group.GROUP_NEW_POLICY_VIOLATIONS_SUMMARY) {
            assertThat(record.key()).isNull();
        } else if (notification.getScope() == Scope.SCOPE_PORTFOLIO) {
            assertThat(record.key()).isEqualTo("c9c9539a-e381-4b36-ac52-6a7ab83b2c95");
        } else {
            if (notification.getGroup() == Group.GROUP_USER_CREATED
                    || notification.getGroup() == Group.GROUP_USER_DELETED) {
                assertThat(record.key()).isEqualTo("username");
            } else {
                assertThat(record.key()).isNull();
            }
        }
        assertThat(record.headers()).containsExactly(new RecordHeader("content-type", "application/protobuf".getBytes()));
        assertThat(Notification.parseFrom(record.value())).isEqualTo(notification);
    }

    private ConsumerRecord<String, byte[]> pollNotificationRecord() {
        try (final var consumer = new KafkaConsumer<String, byte[]>(Map.ofEntries(
                Map.entry(BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBootstrapServers()),
                Map.entry(GROUP_ID_CONFIG, UUID.randomUUID().toString()),
                Map.entry(AUTO_OFFSET_RESET_CONFIG, "earliest"),
                Map.entry(KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName()),
                Map.entry(VALUE_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class.getName())))) {
            consumer.subscribe(List.of("dependencytrack-notifications"));

            final ConsumerRecords<String, byte[]> records = consumer.poll(Duration.ofSeconds(1));
            assertThat(records).hasSize(1);

            return records.iterator().next();
        }
    }

}