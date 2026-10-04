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
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.record.internal.CompressionType;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.api.templating.NotificationTemplate;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.ExtensionTestResult;
import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.api.Testable;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.support.net.OutboundConnectionDeniedException;
import org.dependencytrack.support.net.OutboundConnectionPolicy;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.UnknownHostException;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.Objects.requireNonNull;
import static org.apache.kafka.clients.CommonClientConfigs.REQUEST_TIMEOUT_MS_CONFIG;
import static org.apache.kafka.clients.CommonClientConfigs.SECURITY_PROTOCOL_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.BOOTSTRAP_SERVERS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.COMPRESSION_TYPE_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.LINGER_MS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.MAX_BLOCK_MS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.common.config.SslConfigs.SSL_KEYSTORE_CERTIFICATE_CHAIN_CONFIG;
import static org.apache.kafka.common.config.SslConfigs.SSL_KEYSTORE_KEY_CONFIG;
import static org.apache.kafka.common.config.SslConfigs.SSL_KEYSTORE_TYPE_CONFIG;
import static org.apache.kafka.common.config.SslConfigs.SSL_TRUSTSTORE_CERTIFICATES_CONFIG;
import static org.apache.kafka.common.config.SslConfigs.SSL_TRUSTSTORE_TYPE_CONFIG;

/**
 * @since 5.0.0
 */
public final class KafkaNotificationPublisherFactory
        implements NotificationPublisherFactory, RuntimeConfigurable, Testable {

    private record CachedProducer(ProducerConfig config, KafkaProducer<String, byte[]> producer) {}

    private static final Logger LOGGER = LoggerFactory.getLogger(KafkaNotificationPublisherFactory.class);

    private final Lock producerCacheLock = new ReentrantLock();
    private @Nullable ConfigRegistry configRegistry;
    private @Nullable CachedProducer cachedProducer;
    private @Nullable OutboundConnectionPolicy outboundConnectionPolicy;

    @Override
    public String extensionName() {
        return "kafka";
    }

    @Override
    public String displayName() {
        return "Kafka";
    }

    @Override
    public Class<? extends NotificationPublisher> extensionClass() {
        return KafkaNotificationPublisher.class;
    }

    @Override
    public void init(ExtensionContext context) {
        configRegistry = context.configRegistry();
        outboundConnectionPolicy = context.outboundConnectionPolicy();
    }

    @Override
    public NotificationPublisher create() {
        requireNonNull(configRegistry, "configRegistry must not be null");

        final var globalConfig = configRegistry.getRuntimeConfig(KafkaNotificationPublisherGlobalConfigV1.class);

        if (!globalConfig.isEnabled()) {
            throw new IllegalStateException("Publisher is disabled");
        }

        try {
            requireAllowedBrokerHosts(globalConfig);
        } catch (OutboundConnectionDeniedException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }

        final KafkaProducer<String, byte[]> kafkaProducer = getKafkaProducer(globalConfig);

        return new KafkaNotificationPublisher(kafkaProducer);
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        return RuntimeConfigSpec.of(new KafkaNotificationPublisherGlobalConfigV1(), config -> {
            if (!config.isEnabled()) {
                return;
            }
            if (config.getBootstrapServers() == null
                    || config.getBootstrapServers().isEmpty()) {
                throw new InvalidRuntimeConfigException("No bootstrap servers provided");
            }
            if (config.getTls() != null && config.getTls().isEnabled()) {
                if (config.getTls().getCaCert() == null) {
                    throw new InvalidRuntimeConfigException("No TLS CA certificate provided");
                }
            }
            if (config.getmTls() != null && config.getmTls().isEnabled()) {
                if (!config.getTls().isEnabled()) {
                    throw new InvalidRuntimeConfigException("mTLS requires TLS to be enabled");
                }
                if (config.getmTls().getClientCert() == null) {
                    throw new InvalidRuntimeConfigException("No mTLS client certificate provided");
                }
                if (config.getmTls().getClientKey() == null) {
                    throw new InvalidRuntimeConfigException("No mTLS client key provided");
                }
            }
        });
    }

    @Override
    public ExtensionTestResult test(@Nullable RuntimeConfig runtimeConfig) {
        requireNonNull(runtimeConfig, "runtimeConfig must not be null");

        final var config = (KafkaNotificationPublisherGlobalConfigV1) runtimeConfig;

        final var testResult = ExtensionTestResult.ofChecks("connection");

        try {
            requireAllowedBrokerHosts(config);
        } catch (OutboundConnectionDeniedException e) {
            return testResult.fail("connection", e.getMessage());
        }

        final ProducerConfig producerConfig = createProducerConfig(config);

        // NB: The configs relevant for connecting to Kafka clusters
        // are identical across all client types, so we can just reuse
        // the producer config here.
        try (final var adminClient = AdminClient.create(producerConfig.originals())) {
            adminClient.describeCluster().clusterId().get(10, TimeUnit.SECONDS);
            testResult.pass("connection");
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            LOGGER.warn("Failed to connect to Kafka cluster", e);
            testResult.fail("connection", "Connection failed, check logs for details");
        } catch (RuntimeException e) {
            LOGGER.warn("Failed to test connection to Kafka cluster", e);
            testResult.fail("connection", "Internal failure, check logs for details");
        }

        return testResult;
    }

    @Override
    public RuntimeConfigSpec ruleConfigSpec() {
        return RuntimeConfigSpec.of(new KafkaNotificationPublisherRuleConfigV1()
                .withTopicName("dependencytrack-notifications")
                .withPublishProtobuf(true));
    }

    @Override
    public @Nullable NotificationTemplate defaultTemplate() {
        return null;
    }

    @Override
    public void close() {
        producerCacheLock.lock();
        try {
            if (cachedProducer != null) {
                cachedProducer.producer().close();
                cachedProducer = null;
            }
        } finally {
            producerCacheLock.unlock();
        }
    }

    private KafkaProducer<String, byte[]> getKafkaProducer(KafkaNotificationPublisherGlobalConfigV1 config) {
        final ProducerConfig producerConfig = createProducerConfig(config);

        producerCacheLock.lock();
        try {
            if (cachedProducer != null) {
                if (Objects.equals(cachedProducer.config(), producerConfig)) {
                    // NB: Publishers treat closed Kafka producers as a retryable failure.
                    LOGGER.debug("Using cached producer with matching config");
                    return cachedProducer.producer();
                }

                LOGGER.debug("Producer config has changed; Closing cached producer");
                cachedProducer.producer().close();
                cachedProducer = null;
            }

            final var producer = new KafkaProducer<String, byte[]>(producerConfig.originals());
            cachedProducer = new CachedProducer(producerConfig, producer);
            return producer;
        } finally {
            producerCacheLock.unlock();
        }
    }

    private static ProducerConfig createProducerConfig(KafkaNotificationPublisherGlobalConfigV1 config) {
        final var props = new Properties();
        props.put(BOOTSTRAP_SERVERS_CONFIG, String.join(",", config.getBootstrapServers()));
        props.put(KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        props.put(VALUE_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class.getName());
        props.put(ENABLE_IDEMPOTENCE_CONFIG, "true");
        props.put(COMPRESSION_TYPE_CONFIG, CompressionType.SNAPPY.name);
        props.put(LINGER_MS_CONFIG, 0);
        props.put(DELIVERY_TIMEOUT_MS_CONFIG, 10_000); // Must be >= linger.ms + request.timeout.ms.
        props.put(MAX_BLOCK_MS_CONFIG, 10_000);
        props.put(REQUEST_TIMEOUT_MS_CONFIG, 10_000);

        if (config.getTls() != null && config.getTls().isEnabled()) {
            props.put(SECURITY_PROTOCOL_CONFIG, "SSL");
            props.put(SSL_TRUSTSTORE_TYPE_CONFIG, "PEM");
            props.put(SSL_TRUSTSTORE_CERTIFICATES_CONFIG, config.getTls().getCaCert());

            if (config.getmTls() != null && config.getmTls().isEnabled()) {
                props.put(SSL_KEYSTORE_TYPE_CONFIG, "PEM");
                props.put(
                        SSL_KEYSTORE_CERTIFICATE_CHAIN_CONFIG, config.getmTls().getClientCert());
                props.put(SSL_KEYSTORE_KEY_CONFIG, config.getmTls().getClientKey());
            }
        }

        return new ProducerConfig(props);
    }

    private void requireAllowedBrokerHosts(KafkaNotificationPublisherGlobalConfigV1 config)
            throws OutboundConnectionDeniedException {
        requireNonNull(outboundConnectionPolicy, "outboundConnectionPolicy must not be null");

        for (final String bootstrapServer : config.getBootstrapServers()) {
            try {
                outboundConnectionPolicy.requireAllowed(hostOf(bootstrapServer));
            } catch (UnknownHostException _) {
                // Let the actual connection logic handle this.
            }
        }
    }

    private static String hostOf(String bootstrapServer) {
        // IPv6 addresses use brackets, e.g. [::1]:9092.
        if (bootstrapServer.startsWith("[")) {
            final int closingBracketIndex = bootstrapServer.indexOf(']');
            return closingBracketIndex < 0 ? bootstrapServer : bootstrapServer.substring(1, closingBracketIndex);
        }

        return bootstrapServer.split(":", 2)[0];
    }
}
