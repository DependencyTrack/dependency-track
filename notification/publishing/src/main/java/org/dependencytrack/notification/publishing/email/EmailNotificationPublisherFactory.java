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

import jakarta.mail.AuthenticationFailedException;
import jakarta.mail.Authenticator;
import jakarta.mail.MessagingException;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;

import javax.net.ssl.SSLSocketFactory;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.Map;
import java.util.Properties;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.api.publishing.NotificationPublisherFactory.loadDefaultTemplate;

/**
 * @since 5.0.0
 */
public final class EmailNotificationPublisherFactory
        implements NotificationPublisherFactory, RuntimeConfigurable, Testable {

    private static final Logger LOGGER = LoggerFactory.getLogger(EmailNotificationPublisherFactory.class);

    private final Map<String, String> overrideMailProperties;
    private final Class<? extends SSLSocketFactory> sslSocketFactoryClass;
    private @Nullable ConfigRegistry configRegistry;
    private @Nullable OutboundConnectionPolicy outboundConnectionPolicy;

    EmailNotificationPublisherFactory(
            Map<String, String> overrideMailProperties, Class<? extends SSLSocketFactory> sslSocketFactoryClass) {
        this.overrideMailProperties = Map.copyOf(overrideMailProperties);
        this.sslSocketFactoryClass = sslSocketFactoryClass;
    }

    public EmailNotificationPublisherFactory() {
        this(Collections.emptyMap(), SSLSocketFactory.class);
    }

    @Override
    public String extensionName() {
        return "email";
    }

    @Override
    public String displayName() {
        return "Email";
    }

    @Override
    public Class<? extends NotificationPublisher> extensionClass() {
        return EmailNotificationPublisher.class;
    }

    @Override
    public void init(ExtensionContext context) {
        configRegistry = context.configRegistry();
        outboundConnectionPolicy = context.outboundConnectionPolicy();
    }

    @Override
    public NotificationPublisher create() {
        requireNonNull(configRegistry, "configRegistry must not be null");

        final var globalConfig = configRegistry.getRuntimeConfig(EmailNotificationPublisherGlobalConfigV1.class);

        if (!globalConfig.isEnabled()) {
            throw new IllegalStateException("Publisher is disabled");
        }

        try {
            requireAllowedHost(globalConfig.getHost());
        } catch (OutboundConnectionDeniedException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }

        return new EmailNotificationPublisher(createSession(globalConfig), globalConfig.getSenderAddress());
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        return RuntimeConfigSpec.of(new EmailNotificationPublisherGlobalConfigV1(), config -> {
            if (!config.isEnabled()) {
                return;
            }
            if (config.getHost() == null) {
                throw new InvalidRuntimeConfigException("No host provided");
            }
            if (config.getPort() == null) {
                throw new InvalidRuntimeConfigException("No port provided");
            }
            if (config.getSenderAddress() == null) {
                throw new InvalidRuntimeConfigException("No sender address provided");
            }
        });
    }

    @Override
    public ExtensionTestResult test(@Nullable RuntimeConfig runtimeConfig) {
        requireNonNull(runtimeConfig, "runtimeConfig must not be null");

        final var config = (EmailNotificationPublisherGlobalConfigV1) runtimeConfig;

        final var testResult = ExtensionTestResult.ofChecks("connection");
        if (!config.isEnabled()) {
            return testResult;
        }

        try {
            requireAllowedHost(config.getHost());
        } catch (OutboundConnectionDeniedException e) {
            return testResult.fail("connection", e.getMessage());
        }

        final Session session = createSession(config);

        try (final Transport transport = session.getTransport()) {
            transport.connect();
            testResult.pass("connection");
        } catch (AuthenticationFailedException e) {
            LOGGER.warn("Failed to authenticate to email server", e);
            testResult.fail("connection", "Authentication failed");
        } catch (MessagingException e) {
            LOGGER.warn("Failed to connect to email server", e);
            testResult.fail("connection", "Connection failed, check logs for details");
        }

        return testResult;
    }

    @Override
    public RuntimeConfigSpec ruleConfigSpec() {
        return RuntimeConfigSpec.of(
                new EmailNotificationPublisherRuleConfigV1().withSubjectPrefix("[Dependency-Track]"));
    }

    @Override
    public NotificationTemplate defaultTemplate() {
        return new NotificationTemplate(loadDefaultTemplate(extensionClass()), "text/plain; charset=utf-8");
    }

    private Session createSession(EmailNotificationPublisherGlobalConfigV1 config) {
        final Properties props = new Properties();
        props.put("mail.smtp.host", config.getHost());
        props.put("mail.smtp.port", config.getPort());
        props.put("mail.smtp.socketFactory.port", config.getPort());
        props.put("mail.smtp.connectiontimeout", 10_000);
        props.put("mail.smtp.timeout", 10_000);
        props.put("mail.smtp.writetimeout", 10_000);

        if (config.isSslEnabled()) {
            props.put("mail.smtp.ssl.enable", true);
            props.put("mail.smtp.socketFactory.class", sslSocketFactoryClass.getName());
            props.put("mail.smtp.socketFactory.fallback", "false");
        }

        if (config.isStartTlsEnabled()) {
            props.put("mail.smtp.starttls.enable", true);
        }

        final boolean authenticated = config.getUsername() != null && config.getPassword() != null;

        Authenticator authenticator = null;
        if (authenticated) {
            props.put("mail.smtp.auth", true);
            authenticator = new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(config.getUsername(), config.getPassword());
                }
            };
        }

        props.putAll(overrideMailProperties);

        return Session.getInstance(props, authenticator);
    }

    private void requireAllowedHost(String hostname) throws OutboundConnectionDeniedException {
        requireNonNull(outboundConnectionPolicy, "outboundConnectionPolicy must not be null");

        try {
            outboundConnectionPolicy.requireAllowed(hostname);
        } catch (UnknownHostException _) {
            // Let the actual connection logic handle this.
        }
    }
}
