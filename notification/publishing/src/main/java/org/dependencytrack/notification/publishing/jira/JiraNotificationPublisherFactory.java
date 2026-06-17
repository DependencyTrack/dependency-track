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
package org.dependencytrack.notification.publishing.jira;

import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.api.templating.NotificationTemplate;
import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.InvalidRuntimeConfigException;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.jspecify.annotations.Nullable;

import java.net.http.HttpClient;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.api.publishing.NotificationPublisherFactory.loadDefaultTemplate;

/**
 * @since 5.0.0
 */
public final class JiraNotificationPublisherFactory implements NotificationPublisherFactory, RuntimeConfigurable {

    private @Nullable ConfigRegistry configRegistry;
    private @Nullable HttpClient httpClient;

    @Override
    public String extensionName() {
        return "jira";
    }

    @Override
    public Class<? extends NotificationPublisher> extensionClass() {
        return JiraNotificationPublisher.class;
    }

    @Override
    public void init(ServiceRegistry serviceRegistry) {
        configRegistry = serviceRegistry.require(ConfigRegistry.class);
        httpClient = serviceRegistry.require(HttpClient.class);
    }

    @Override
    public NotificationPublisher create() {
        requireNonNull(configRegistry, "configRegistry must not be null");
        requireNonNull(httpClient, "httpClient must not be null");

        final var globalConfig = configRegistry.getRuntimeConfig(JiraNotificationPublisherGlobalConfigV1.class);

        if (!globalConfig.isEnabled()) {
            throw new IllegalStateException("Publisher is disabled");
        }

        return new JiraNotificationPublisher(globalConfig, httpClient);
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        return RuntimeConfigSpec.of(
                new JiraNotificationPublisherGlobalConfigV1(),
                config -> {
                    if (!config.isEnabled()) {
                        return;
                    }
                    if (config.getApiUrl() == null) {
                        throw new InvalidRuntimeConfigException("No API URL provided");
                    }
                    if (config.getPasswordOrToken() == null) {
                        throw new InvalidRuntimeConfigException("No password or token provided");
                    }
                });
    }

    @Override
    public RuntimeConfigSpec ruleConfigSpec() {
        return RuntimeConfigSpec.of(
                new JiraNotificationPublisherRuleConfigV1()
                        .withProjectKey("EXAMPLE")
                        .withIssueType("Bug"),
                config -> {
                    if (config.getProjectKey() == null) {
                        throw new InvalidRuntimeConfigException("No project key provided");
                    }
                    if (config.getIssueType() == null) {
                        throw new InvalidRuntimeConfigException("No issue type provided");
                    }
                });
    }

    @Override
    public NotificationTemplate defaultTemplate() {
        return new NotificationTemplate(loadDefaultTemplate(extensionClass()), "application/json");
    }

}
