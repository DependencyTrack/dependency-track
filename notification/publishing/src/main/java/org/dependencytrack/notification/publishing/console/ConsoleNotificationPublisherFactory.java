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
package org.dependencytrack.notification.publishing.console;

import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.api.templating.NotificationTemplate;
import org.dependencytrack.plugin.api.ServiceRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.jspecify.annotations.Nullable;

import java.io.OutputStream;

import static org.dependencytrack.notification.api.publishing.NotificationPublisherFactory.loadDefaultTemplate;

/**
 * @since 5.0.0
 */
public final class ConsoleNotificationPublisherFactory implements NotificationPublisherFactory {

    private final OutputStream outputStream;

    ConsoleNotificationPublisherFactory(OutputStream outputStream) {
        this.outputStream = outputStream;
    }

    public ConsoleNotificationPublisherFactory() {
        this(System.out);
    }

    @Override
    public String extensionName() {
        return "console";
    }

    @Override
    public Class<? extends NotificationPublisher> extensionClass() {
        return ConsoleNotificationPublisher.class;
    }

    @Override
    public void init(ServiceRegistry serviceRegistry) {
    }

    @Override
    public NotificationPublisher create() {
        return new ConsoleNotificationPublisher(outputStream);
    }

    @Override
    public @Nullable RuntimeConfigSpec ruleConfigSpec() {
        return null;
    }

    @Override
    public NotificationTemplate defaultTemplate() {
        return new NotificationTemplate(loadDefaultTemplate(extensionClass()), "text/plain");
    }

}
