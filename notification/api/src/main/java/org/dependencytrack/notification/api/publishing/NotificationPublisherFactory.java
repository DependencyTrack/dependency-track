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
package org.dependencytrack.notification.api.publishing;

import org.dependencytrack.notification.api.templating.NotificationTemplate;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.NoSuchElementException;

/**
 * @since 5.0.0
 */
public interface NotificationPublisherFactory extends ExtensionFactory<NotificationPublisher> {

    /**
     * @return Specification of rule-level configuration supported by the publisher.
     * May be {@code null} when the publisher doesn't support any rule-level configuration.
     */
    @Nullable RuntimeConfigSpec ruleConfigSpec();

    /**
     * @return The default template of the publisher.
     */
    @Nullable NotificationTemplate defaultTemplate();

    @Override
    default int priority() {
        // Priority is irrelevant for notification publishers.
        return 0;
    }

    static String loadDefaultTemplate(Class<? extends NotificationPublisher> publisherClass) {
        final InputStream inputStream = publisherClass.getResourceAsStream("default-template.peb");
        if (inputStream == null) {
            throw new NoSuchElementException("No default template found for publisher: " + publisherClass.getName());
        }

        try (inputStream) {
            final byte[] schemaBytes = inputStream.readAllBytes();
            return new String(schemaBytes, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
