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
package org.dependencytrack.persistence.command;

import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.Tag;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationLevel;
import org.dependencytrack.notification.NotificationScope;
import org.jspecify.annotations.Nullable;

import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * @param name                 Name of the rule
 * @param scope                Scope of the rule
 * @param level                Minimum notification level the rule applies to
 * @param publisher            Publisher to deliver notifications with
 * @param enabled              Whether the rule is enabled, or {@code null} for the default
 * @param notifyChildren       Whether to notify for child projects, or {@code null} for the default
 * @param logSuccessfulPublish Whether to log successful publishes, or {@code null} for the default
 * @param notifyOn             Notification groups to subscribe to, or {@code null} for none
 * @param publisherConfig      Publisher configuration as JSON, or {@code null} for none
 * @param filterExpression     Filter expression, or {@code null} for none
 * @param tags                 Tags to limit the rule to, or {@code null} for none
 * @since 5.2.0
 */
public record CreateNotificationRuleCommand(
        String name,
        NotificationScope scope,
        NotificationLevel level,
        NotificationPublisher publisher,
        @Nullable Boolean enabled,
        @Nullable Boolean notifyChildren,
        @Nullable Boolean logSuccessfulPublish,
        @Nullable Set<NotificationGroup> notifyOn,
        @Nullable String publisherConfig,
        @Nullable String filterExpression,
        @Nullable Set<Tag> tags) {

    public CreateNotificationRuleCommand {
        requireNonNull(name, "name must not be null");
        requireNonNull(scope, "scope must not be null");
        requireNonNull(level, "level must not be null");
        requireNonNull(publisher, "publisher must not be null");
    }

    public CreateNotificationRuleCommand(
            final String name,
            final NotificationScope scope,
            final NotificationLevel level,
            final NotificationPublisher publisher) {
        this(name, scope, level, publisher, null, null, null, null, null, null, null);
    }

    public CreateNotificationRuleCommand withEnabled(final Boolean enabled) {
        return new CreateNotificationRuleCommand(
                this.name,
                this.scope,
                this.level,
                this.publisher,
                enabled,
                this.notifyChildren,
                this.logSuccessfulPublish,
                this.notifyOn,
                this.publisherConfig,
                this.filterExpression,
                this.tags);
    }

    public CreateNotificationRuleCommand withNotifyChildren(final Boolean notifyChildren) {
        return new CreateNotificationRuleCommand(
                this.name,
                this.scope,
                this.level,
                this.publisher,
                this.enabled,
                notifyChildren,
                this.logSuccessfulPublish,
                this.notifyOn,
                this.publisherConfig,
                this.filterExpression,
                this.tags);
    }

    public CreateNotificationRuleCommand withLogSuccessfulPublish(final Boolean logSuccessfulPublish) {
        return new CreateNotificationRuleCommand(
                this.name,
                this.scope,
                this.level,
                this.publisher,
                this.enabled,
                this.notifyChildren,
                logSuccessfulPublish,
                this.notifyOn,
                this.publisherConfig,
                this.filterExpression,
                this.tags);
    }

    public CreateNotificationRuleCommand withNotifyOn(final Set<NotificationGroup> notifyOn) {
        return new CreateNotificationRuleCommand(
                this.name,
                this.scope,
                this.level,
                this.publisher,
                this.enabled,
                this.notifyChildren,
                this.logSuccessfulPublish,
                notifyOn,
                this.publisherConfig,
                this.filterExpression,
                this.tags);
    }

    public CreateNotificationRuleCommand withPublisherConfig(final String publisherConfig) {
        return new CreateNotificationRuleCommand(
                this.name,
                this.scope,
                this.level,
                this.publisher,
                this.enabled,
                this.notifyChildren,
                this.logSuccessfulPublish,
                this.notifyOn,
                publisherConfig,
                this.filterExpression,
                this.tags);
    }

    public CreateNotificationRuleCommand withFilterExpression(final String filterExpression) {
        return new CreateNotificationRuleCommand(
                this.name,
                this.scope,
                this.level,
                this.publisher,
                this.enabled,
                this.notifyChildren,
                this.logSuccessfulPublish,
                this.notifyOn,
                this.publisherConfig,
                filterExpression,
                this.tags);
    }

    public CreateNotificationRuleCommand withTags(final Set<Tag> tags) {
        return new CreateNotificationRuleCommand(
                this.name,
                this.scope,
                this.level,
                this.publisher,
                this.enabled,
                this.notifyChildren,
                this.logSuccessfulPublish,
                this.notifyOn,
                this.publisherConfig,
                this.filterExpression,
                tags);
    }
}
