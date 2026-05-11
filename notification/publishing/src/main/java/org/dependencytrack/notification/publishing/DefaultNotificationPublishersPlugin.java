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
package org.dependencytrack.notification.publishing;

import org.dependencytrack.notification.publishing.console.ConsoleNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.email.EmailNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.jira.JiraNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.kafka.KafkaNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.mattermost.MattermostNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.msteams.MsTeamsNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.slack.SlackNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.webex.WebexNotificationPublisherFactory;
import org.dependencytrack.notification.publishing.webhook.WebhookNotificationPublisherFactory;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.Plugin;

import java.util.Collection;
import java.util.List;

/**
 * @since 5.0.0
 */
public final class DefaultNotificationPublishersPlugin implements Plugin {

    @Override
    public Collection<? extends ExtensionFactory<? extends ExtensionPoint>> extensionFactories() {
        return List.of(
                new ConsoleNotificationPublisherFactory(),
                new EmailNotificationPublisherFactory(),
                new JiraNotificationPublisherFactory(),
                new KafkaNotificationPublisherFactory(),
                new MattermostNotificationPublisherFactory(),
                new MsTeamsNotificationPublisherFactory(),
                new SlackNotificationPublisherFactory(),
                new WebexNotificationPublisherFactory(),
                new WebhookNotificationPublisherFactory());
    }

}
