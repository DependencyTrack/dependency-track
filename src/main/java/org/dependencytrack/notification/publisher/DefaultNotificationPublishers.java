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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.notification.publisher;

import javax.ws.rs.core.MediaType;

public enum DefaultNotificationPublishers {

    SLACK("Slack", "Publishes notifications to a Slack channel", SlackPublisher.class, "/templates/notification/publisher/slack.peb", MediaType.APPLICATION_JSON, true),
    MS_TEAMS("Microsoft Teams", "Publishes notifications to a Microsoft Teams channel", MsTeamsPublisher.class, "/templates/notification/publisher/msteams.peb", MediaType.APPLICATION_JSON, true),
    EMAIL("Email", "Sends notifications to an email address", SendMailPublisher.class, "/templates/notification/publisher/email.peb", MediaType.TEXT_PLAIN, true),
    CONSOLE("Console", "Displays notifications on the system console", ConsolePublisher.class, "/templates/notification/publisher/console.peb", MediaType.TEXT_PLAIN, true),
    WEBHOOK("Outbound Webhook", "Publishes notifications to a configurable endpoint", WebhookPublisher.class, "/templates/notification/publisher/webhook.peb", MediaType.APPLICATION_JSON, true),
    CS_WEBEX("Cisco Webex", "Publishes notifications to a Cisco Webex Teams channel", CsWebexPublisher.class, "/templates/notification/publisher/cswebex.peb", MediaType.APPLICATION_JSON, true);

    private String name;
    private String description;
    private Class publisherClass;
    private String templateFile;
    private String templateMimeType;
    private boolean defaultPublisher;

    DefaultNotificationPublishers(final String name, final String description, final Class publisherClass,
                                  final String templateFile, final String templateMimeType, final boolean defaultPublisher) {
        this.name = name;
        this.description = description;
        this.publisherClass = publisherClass;
        this.templateFile = templateFile;
        this.templateMimeType = templateMimeType;
        this.defaultPublisher = defaultPublisher;
    }

    public String getPublisherName() {
        return name;
    }

    public String getPublisherDescription() {
        return description;
    }

    public Class getPublisherClass() {
        return publisherClass;
    }

    public String getPublisherTemplateFile() {
        return templateFile;
    }

    public String getTemplateMimeType() {
        return templateMimeType;
    }

    public boolean isDefaultPublisher() {
        return defaultPublisher;
    }
}