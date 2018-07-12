/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencytrack.notification.publisher;

public enum DefaultNotificationPublishers {

    SLACK("Slack", "Publishes notifications to a Slack channel", SlackPublisher.class, "/templates/notification/publisher/slack.peb"),
    MS_TEAMS("Microsoft Teams", "Publishes notifications to a Microsoft Teams channel", MsTeamsPublisher.class, "/templates/notification/publisher/msteams.peb"),
    EMAIL("Email", "Sends notifications to an email address", SendMailPublisher.class, "/templates/notification/publisher/email.peb"),
    CONSOLE("Console", "Displays notifications on the system console", ConsolePublisher.class, "/templates/notification/publisher/console.peb");

    private String name;
    private String description;
    private Class publisherClass;
    private String templateFile;

    DefaultNotificationPublishers(String name, String description, Class publisherClass, String templateFile) {
        this.name = name;
        this.description = description;
        this.publisherClass = publisherClass;
        this.templateFile = templateFile;
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
}