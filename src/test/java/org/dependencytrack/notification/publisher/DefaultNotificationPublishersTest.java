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
package org.dependencytrack.notification.publisher;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import jakarta.ws.rs.core.MediaType;

class DefaultNotificationPublishersTest {

    @Test
    void testEnums() {
        Assertions.assertEquals("SLACK", DefaultNotificationPublishers.SLACK.name());
        Assertions.assertEquals("MS_TEAMS", DefaultNotificationPublishers.MS_TEAMS.name());
        Assertions.assertEquals("MATTERMOST", DefaultNotificationPublishers.MATTERMOST.name());
        Assertions.assertEquals("EMAIL", DefaultNotificationPublishers.EMAIL.name());
        Assertions.assertEquals("CONSOLE", DefaultNotificationPublishers.CONSOLE.name());
        Assertions.assertEquals("WEBHOOK", DefaultNotificationPublishers.WEBHOOK.name());
        Assertions.assertEquals("JIRA", DefaultNotificationPublishers.JIRA.name());
    }

    @Test
    void testSlack() {
        Assertions.assertEquals("Slack", DefaultNotificationPublishers.SLACK.getPublisherName());
        Assertions.assertEquals("Publishes notifications to a Slack channel", DefaultNotificationPublishers.SLACK.getPublisherDescription());
        Assertions.assertEquals(SlackPublisher.class, DefaultNotificationPublishers.SLACK.getPublisherClass());
        Assertions.assertEquals("/templates/notification/publisher/slack.peb", DefaultNotificationPublishers.SLACK.getPublisherTemplateFile());
        Assertions.assertEquals(MediaType.APPLICATION_JSON, DefaultNotificationPublishers.SLACK.getTemplateMimeType());
        Assertions.assertTrue(DefaultNotificationPublishers.SLACK.isDefaultPublisher());
    }

    @Test
    void testMsTeams() {
        Assertions.assertEquals("Microsoft Teams", DefaultNotificationPublishers.MS_TEAMS.getPublisherName());
        Assertions.assertEquals("Publishes notifications to a Microsoft Teams channel", DefaultNotificationPublishers.MS_TEAMS.getPublisherDescription());
        Assertions.assertEquals(MsTeamsPublisher.class, DefaultNotificationPublishers.MS_TEAMS.getPublisherClass());
        Assertions.assertEquals("/templates/notification/publisher/msteams.peb", DefaultNotificationPublishers.MS_TEAMS.getPublisherTemplateFile());
        Assertions.assertEquals(MediaType.APPLICATION_JSON, DefaultNotificationPublishers.MS_TEAMS.getTemplateMimeType());
        Assertions.assertTrue(DefaultNotificationPublishers.MS_TEAMS.isDefaultPublisher());
    }

    @Test
    void testMattermost() {
        Assertions.assertEquals("Mattermost", DefaultNotificationPublishers.MATTERMOST.getPublisherName());
        Assertions.assertEquals("Publishes notifications to a Mattermost channel", DefaultNotificationPublishers.MATTERMOST.getPublisherDescription());
        Assertions.assertEquals(MattermostPublisher.class, DefaultNotificationPublishers.MATTERMOST.getPublisherClass());
        Assertions.assertEquals("/templates/notification/publisher/mattermost.peb", DefaultNotificationPublishers.MATTERMOST.getPublisherTemplateFile());
        Assertions.assertEquals(MediaType.APPLICATION_JSON, DefaultNotificationPublishers.MATTERMOST.getTemplateMimeType());
        Assertions.assertTrue(DefaultNotificationPublishers.MATTERMOST.isDefaultPublisher());
    }

    @Test
    void testEmail() {
        Assertions.assertEquals("Email", DefaultNotificationPublishers.EMAIL.getPublisherName());
        Assertions.assertEquals("Sends notifications to an email address", DefaultNotificationPublishers.EMAIL.getPublisherDescription());
        Assertions.assertEquals(SendMailPublisher.class, DefaultNotificationPublishers.EMAIL.getPublisherClass());
        Assertions.assertEquals("/templates/notification/publisher/email.peb", DefaultNotificationPublishers.EMAIL.getPublisherTemplateFile());
        Assertions.assertEquals("text/plain; charset=utf-8", DefaultNotificationPublishers.EMAIL.getTemplateMimeType());
        Assertions.assertTrue(DefaultNotificationPublishers.EMAIL.isDefaultPublisher());
    }

    @Test
    void testConsole() {
        Assertions.assertEquals("Console", DefaultNotificationPublishers.CONSOLE.getPublisherName());
        Assertions.assertEquals("Displays notifications on the system console", DefaultNotificationPublishers.CONSOLE.getPublisherDescription());
        Assertions.assertEquals(ConsolePublisher.class, DefaultNotificationPublishers.CONSOLE.getPublisherClass());
        Assertions.assertEquals("/templates/notification/publisher/console.peb", DefaultNotificationPublishers.CONSOLE.getPublisherTemplateFile());
        Assertions.assertEquals(MediaType.TEXT_PLAIN, DefaultNotificationPublishers.CONSOLE.getTemplateMimeType());
        Assertions.assertTrue(DefaultNotificationPublishers.CONSOLE.isDefaultPublisher());
    }

    @Test
    void testWebhook() {
        Assertions.assertEquals("Outbound Webhook", DefaultNotificationPublishers.WEBHOOK.getPublisherName());
        Assertions.assertEquals("Publishes notifications to a configurable endpoint", DefaultNotificationPublishers.WEBHOOK.getPublisherDescription());
        Assertions.assertEquals(WebhookPublisher.class, DefaultNotificationPublishers.WEBHOOK.getPublisherClass());
        Assertions.assertEquals("/templates/notification/publisher/webhook.peb", DefaultNotificationPublishers.WEBHOOK.getPublisherTemplateFile());
        Assertions.assertEquals(MediaType.APPLICATION_JSON, DefaultNotificationPublishers.WEBHOOK.getTemplateMimeType());
        Assertions.assertTrue(DefaultNotificationPublishers.WEBHOOK.isDefaultPublisher());
    }

    @Test
    void testJira() {
        Assertions.assertEquals("Jira", DefaultNotificationPublishers.JIRA.getPublisherName());
        Assertions.assertEquals("Creates a Jira issue in a configurable Jira instance and queue", DefaultNotificationPublishers.JIRA.getPublisherDescription());
        Assertions.assertEquals(JiraPublisher.class, DefaultNotificationPublishers.JIRA.getPublisherClass());
        Assertions.assertEquals("/templates/notification/publisher/jira.peb", DefaultNotificationPublishers.JIRA.getPublisherTemplateFile());
        Assertions.assertEquals(MediaType.APPLICATION_JSON, DefaultNotificationPublishers.JIRA.getTemplateMimeType());
        Assertions.assertTrue(DefaultNotificationPublishers.JIRA.isDefaultPublisher());
    }
}
