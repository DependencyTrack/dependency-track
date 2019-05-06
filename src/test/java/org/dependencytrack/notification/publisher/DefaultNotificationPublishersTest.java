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

import org.junit.Assert;
import org.junit.Test;
import javax.ws.rs.core.MediaType;

public class DefaultNotificationPublishersTest {

    @Test
    public void testEnums() {
        Assert.assertEquals("SLACK", DefaultNotificationPublishers.SLACK.name());
        Assert.assertEquals("MS_TEAMS", DefaultNotificationPublishers.MS_TEAMS.name());
        Assert.assertEquals("EMAIL", DefaultNotificationPublishers.EMAIL.name());
        Assert.assertEquals("CONSOLE", DefaultNotificationPublishers.CONSOLE.name());
        Assert.assertEquals("WEBHOOK", DefaultNotificationPublishers.WEBHOOK.name());
    }

    @Test
    public void testSlack() {
        Assert.assertEquals("Slack", DefaultNotificationPublishers.SLACK.getPublisherName());
        Assert.assertEquals("Publishes notifications to a Slack channel", DefaultNotificationPublishers.SLACK.getPublisherDescription());
        Assert.assertEquals(SlackPublisher.class, DefaultNotificationPublishers.SLACK.getPublisherClass());
        Assert.assertEquals("/templates/notification/publisher/slack.peb", DefaultNotificationPublishers.SLACK.getPublisherTemplateFile());
        Assert.assertEquals(MediaType.APPLICATION_JSON, DefaultNotificationPublishers.SLACK.getTemplateMimeType());
        Assert.assertTrue(DefaultNotificationPublishers.SLACK.isDefaultPublisher());
    }

    @Test
    public void testMsTeams() {
        Assert.assertEquals("Microsoft Teams", DefaultNotificationPublishers.MS_TEAMS.getPublisherName());
        Assert.assertEquals("Publishes notifications to a Microsoft Teams channel", DefaultNotificationPublishers.MS_TEAMS.getPublisherDescription());
        Assert.assertEquals(MsTeamsPublisher.class, DefaultNotificationPublishers.MS_TEAMS.getPublisherClass());
        Assert.assertEquals("/templates/notification/publisher/msteams.peb", DefaultNotificationPublishers.MS_TEAMS.getPublisherTemplateFile());
        Assert.assertEquals(MediaType.APPLICATION_JSON, DefaultNotificationPublishers.MS_TEAMS.getTemplateMimeType());
        Assert.assertTrue(DefaultNotificationPublishers.MS_TEAMS.isDefaultPublisher());
    }

    @Test
    public void testEmail() {
        Assert.assertEquals("Email", DefaultNotificationPublishers.EMAIL.getPublisherName());
        Assert.assertEquals("Sends notifications to an email address", DefaultNotificationPublishers.EMAIL.getPublisherDescription());
        Assert.assertEquals(SendMailPublisher.class, DefaultNotificationPublishers.EMAIL.getPublisherClass());
        Assert.assertEquals("/templates/notification/publisher/email.peb", DefaultNotificationPublishers.EMAIL.getPublisherTemplateFile());
        Assert.assertEquals(MediaType.TEXT_PLAIN, DefaultNotificationPublishers.EMAIL.getTemplateMimeType());
        Assert.assertTrue(DefaultNotificationPublishers.EMAIL.isDefaultPublisher());
    }

    @Test
    public void testConsole() {
        Assert.assertEquals("Console", DefaultNotificationPublishers.CONSOLE.getPublisherName());
        Assert.assertEquals("Displays notifications on the system console", DefaultNotificationPublishers.CONSOLE.getPublisherDescription());
        Assert.assertEquals(ConsolePublisher.class, DefaultNotificationPublishers.CONSOLE.getPublisherClass());
        Assert.assertEquals("/templates/notification/publisher/console.peb", DefaultNotificationPublishers.CONSOLE.getPublisherTemplateFile());
        Assert.assertEquals(MediaType.TEXT_PLAIN, DefaultNotificationPublishers.CONSOLE.getTemplateMimeType());
        Assert.assertTrue(DefaultNotificationPublishers.CONSOLE.isDefaultPublisher());
    }

    @Test
    public void testWebhook() {
        Assert.assertEquals("Outbound Webhook", DefaultNotificationPublishers.WEBHOOK.getPublisherName());
        Assert.assertEquals("Publishes notifications to a configurable endpoint", DefaultNotificationPublishers.WEBHOOK.getPublisherDescription());
        Assert.assertEquals(WebhookPublisher.class, DefaultNotificationPublishers.WEBHOOK.getPublisherClass());
        Assert.assertEquals("/templates/notification/publisher/webhook.peb", DefaultNotificationPublishers.WEBHOOK.getPublisherTemplateFile());
        Assert.assertEquals(MediaType.APPLICATION_JSON, DefaultNotificationPublishers.WEBHOOK.getTemplateMimeType());
        Assert.assertTrue(DefaultNotificationPublishers.WEBHOOK.isDefaultPublisher());
    }
}
