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

import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.security.crypto.DataEncryption;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.ws.rs.core.HttpHeaders;
import java.util.Base64;

import static org.dependencytrack.model.ConfigPropertyConstants.JIRA_PASSWORD;
import static org.dependencytrack.model.ConfigPropertyConstants.JIRA_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.JIRA_USERNAME;
import static org.mockserver.integration.ClientAndServer.startClientAndServer;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

public class JiraPublisherTest extends PersistenceCapableTest implements NotificationTestConfigProvider {

    private static ClientAndServer mockServer;

    @BeforeClass
    public static void beforeClass() {
        mockServer = startClientAndServer(1080);
    }


    @AfterClass
    public static void afterClass() {
        mockServer.stop();
    }

    @Test
    public void testPublish() throws Exception {
        final var jiraUser = "jiraUser";
        final var jiraPassword = "jiraPassword";

        final var request = request()
                .withMethod("POST")
                .withHeader(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder().encodeToString((jiraUser + ":" + jiraPassword).getBytes()));
        mockServer.when(request)
                .respond(
                        response()
                                .withStatusCode(200)
                                .withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                );
        final JsonObject config = getConfig(DefaultNotificationPublishers.JIRA, "MyProjectKey");
        final Notification notification = new Notification();
        notification.setScope(NotificationScope.PORTFOLIO.name());
        notification.setGroup(NotificationGroup.NEW_VULNERABILITY.name());
        notification.setLevel(NotificationLevel.INFORMATIONAL);
        notification.setTitle("Test Notification");
        notification.setContent("This is only a test");
        final JiraPublisher publisher = new JiraPublisher();


        qm.createConfigProperty(JIRA_URL.getGroupName(),
                JIRA_URL.getPropertyName(),
                "http://localhost:1080",
                JIRA_URL.getPropertyType(), JIRA_URL.getDescription());

        qm.createConfigProperty(JIRA_USERNAME.getGroupName(),
                JIRA_USERNAME.getPropertyName(),
                jiraUser,
                JIRA_USERNAME.getPropertyType(), JIRA_USERNAME.getDescription());

        qm.createConfigProperty(JIRA_PASSWORD.getGroupName(),
                JIRA_PASSWORD.getPropertyName(),
                DataEncryption.encryptAsString(jiraPassword),
                JIRA_PASSWORD.getPropertyType(), JIRA_PASSWORD.getDescription());

        publisher.inform(notification, config);
        mockServer.verify(request);

    }

    @Override
    public JsonObjectBuilder getExtraConfig() {
        return Json.createObjectBuilder()
                .add("jiraTicketType", "Task");
    }
}

