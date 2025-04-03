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
package org.dependencytrack.resources.v1;

import alpine.common.util.UuidUtil;
import alpine.notification.NotificationLevel;
import alpine.security.crypto.DataEncryption;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.NotificationTriggerType;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.dependencytrack.notification.publisher.Publisher;
import org.dependencytrack.notification.publisher.SendMailPublisher;
import org.dependencytrack.notification.publisher.SlackPublisher;
import org.dependencytrack.notification.publisher.WebhookPublisher;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

public class NotificationPublisherResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(NotificationPublisherResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @Before
    public void before() throws Exception {
        super.before();
        final var generator = new DefaultObjectGenerator();
        generator.loadDefaultNotificationPublishers();
    }

    @Test
    public void getAllNotificationPublishersTest() {
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(8, json.size());
        Assert.assertEquals("Console", json.getJsonObject(1).getString("name"));
        Assert.assertEquals("Displays notifications on the system console", json.getJsonObject(1).getString("description"));
        Assert.assertEquals("text/plain", json.getJsonObject(1).getString("templateMimeType"));
        Assert.assertNotNull("template");
        Assert.assertTrue(json.getJsonObject(1).getBoolean("defaultPublisher"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getJsonObject(1).getString("uuid")));
    }

    @Test
    public void createNotificationPublisherTest() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setName("Example Publisher");
        publisher.setDescription("Publisher description");
        publisher.setTemplate("template");
        publisher.setTemplateMimeType("application/json");
        publisher.setPublisherClass(SendMailPublisher.class.getName());
        publisher.setDefaultPublisher(false);
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(publisher, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Example Publisher", json.getString("name"));
        Assert.assertFalse(json.getBoolean("defaultPublisher"));
        Assert.assertEquals("Publisher description", json.getString("description"));
        Assert.assertEquals("template", json.getString("template"));
        Assert.assertEquals("application/json", json.getString("templateMimeType"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
        Assert.assertEquals(SendMailPublisher.class.getName(), json.getString("publisherClass"));
    }

    @Test
    public void createNotificationPublisherWithDefaultFlagTest() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setName("Example Publisher");
        publisher.setDescription("Publisher description");
        publisher.setTemplate("template");
        publisher.setTemplateMimeType("application/json");
        publisher.setPublisherClass(SendMailPublisher.class.getName());
        publisher.setDefaultPublisher(true);
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(publisher, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("The creation of a new default publisher is forbidden", body);
    }

    @Test
    public void createNotificationPublisherWithExistingNameTest() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setName(DefaultNotificationPublishers.SLACK.getPublisherName());
        publisher.setDescription("Publisher description");
        publisher.setTemplate("template");
        publisher.setTemplateMimeType("application/json");
        publisher.setPublisherClass(SendMailPublisher.class.getName());
        publisher.setDefaultPublisher(true);
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(publisher, MediaType.APPLICATION_JSON));
        Assert.assertEquals(409, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("The notification with the name " + DefaultNotificationPublishers.SLACK.getPublisherName() + " already exist", body);
    }

    @Test
    public void createNotificationPublisherWithClassNotImplementingPublisherInterfaceTest() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setName("Example Publisher");
        publisher.setDescription("Publisher description");
        publisher.setTemplate("template");
        publisher.setTemplateMimeType("application/json");
        publisher.setPublisherClass(NotificationPublisherResource.class.getName());
        publisher.setDefaultPublisher(false);
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(publisher, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("The class " + NotificationPublisherResource.class.getName() + " does not implement " + Publisher.class.getName(), body);
    }

    @Test
    public void createNotificationPublisherClassNotFoundTest() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setName("Example Publisher");
        publisher.setDescription("Publisher description");
        publisher.setTemplate("template");
        publisher.setTemplateMimeType("application/json");
        publisher.setPublisherClass("invalidClassFqcn");
        publisher.setDefaultPublisher(false);
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(publisher, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("The class invalidClassFqcn cannot be found", body);
    }

    @Test
    public void updateNotificationPublisherTest() {
        NotificationPublisher notificationPublisher = qm.createNotificationPublisher(
                "Example Publisher", "Publisher description",
                SendMailPublisher.class, "template", "text/html",
                false
        );
        notificationPublisher.setName("Updated Publisher name");
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(notificationPublisher, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Updated Publisher name", json.getString("name"));
        Assert.assertFalse(json.getBoolean("defaultPublisher"));
        Assert.assertEquals("Publisher description", json.getString("description"));
        Assert.assertEquals("template", json.getString("template"));
        Assert.assertEquals("text/html", json.getString("templateMimeType"));
        Assert.assertEquals(notificationPublisher.getUuid().toString(), json.getString("uuid"));
        Assert.assertEquals(SendMailPublisher.class.getName(), json.getString("publisherClass"));
    }

    @Test
    public void updateUnknownNotificationPublisherTest() {
        NotificationPublisher notificationPublisher = qm.createNotificationPublisher(
                "Example Publisher", "Publisher description",
                SendMailPublisher.class, "template", "text/html",
                false
        );
        notificationPublisher = qm.detach(NotificationPublisher.class, notificationPublisher.getId());
        notificationPublisher.setUuid(UUID.randomUUID());
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(notificationPublisher, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The UUID of the notification publisher could not be found.", body);
    }

    @Test
    public void updateExistingDefaultNotificationPublisherTest() {
        NotificationPublisher notificationPublisher = qm.getDefaultNotificationPublisher(SendMailPublisher.class);
        notificationPublisher.setName(notificationPublisher.getName() + " Updated");
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(notificationPublisher, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The modification of a default publisher is forbidden", body);
    }

    @Test
    public void updateNotificationPublisherWithNameOfAnotherNotificationPublisherTest() {
        NotificationPublisher notificationPublisher = qm.createNotificationPublisher(
                "Example Publisher", "Publisher description",
                SendMailPublisher.class, "template", "text/html",
                false
        );
        notificationPublisher = qm.detach(NotificationPublisher.class, notificationPublisher.getId());
        notificationPublisher.setName(DefaultNotificationPublishers.MS_TEAMS.getPublisherName());
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(notificationPublisher, MediaType.APPLICATION_JSON));
        Assert.assertEquals(409, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("An existing publisher with the name '" + DefaultNotificationPublishers.MS_TEAMS.getPublisherName() + "' already exist", body);
    }

    @Test
    public void updateNotificationPublisherWithInvalidClassTest() {
        NotificationPublisher notificationPublisher = qm.createNotificationPublisher(
                "Example Publisher", "Publisher description",
                SendMailPublisher.class, "template", "text/html",
                false
        );
        notificationPublisher.setPublisherClass("unknownClass");
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(notificationPublisher, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The class unknownClass cannot be found", body);
    }

    @Test
    public void updateNotificationPublisherWithClassNotImplementingPublisherInterfaceTest() {
        NotificationPublisher notificationPublisher = qm.createNotificationPublisher(
                "Example Publisher", "Publisher description",
                SendMailPublisher.class, "template", "text/html",
                false
        );
        notificationPublisher.setPublisherClass(NotificationPublisherResource.class.getName());
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(notificationPublisher, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The class " + NotificationPublisherResource.class.getName() + " does not implement " + Publisher.class.getName(), body);
    }

    @Test
    public void deleteNotificationPublisherWithNoRulesTest() {
        NotificationPublisher publisher = qm.createNotificationPublisher(
                "Example Publisher", "Publisher description",
                SendMailPublisher.class, "template", "text/html",
                false
        );
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER + "/" + publisher.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(204, response.getStatus(), 0);
        Assert.assertNull(qm.getObjectByUuid(NotificationPublisher.class, publisher.getUuid()));
    }

    @Test
    public void deleteNotificationPublisherWithLinkedNotificationRulesTest() {
        NotificationPublisher publisher = qm.createNotificationPublisher(
                "Example Publisher", "Publisher description",
                SendMailPublisher.class, "template", "text/html",
                false
        );
        NotificationRule firstRule = qm.createNotificationRule("Example Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        NotificationRule secondRule = qm.createNotificationRule("Example Rule 2", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER + "/" + publisher.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(204, response.getStatus(), 0);
        Assert.assertNull(qm.getObjectByUuid(NotificationPublisher.class, publisher.getUuid()));
        Assert.assertNull(qm.getObjectByUuid(NotificationRule.class, firstRule.getUuid()));
        Assert.assertNull(qm.getObjectByUuid(NotificationRule.class, secondRule.getUuid()));
    }

    @Test
    public void deleteUnknownNotificationPublisherTest() {
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER + "/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void deleteDefaultNotificationPublisherTest() {
        NotificationPublisher notificationPublisher = qm.getDefaultNotificationPublisher(SendMailPublisher.class);
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER + "/" + notificationPublisher.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("Deleting a default notification publisher is forbidden.", body);
    }

    @Test
    public void testSmtpPublisherConfigTest() {
        Form form = new Form();
        form.param("destination", "test@example.com");
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER + "/test/smtp").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assert.assertEquals(200, response.getStatus(), 0);
    }

    @Test
    public void testNotificationRuleTest() {
        NotificationPublisher publisher = qm.createNotificationPublisher(
                "Example Publisher", "Publisher description",
                SlackPublisher.class, "template", "text/html",
                false);

        NotificationRule rule = qm.createNotificationRule("Example Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);

        Set<NotificationGroup> groups = new HashSet<>(Set.of(NotificationGroup.BOM_CONSUMED, NotificationGroup.BOM_PROCESSED, NotificationGroup.BOM_PROCESSING_FAILED,
                NotificationGroup.BOM_VALIDATION_FAILED, NotificationGroup.NEW_VULNERABILITY, NotificationGroup.NEW_VULNERABLE_DEPENDENCY,
                NotificationGroup.POLICY_VIOLATION, NotificationGroup.PROJECT_CREATED, NotificationGroup.PROJECT_AUDIT_CHANGE,
                NotificationGroup.VEX_CONSUMED, NotificationGroup.VEX_PROCESSED));
        rule.setNotifyOn(groups);

        rule.setPublisherConfig("{\"destination\":\"https://example.com/webhook\"}");

        Response sendMailResponse = jersey.target(V1_NOTIFICATION_PUBLISHER + "/test/" + rule.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity("", MediaType.APPLICATION_FORM_URLENCODED_TYPE));

        Assert.assertEquals(200, sendMailResponse.getStatus());
    }

    @Test
    public void testScheduledNotificationRuleTest() {
        final var notificationPublisher = qm.getDefaultNotificationPublisher(WebhookPublisher.class);
        final NotificationRule rule = qm.createScheduledNotificationRule(
                "rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, notificationPublisher);
        rule.setNotifyOn(
                Arrays.stream(NotificationGroup.values())
                        .filter(group -> group.getSupportedTriggerType() == NotificationTriggerType.SCHEDULE)
                        .collect(Collectors.toSet()));

        final var wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();
        try {
            rule.setPublisherConfig("{\"destination\":\"%s\"}".formatted(wireMock.baseUrl()));

            wireMock.stubFor(WireMock.post(WireMock.anyUrl())
                    .willReturn(aResponse()
                            .withStatus(200)));

            final Response response = jersey.target(V1_NOTIFICATION_PUBLISHER + "/test/" + rule.getUuid()).request()
                    .header(X_API_KEY, apiKey)
                    .post(Entity.entity("", MediaType.APPLICATION_FORM_URLENCODED_TYPE));
            assertThat(response.getStatus()).isEqualTo(200);

            await("Notification Delivery")
                    .atMost(Duration.ofSeconds(5))
                    .untilAsserted(() -> wireMock.verify(rule.getNotifyOn().size(), anyRequestedFor(anyUrl())));
        } finally {
            wireMock.stop();
        }
    }

    @Test
    public void testNotificationRuleJiraTest() throws Exception {
        new DefaultObjectGenerator().loadDefaultNotificationPublishers();

        final NotificationPublisher jiraPublisher = qm.getNotificationPublisher(
                DefaultNotificationPublishers.JIRA.getPublisherName());
        assertThat(jiraPublisher).isNotNull();

        final var notificationRule = new NotificationRule();
        notificationRule.setPublisher(jiraPublisher);
        notificationRule.setPublisherConfig("""
                {
                  "destination": "FOO",
                  "jiraTicketType": "Task"
                }
                """);
        notificationRule.setName("Jira Test");
        notificationRule.setNotifyOn(Set.of(NotificationGroup.NEW_VULNERABILITY));
        notificationRule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        notificationRule.setScope(NotificationScope.PORTFOLIO);
        notificationRule.setTriggerType(NotificationTriggerType.EVENT);
        qm.persist(notificationRule);

        final var wireMock = new WireMockServer(options().dynamicPort());
        wireMock.start();

        try {
            qm.createConfigProperty(
                    ConfigPropertyConstants.JIRA_URL.getGroupName(),
                    ConfigPropertyConstants.JIRA_URL.getPropertyName(),
                    wireMock.baseUrl(),
                    ConfigPropertyConstants.JIRA_URL.getPropertyType(),
                    ConfigPropertyConstants.JIRA_URL.getDescription());
            qm.createConfigProperty(
                    ConfigPropertyConstants.JIRA_PASSWORD.getGroupName(),
                    ConfigPropertyConstants.JIRA_PASSWORD.getPropertyName(),
                    DataEncryption.encryptAsString("authToken"),
                    ConfigPropertyConstants.JIRA_PASSWORD.getPropertyType(),
                    ConfigPropertyConstants.JIRA_PASSWORD.getDescription());

            wireMock.stubFor(WireMock.post(WireMock.anyUrl())
                    .willReturn(aResponse()
                            .withStatus(200)));

            final Response response = jersey.target(V1_NOTIFICATION_PUBLISHER + "/test/" + notificationRule.getUuid()).request()
                    .header(X_API_KEY, apiKey)
                    .post(null);
            assertThat(response.getStatus()).isEqualTo(200);

            await("Notification Delivery")
                    .atMost(Duration.ofSeconds(5))
                    .untilAsserted(() -> wireMock.verify(postRequestedFor(urlPathEqualTo("/rest/api/2/issue"))
                            .withRequestBody(equalToJson("""
                                    {
                                      "fields" : {
                                        "project" : {
                                          "key" : "FOO"
                                        },
                                        "issuetype" : {
                                          "name" : "Task"
                                        },
                                        "summary" : "[Dependency-Track] [NEW_VULNERABILITY] [MEDIUM] New medium vulnerability identified: INT-001",
                                        "description" : "A new vulnerability has been identified on your project(s).\\n\\\\\\\\\\n\\\\\\\\\\n*Vulnerability description*\\n{code:none|bgColor=white|borderStyle=none}{code}\\n\\n*VulnID*\\nINT-001\\n\\n*Severity*\\nMedium\\n\\n*Component*\\n[componentName : componentVersion|/components/94f87321-a5d1-4c2f-b2fe-95165debebc6]\\n\\n*Affected project(s)*\\n- [projectName (projectVersion)|/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95]\\n"
                                      }
                                    }
                                    """))));
        } finally {
            wireMock.stop();
        }
    }

    @Test
    public void testNotificationRuleNotFoundTest() {
        final Response response = jersey.target(V1_NOTIFICATION_PUBLISHER + "/test/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .post(null);
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void restoreDefaultTemplatesTest() {
        NotificationPublisher slackPublisher = qm.getDefaultNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherClass());
        slackPublisher.setName(slackPublisher.getName() + " Updated");
        qm.persist(slackPublisher);
        qm.detach(NotificationPublisher.class, slackPublisher.getId());
        qm.createConfigProperty(
                ConfigPropertyConstants.NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED.getGroupName(),
                ConfigPropertyConstants.NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED.getPropertyType(),
                ConfigPropertyConstants.NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED.getDescription()
        );
        Response response = jersey.target(V1_NOTIFICATION_PUBLISHER + "/restoreDefaultTemplates").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        qm.getPersistenceManager().refreshAll();
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertFalse(qm.isEnabled(ConfigPropertyConstants.NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED));
        slackPublisher = qm.getDefaultNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherClass());
        Assert.assertEquals(DefaultNotificationPublishers.SLACK.getPublisherName(), slackPublisher.getName());
    }
}
