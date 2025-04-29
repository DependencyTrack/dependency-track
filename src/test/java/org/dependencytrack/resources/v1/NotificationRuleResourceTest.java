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
import alpine.model.Team;
import alpine.notification.NotificationLevel;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Project;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.dependencytrack.notification.publisher.SendMailPublisher;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;

class NotificationRuleResourceTest extends ResourceTest {

    @RegisterExtension
    public static JerseyTestExtension jersey = new JerseyTestExtension(
            () -> new ResourceConfig(NotificationRuleResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @BeforeEach
    public void before() throws Exception {
        final var generator = new DefaultObjectGenerator();
        generator.loadDefaultNotificationPublishers();
    }

    @Test
    void getAllNotificationRulesTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule r1 = qm.createNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        NotificationRule r2 = qm.createNotificationRule("Rule 2", NotificationScope.PORTFOLIO, NotificationLevel.WARNING, publisher);
        NotificationRule r3 = qm.createNotificationRule("Rule 3", NotificationScope.SYSTEM, NotificationLevel.ERROR, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(3, json.size());
        Assertions.assertEquals("Rule 1", json.getJsonObject(0).getString("name"));
        Assertions.assertTrue(json.getJsonObject(0).getBoolean("enabled"));
        Assertions.assertEquals("PORTFOLIO", json.getJsonObject(0).getString("scope"));
        Assertions.assertEquals("INFORMATIONAL", json.getJsonObject(0).getString("notificationLevel"));
        Assertions.assertEquals(0, json.getJsonObject(0).getJsonArray("notifyOn").size());
        Assertions.assertTrue(UuidUtil.isValidUUID(json.getJsonObject(0).getString("uuid")));
        Assertions.assertEquals("Slack", json.getJsonObject(0).getJsonObject("publisher").getString("name"));
    }

    @Test
    void createNotificationRuleTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = new NotificationRule();
        rule.setName("Example Rule");
        rule.setEnabled(true);
        rule.setPublisherConfig("{ \"foo\": \"bar\" }");
        rule.setMessage("A message");
        rule.setNotificationLevel(NotificationLevel.WARNING);
        rule.setScope(NotificationScope.SYSTEM);
        rule.setPublisher(publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(rule, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("Example Rule", json.getString("name"));
        Assertions.assertTrue(json.getBoolean("enabled"));
        Assertions.assertEquals("SYSTEM", json.getString("scope"));
        Assertions.assertEquals("WARNING", json.getString("notificationLevel"));
        Assertions.assertEquals(0, json.getJsonArray("notifyOn").size());
        Assertions.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
        Assertions.assertEquals("Slack", json.getJsonObject("publisher").getString("name"));
    }

    @Test
    void createNotificationRuleInvalidPublisherTest() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setUuid(UUID.randomUUID());
        NotificationRule rule = new NotificationRule();
        rule.setName("Example Rule");
        rule.setEnabled(true);
        rule.setPublisherConfig("{ \"foo\": \"bar\" }");
        rule.setMessage("A message");
        rule.setNotificationLevel(NotificationLevel.WARNING);
        rule.setScope(NotificationScope.SYSTEM);
        rule.setPublisher(publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(rule, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The UUID of the notification rule could not be found.", body);
    }

    @Test
    public void createScheduledNotificationRuleTest() {
        final NotificationPublisher publisher = qm.getNotificationPublisher(
                DefaultNotificationPublishers.SLACK.getPublisherName());

        final Response response = jersey.target(V1_NOTIFICATION_RULE + "/scheduled")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "foo",
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "publisher": {
                            "uuid": "%s"
                          }
                        }
                        """.formatted(publisher.getUuid())));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "name": "foo",
                  "enabled": false,
                  "notifyChildren": false,
                  "logSuccessfulPublish": false,
                  "scope": "PORTFOLIO",
                  "notificationLevel": "INFORMATIONAL",
                  "projects": [],
                  "tags": [],
                  "teams": [],
                  "notifyOn": [],
                  "notifySeverities": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED"],
                  "publisher": {
                    "name": "Slack",
                    "description": "${json-unit.any-string}",
                    "publisherClass": "${json-unit.any-string}",
                    "templateMimeType": "${json-unit.any-string}",
                    "defaultPublisher": true,
                    "uuid": "${json-unit.any-string}"
                  },
                  "triggerType":"SCHEDULE",
                  "scheduleLastTriggeredAt": "${json-unit.any-number}",
                  "scheduleNextTriggerAt": "${json-unit.any-number}",
                  "scheduleCron": "0 * * * *",
                  "scheduleSkipUnchanged": false,
                  "uuid": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    public void createScheduledNotificationRuleWithNonExistentPublisherTest() {
        final Response response = jersey.target(V1_NOTIFICATION_RULE + "/scheduled")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "foo",
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "publisher": {
                            "uuid": "1228b979-c449-432b-8b56-e00fe69e0d3c"
                          }
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "Notification publisher could not be found"
                }
                """);
    }

    @Test
    void updateNotificationRuleTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setName("Example Rule");
        rule.setNotifyOn(Collections.singleton(NotificationGroup.NEW_VULNERABILITY));
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(rule, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("Example Rule", json.getString("name"));
        Assertions.assertTrue(json.getBoolean("enabled"));
        Assertions.assertEquals("PORTFOLIO", json.getString("scope"));
        Assertions.assertEquals("INFORMATIONAL", json.getString("notificationLevel"));
        Assertions.assertEquals("NEW_VULNERABILITY", json.getJsonArray("notifyOn").getString(0));
        Assertions.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
        Assertions.assertEquals("Slack", json.getJsonObject("publisher").getString("name"));
    }

    @Test
    void updateNotificationRuleInvalidTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule = qm.detach(NotificationRule.class, rule.getId());
        rule.setUuid(UUID.randomUUID());
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(rule, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The UUID of the notification rule could not be found.", body);
    }

    @Test
    void updateNotificationRuleWithTagsTest() {
        final NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        final NotificationRule rule = qm.createNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);

        // Tag the rule with "foo" and "bar".
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "Rule 1",
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "tags": [
                            {
                              "name": "foo"
                            },
                            {
                              "name": "bar"
                            }
                          ]
                        }
                        """.formatted(rule.getUuid()), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .withMatcher("ruleUuid", equalTo(rule.getUuid().toString()))
                .isEqualTo(/* language=JSON */ """
                        {
                          "name": "Rule 1",
                          "enabled": false,
                          "notifyChildren": false,
                          "logSuccessfulPublish": false,
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "triggerType": "EVENT",
                          "projects": [],
                          "tags": [
                            {
                              "name": "foo"
                            },
                            {
                              "name": "bar"
                            }
                          ],
                          "teams": [],
                          "notifyOn": [],
                          "notifySeverities": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED"],
                          "publisher": {
                            "name": "${json-unit.any-string}",
                            "description": "${json-unit.any-string}",
                            "publisherClass": "${json-unit.any-string}",
                            "templateMimeType": "${json-unit.any-string}",
                            "defaultPublisher": true,
                            "uuid": "${json-unit.any-string}"
                          },
                          "uuid": "${json-unit.matches:ruleUuid}"
                        }
                        """);

        // Replace the previous tags with only "baz".
        response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "Rule 1",
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "tags": [
                            {
                              "name": "baz"
                            }
                          ]
                        }
                        """.formatted(rule.getUuid()), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("ruleUuid", equalTo(rule.getUuid().toString()))
                .isEqualTo(/* language=JSON */ """
                        {
                          "name": "Rule 1",
                          "enabled": false,
                          "notifyChildren": false,
                          "logSuccessfulPublish": false,
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "triggerType": "EVENT",
                          "projects": [],
                          "tags": [
                            {
                              "name": "baz"
                            }
                          ],
                          "teams": [],
                          "notifyOn": [],
                          "notifySeverities": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED"],
                          "publisher": {
                            "name": "${json-unit.any-string}",
                            "description": "${json-unit.any-string}",
                            "publisherClass": "${json-unit.any-string}",
                            "templateMimeType": "${json-unit.any-string}",
                            "defaultPublisher": true,
                            "uuid": "${json-unit.any-string}"
                          },
                          "uuid": "${json-unit.matches:ruleUuid}"
                        }
                        """);
    }

    @Test
    public void updateNotificationRuleWithDifferentTriggerTypeTest() {
        final NotificationPublisher publisher = qm.getNotificationPublisher(
                DefaultNotificationPublishers.SLACK.getPublisherName());
        final NotificationRule rule = qm.createNotificationRule(
                "Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);

        final Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "Rule 1",
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "triggerType": "SCHEDULE"
                        }
                        """.formatted(rule.getUuid())));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 400,
                  "title": "Illegal argument provided",
                  "detail": "Trigger type can not be changed"
                }
                """);
    }

    @Test
    public void updateNotificationRuleWithGroupUnsupportedForScheduleTest() {
        final NotificationPublisher publisher = qm.getNotificationPublisher(
                DefaultNotificationPublishers.SLACK.getPublisherName());
        final NotificationRule rule = qm.createScheduledNotificationRule(
                "Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);

        final Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "Rule 1",
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "notifyOn": ["BOM_PROCESSED", "NEW_VULNERABILITIES_SUMMARY"]
                        }
                        """.formatted(rule.getUuid())));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 400,
                  "title": "Illegal argument provided",
                  "detail": "Groups [BOM_PROCESSED] are not supported for trigger type SCHEDULE"
                }
                """);
    }

    @Test
    public void updateNotificationRuleWithNewCronExpressionTest() {
        final NotificationPublisher publisher = qm.getNotificationPublisher(
                DefaultNotificationPublishers.SLACK.getPublisherName());
        final NotificationRule rule = qm.createScheduledNotificationRule(
                "Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);

        final Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "Rule 1",
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "notifyOn": ["NEW_VULNERABILITIES_SUMMARY"],
                          "triggerType": "SCHEDULE",
                          "scheduleCron": "6 6 6 6 6"
                        }
                        """.formatted(rule.getUuid())));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("unmodifiedScheduleLastTriggeredAt", equalTo(BigDecimal.valueOf(rule.getScheduleLastTriggeredAt().getTime())))
                .withMatcher("modifiedScheduleNextTriggerAt", greaterThan(BigDecimal.valueOf(rule.getScheduleNextTriggerAt().getTime())))
                .whenIgnoringPaths("$.publisher")
                .isEqualTo(/* language=JSON */ """
                        {
                          "name":"Rule 1",
                          "enabled": false,
                          "notifyChildren": false,
                          "logSuccessfulPublish": false,
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "projects": [],
                          "tags": [],
                          "teams": [],
                          "notifyOn": ["NEW_VULNERABILITIES_SUMMARY"],
                          "notifySeverities": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED"],
                          "triggerType": "SCHEDULE",
                          "scheduleLastTriggeredAt": "${json-unit.matches:unmodifiedScheduleLastTriggeredAt}",
                          "scheduleNextTriggerAt": "${json-unit.matches:modifiedScheduleNextTriggerAt}",
                          "scheduleCron": "6 6 6 6 6",
                          "uuid": "${json-unit.any-string}"
                        }
                        """);
    }

    @Test
    public void updateNotificationRuleWithInvalidCronExpressionTest() {
        final NotificationPublisher publisher = qm.getNotificationPublisher(
                DefaultNotificationPublishers.SLACK.getPublisherName());
        final NotificationRule rule = qm.createScheduledNotificationRule(
                "Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);

        final Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "Rule 1",
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "notifyOn": ["NEW_VULNERABILITIES_SUMMARY"],
                          "triggerType": "SCHEDULE",
                          "scheduleCron": "not valid at all"
                        }
                        """.formatted(rule.getUuid())));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "message": "The cron expression must be valid",
                    "messageTemplate": "The cron expression must be valid",
                    "path": "scheduleCron",
                    "invalidValue": "not valid at all"
                  }
                ]
                """);
    }

    @Test
    void deleteNotificationRuleTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setName("Example Rule");
        Response response = jersey.target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(rule, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assertions.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    void addProjectToRuleTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("Example Rule", json.getString("name"));
        Assertions.assertEquals(1, json.getJsonArray("projects").size());
        Assertions.assertEquals("Acme Example", json.getJsonArray("projects").getJsonObject(0).getString("name"));
        Assertions.assertEquals(project.getUuid().toString(), json.getJsonArray("projects").getJsonObject(0).getString("uuid"));
    }

    @Test
    void addProjectToRuleInvalidRuleTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + UUID.randomUUID().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The notification rule could not be found.", body);
    }

    @Test
    void addProjectToRuleInvalidScopeTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.SYSTEM, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(406, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("Project limitations are only possible on notification rules with PORTFOLIO scope.", body);
    }

    @Test
    void addProjectToRuleInvalidProjectTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The project could not be found.", body);
    }

    @Test
    void addProjectToRuleDuplicateProjectTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        List<Project> projects = new ArrayList<>();
        projects.add(project);
        rule.setProjects(projects);
        qm.persist(rule);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(304, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    void removeProjectFromRuleTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        List<Project> projects = new ArrayList<>();
        projects.add(project);
        rule.setProjects(projects);
        qm.persist(rule);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    void removeProjectFromRuleInvalidRuleTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + UUID.randomUUID().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The notification rule could not be found.", body);
    }

    @Test
    void removeProjectFromRuleInvalidScopeTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.SYSTEM, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(406, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("Project limitations are only possible on notification rules with PORTFOLIO scope.", body);
    }

    @Test
    void removeProjectFromRuleInvalidProjectTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The project could not be found.", body);
    }

    @Test
    void removeProjectFromRuleDuplicateProjectTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(304, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    void addTeamToRuleTest(){
        Team team = qm.createTeam("Team Example");
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("Example Rule", json.getString("name"));
        Assertions.assertEquals(1, json.getJsonArray("teams").size());
        Assertions.assertEquals("Team Example", json.getJsonArray("teams").getJsonObject(0).getString("name"));
        Assertions.assertEquals(team.getUuid().toString(), json.getJsonArray("teams").getJsonObject(0).getString("uuid"));
    }

    @Test
    void addTeamToRuleInvalidRuleTest(){
        Team team = qm.createTeam("Team Example");
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + UUID.randomUUID().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The notification rule could not be found.", body);
    }

    @Test
    void addTeamToRuleInvalidTeamTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The team could not be found.", body);
    }

    @Test
    void addTeamToRuleDuplicateTeamTest() {
        Team team = qm.createTeam("Team Example");
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        List<Team> teams = new ArrayList<>();
        teams.add(team);
        rule.setTeams(teams);
        qm.persist(rule);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(304, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    void addTeamToRuleInvalidPublisherTest(){
        Team team = qm.createTeam("Team Example");
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assertions.assertEquals(406, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("Team subscriptions are only possible on notification rules with EMAIL publisher.", body);
    }

    @Test
    void addTeamToRuleWithCustomEmailPublisherTest() {
        final Team team = qm.createTeam("Team Example");
        final NotificationPublisher publisher = qm.createNotificationPublisher("foo", "description", SendMailPublisher.class, "template", "templateMimeType", false);
        final NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        final Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid() + "/team/" + team.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("publisherUuid", equalTo(publisher.getUuid().toString()))
                .withMatcher("ruleUuid", equalTo(rule.getUuid().toString()))
                .withMatcher("teamUuid", equalTo(team.getUuid().toString()))
                .isEqualTo(/* language=JSON */ """
                        {
                          "name": "Example Rule",
                          "enabled": true,
                          "notifyChildren": true,
                          "logSuccessfulPublish": false,
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "triggerType": "EVENT",
                          "projects": [],
                          "tags": [],
                          "teams": [
                            {
                              "uuid": "${json-unit.matches:teamUuid}",
                              "name": "Team Example",
                              "permissions": []
                            }
                          ],
                          "notifyOn": [],
                          "notifySeverities": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED"],
                          "publisher": {
                            "name": "foo",
                            "description": "description",
                            "publisherClass": "org.dependencytrack.notification.publisher.SendMailPublisher",
                            "templateMimeType": "templateMimeType",
                            "defaultPublisher": false,
                            "uuid": "${json-unit.matches:publisherUuid}"
                          },
                          "uuid": "${json-unit.matches:ruleUuid}"
                        }
                        """);
    }

    @Test
    void removeTeamFromRuleTest() {
        Team team = qm.createTeam("Team Example");
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        List<Team> teams = new ArrayList<>();
        teams.add(team);
        rule.setTeams(teams);
        qm.persist(rule);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    void removeTeamFromRuleInvalidRuleTest() {
        Team team = qm.createTeam("Team Example");
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + UUID.randomUUID().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The notification rule could not be found.", body);
    }

    @Test
    void removeTeamFromRuleInvalidTeamTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The team could not be found.", body);
    }

    @Test
    void removeTeamFromRuleDuplicateTeamTest() {
        Team team = qm.createTeam("Team Example");
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(304, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    void removeTeamToRuleInvalidPublisherTest(){
        Team team = qm.createTeam("Team Example");
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(406, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("Team subscriptions are only possible on notification rules with EMAIL publisher.", body);
    }
}
