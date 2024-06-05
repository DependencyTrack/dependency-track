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

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ScheduledNotificationRule;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.dependencytrack.notification.publisher.SendMailPublisher;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import alpine.common.util.UuidUtil;
import alpine.model.Team;
import alpine.notification.NotificationLevel;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class ScheduledNotificationRuleResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(ScheduledNotificationRuleResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));
    
    @Before
    public void before() throws Exception {
        super.before();
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        generator.contextInitialized(null);
    }

    @Test
    public void getAllScheduledNotificationRulesTest(){
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        ScheduledNotificationRule r1 = qm.createScheduledNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        qm.createScheduledNotificationRule("Rule 2", NotificationScope.PORTFOLIO, NotificationLevel.WARNING, publisher);
        qm.createScheduledNotificationRule("Rule 3", NotificationScope.SYSTEM, NotificationLevel.ERROR, publisher);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(3, json.size());
        Assert.assertEquals("Rule 1", json.getJsonObject(0).getString("name"));
        Assert.assertTrue(json.getJsonObject(0).getBoolean("enabled"));
        Assert.assertEquals("PORTFOLIO", json.getJsonObject(0).getString("scope"));
        Assert.assertEquals("INFORMATIONAL", json.getJsonObject(0).getString("notificationLevel"));
        Assert.assertEquals(0, json.getJsonObject(0).getJsonArray("notifyOn").size());
        Assert.assertTrue(UuidUtil.isValidUUID(json.getJsonObject(0).getString("uuid")));
        Assert.assertEquals("Slack", json.getJsonObject(0).getJsonObject("publisher").getString("name"));
        Assert.assertFalse(json.getJsonObject(0).getBoolean("logSuccessfulPublish"));
        Assert.assertEquals(ConfigPropertyConstants.NOTIFICATION_CRON_DEFAULT_EXPRESSION.getDefaultPropertyValue(), json.getJsonObject(0).getString("cronConfig"));
        JsonValue jsonValue = json.getJsonObject(0).get("lastExecutionTime");
        try {
            Assert.assertEquals(r1.getLastExecutionTime(), jsonMapper.readValue(jsonValue.toString(), ZonedDateTime.class).withZoneSameInstant(r1.getLastExecutionTime().getZone()));
        } catch (JsonProcessingException e) {
            Assert.fail();
        }
        Assert.assertFalse(json.getJsonObject(0).getBoolean("publishOnlyWithUpdates"));
    }

    @Test
    public void createScheduledNotificationRuleTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setName("Example Rule");
        rule.setNotificationLevel(NotificationLevel.WARNING);
        rule.setScope(NotificationScope.SYSTEM);
        rule.setPublisher(publisher);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(rule, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Example Rule", json.getString("name"));
        Assert.assertTrue(json.getBoolean("enabled"));
        Assert.assertTrue(json.getBoolean("notifyChildren"));
        Assert.assertFalse(json.getBoolean("logSuccessfulPublish"));
        Assert.assertEquals("SYSTEM", json.getString("scope"));
        Assert.assertEquals("WARNING", json.getString("notificationLevel"));
        Assert.assertEquals(0, json.getJsonArray("notifyOn").size());
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
        Assert.assertEquals("Slack", json.getJsonObject("publisher").getString("name"));
        Assert.assertEquals(ConfigPropertyConstants.NOTIFICATION_CRON_DEFAULT_EXPRESSION.getDefaultPropertyValue(), json.getString("cronConfig"));
        Assert.assertFalse(json.getBoolean("publishOnlyWithUpdates"));
    }

    @Test
    public void createScheduledNotificationRuleInvalidPublisherTest() {
        NotificationPublisher publisher = new NotificationPublisher();
        publisher.setUuid(UUID.randomUUID());
        ScheduledNotificationRule rule = new ScheduledNotificationRule();
        rule.setName("Example Rule");
        rule.setEnabled(true);
        rule.setPublisherConfig("{ \"foo\": \"bar\" }");
        rule.setMessage("A message");
        rule.setNotificationLevel(NotificationLevel.WARNING);
        rule.setScope(NotificationScope.SYSTEM);
        rule.setPublisher(publisher);
        rule.setCronConfig("0 * * * *");
        rule.setLastExecutionTime(ZonedDateTime.now());
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(rule, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The UUID of the notification publisher could not be found.", body);
    }

    @Test
    public void updateScheduledNotificationRuleTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setName("Example Rule");
        rule.setNotifyOn(Collections.singleton(NotificationGroup.NEW_VULNERABILITY));
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(rule, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Example Rule", json.getString("name"));
        Assert.assertTrue(json.getBoolean("enabled"));
        Assert.assertEquals("PORTFOLIO", json.getString("scope"));
        Assert.assertEquals("INFORMATIONAL", json.getString("notificationLevel"));
        Assert.assertEquals("NEW_VULNERABILITY", json.getJsonArray("notifyOn").getString(0));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
        Assert.assertEquals("Slack", json.getJsonObject("publisher").getString("name"));
    }

    @Test
    public void updateScheduledNotificationRuleInvalidTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule = qm.detach(ScheduledNotificationRule.class, rule.getId());
        rule.setUuid(UUID.randomUUID());
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(rule, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The UUID of the scheduled notification rule could not be found.", body);
    }

    @Test
    public void deleteScheduledNotificationRuleTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setName("Example Rule");
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(rule, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void addProjectToRuleTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Example Rule", json.getString("name"));
        Assert.assertEquals(1, json.getJsonArray("projects").size());
        Assert.assertEquals("Acme Example", json.getJsonArray("projects").getJsonObject(0).getString("name"));
        Assert.assertEquals(project.getUuid().toString(), json.getJsonArray("projects").getJsonObject(0).getString("uuid"));
    }

    @Test
    public void addProjectToRuleInvalidRuleTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + UUID.randomUUID().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The scheduled notification rule could not be found.", body);
    }

    @Test
    public void addProjectToRuleInvalidScopeTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.SYSTEM, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(406, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("Project limitations are only possible on scheduled notification rules with PORTFOLIO scope.", body);
    }

    @Test
    public void addProjectToRuleInvalidProjectTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void addProjectToRuleDuplicateProjectTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        List<Project> projects = new ArrayList<>();
        projects.add(project);
        rule.setProjects(projects);
        qm.persist(rule);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void removeProjectFromRuleTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        List<Project> projects = new ArrayList<>();
        projects.add(project);
        rule.setProjects(projects);
        qm.persist(rule);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void removeProjectFromRuleInvalidRuleTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + UUID.randomUUID().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The scheduled notification rule could not be found.", body);
    }

    @Test
    public void removeProjectFromRuleInvalidScopeTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.SYSTEM, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(406, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("Project limitations are only possible on scheduled notification rules with PORTFOLIO scope.", body);
    }

    @Test
    public void removeProjectFromRuleInvalidProjectTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void removeProjectFromRuleDuplicateProjectTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void addTeamToRuleTest(){
        Team team = qm.createTeam("Team Example", false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Example Rule", json.getString("name"));
        Assert.assertEquals(1, json.getJsonArray("teams").size());
        Assert.assertEquals("Team Example", json.getJsonArray("teams").getJsonObject(0).getString("name"));
        Assert.assertEquals(team.getUuid().toString(), json.getJsonArray("teams").getJsonObject(0).getString("uuid"));
    }

    @Test
    public void addTeamToRuleInvalidRuleTest(){
        Team team = qm.createTeam("Team Example", false);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + UUID.randomUUID().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The scheduled notification rule could not be found.", body);
    }

    @Test
    public void addTeamToRuleInvalidTeamTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The team could not be found.", body);
    }

    @Test
    public void addTeamToRuleDuplicateTeamTest() {
        Team team = qm.createTeam("Team Example", false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.EMAIL.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        List<Team> teams = new ArrayList<>();
        teams.add(team);
        rule.setTeams(teams);
        qm.persist(rule);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void addTeamToRuleInvalidPublisherTest(){
        Team team = qm.createTeam("Team Example", false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(406, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("Team subscriptions are only possible on scheduled notification rules with EMAIL publisher.", body);
    }

    @Test
    public void addTeamToRuleWithCustomEmailPublisherTest() {
        final Team team = qm.createTeam("Team Example", false);
        final NotificationPublisher publisher = qm.createNotificationPublisher("foo", "description", SendMailPublisher.class, "template", "templateMimeType", false, true);
        final ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        final ZonedDateTime testTime = ZonedDateTime.parse("2024-05-31T13:24:46Z", DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        rule.setLastExecutionTime(testTime);
        final Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + rule.getUuid() + "/team/" + team.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("publisherUuid", equalTo(publisher.getUuid().toString()))
                .withMatcher("ruleUuid", equalTo(rule.getUuid().toString()))
                .withMatcher("teamUuid", equalTo(team.getUuid().toString()))
                .withMatcher("cronConfig", equalTo(rule.getCronConfig()))
                .isEqualTo("""
                        {
                          "name": "Example Rule",
                          "enabled": true,
                          "notifyChildren": true,
                          "logSuccessfulPublish": false,
                          "scope": "PORTFOLIO",
                          "notificationLevel": "INFORMATIONAL",
                          "projects": [],
                          "teams": [
                            {
                              "uuid": "${json-unit.matches:teamUuid}",
                              "name": "Team Example",
                              "permissions": []
                            }
                          ],
                          "notifyOn": [],
                          "publisher": {
                            "name": "foo",
                            "description": "description",
                            "publisherClass": "org.dependencytrack.notification.publisher.SendMailPublisher",
                            "templateMimeType": "templateMimeType",
                            "defaultPublisher": false,
                            "publishScheduled": true,
                            "uuid": "${json-unit.matches:publisherUuid}"
                          },
                          "uuid": "${json-unit.matches:ruleUuid}",
                          "cronConfig": "${json-unit.matches:cronConfig}",
                          "lastExecutionTime": "2024-05-31T13:24:46Z",
                          "publishOnlyWithUpdates": false
                        }
                        """);
    }

    @Test
    public void removeTeamFromRuleTest() {
        Team team = qm.createTeam("Team Example", false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SCHEDULED_EMAIL.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        List<Team> teams = new ArrayList<>();
        teams.add(team);
        rule.setTeams(teams);
        qm.persist(rule);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void removeTeamFromRuleInvalidRuleTest() {
        Team team = qm.createTeam("Team Example", false);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + UUID.randomUUID().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The scheduled notification rule could not be found.", body);
    }

    @Test
    public void removeTeamFromRuleInvalidTeamTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SCHEDULED_EMAIL.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The team could not be found.", body);
    }

    @Test
    public void removeTeamFromRuleDuplicateTeamTest() {
        Team team = qm.createTeam("Team Example", false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SCHEDULED_EMAIL.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void removeTeamToRuleInvalidPublisherTest(){
        Team team = qm.createTeam("Team Example", false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/team/" + team.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(406, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("Team subscriptions are only possible on scheduled notification rules with EMAIL publisher.", body);
    }

    @Test
    public void executeScheduledNotificationRuleNowTest(){
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SCHEDULED_EMAIL.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/execute").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(rule, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Example Rule", json.getString("name"));
        Assert.assertEquals(rule.getUuid().toString(), json.getString("uuid"));
    }

    @Test
    public void executeScheduledNotificationRuleNowInvalidRuleTest(){
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SCHEDULED_EMAIL.getPublisherName());
        ScheduledNotificationRule rule = qm.createScheduledNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        // detach the rule to uncouple from database, else setUuid(...) will update the persistent entry and the request will be valid with http code 200
        rule = qm.detach(ScheduledNotificationRule.class, rule.getId());
        rule.setUuid(UUID.randomUUID());
        Response response = jersey.target(V1_SCHEDULED_NOTIFICATION_RULE + "/execute").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(rule, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The UUID of the scheduled notification rule could not be found.", body);
    }
}