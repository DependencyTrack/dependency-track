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
package org.dependencytrack.resources.v1;

import alpine.filters.ApiFilter;
import alpine.filters.AuthenticationFilter;
import alpine.notification.NotificationLevel;
import alpine.util.UuidUtil;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Project;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class NotificationRuleResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(NotificationRuleResource.class)
                        .register(ApiFilter.class)
                        .register(AuthenticationFilter.class)))
                .build();
    }

    @Before
    public void before() throws Exception {
        super.before();
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        generator.contextInitialized(null);
    }

    @Test
    public void getAllNotificationRulesTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule r1 = qm.createNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        NotificationRule r2 = qm.createNotificationRule("Rule 2", NotificationScope.PORTFOLIO, NotificationLevel.WARNING, publisher);
        NotificationRule r3 = qm.createNotificationRule("Rule 3", NotificationScope.SYSTEM, NotificationLevel.ERROR, publisher);
        Response response = target(V1_NOTIFICATION_RULE).request()
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
    }

    @Test
    public void createNotificationRuleTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = new NotificationRule();
        rule.setName("Example Rule");
        rule.setEnabled(true);
        rule.setPublisherConfig("{ \"foo\": \"bar\" }");
        rule.setMessage("A message");
        rule.setNotificationLevel(NotificationLevel.WARNING);
        rule.setScope(NotificationScope.SYSTEM);
        rule.setPublisher(publisher);
        Response response = target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(rule, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Example Rule", json.getString("name"));
        Assert.assertTrue(json.getBoolean("enabled"));
        Assert.assertEquals("SYSTEM", json.getString("scope"));
        Assert.assertEquals("WARNING", json.getString("notificationLevel"));
        Assert.assertEquals(0, json.getJsonArray("notifyOn").size());
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
        Assert.assertEquals("Slack", json.getJsonObject("publisher").getString("name"));
    }

    @Test
    public void createNotificationRuleInvalidPublisherTest() {
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
        Response response = target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(rule, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The UUID of the notification publisher could not be found.", body);
    }

    @Test
    public void updateNotificationRuleTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setName("Example Rule");
        rule.setNotifyOn(Collections.singleton(NotificationGroup.NEW_VULNERABILITY));
        Response response = target(V1_NOTIFICATION_RULE).request()
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
    public void updateNotificationRuleInvalidTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule = qm.detach(NotificationRule.class, rule.getId());
        rule.setUuid(UUID.randomUUID());
        Response response = target(V1_NOTIFICATION_RULE).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(rule, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The UUID of the notification rule could not be found.", body);
    }

    //@Test
    // TODO: The workaround for Jersey (DELETE with body) no longer throws an exception, but produces a 400. Unable to test at this time
    public void deleteNotificationRuleTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setName("Example Rule");
        Response response = target(V1_NOTIFICATION_RULE).request()
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
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
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
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        Response response = target(V1_NOTIFICATION_RULE + "/" + UUID.randomUUID().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The notification rule could not be found.", body);
    }

    @Test
    public void addProjectToRuleInvalidScopeTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.SYSTEM, NotificationLevel.INFORMATIONAL, publisher);
        Response response = target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(406, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("Project limitations are only possible on notification rules with PORTFOLIO scope.", body);
    }

    @Test
    public void addProjectToRuleInvalidProjectTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + UUID.randomUUID().toString()).request()
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
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        List<Project> projects = new ArrayList<>();
        projects.add(project);
        rule.setProjects(projects);
        qm.persist(rule);
        Response response = target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void removeProjectFromRuleTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        List<Project> projects = new ArrayList<>();
        projects.add(project);
        rule.setProjects(projects);
        qm.persist(rule);
        Response response = target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void removeProjectFromRuleInvalidRuleTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        Response response = target(V1_NOTIFICATION_RULE + "/" + UUID.randomUUID().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The notification rule could not be found.", body);
    }

    @Test
    public void removeProjectFromRuleInvalidScopeTest() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, true, false);
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.SYSTEM, NotificationLevel.INFORMATIONAL, publisher);
        Response response = target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(406, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("Project limitations are only possible on notification rules with PORTFOLIO scope.", body);
    }

    @Test
    public void removeProjectFromRuleInvalidProjectTest() {
        NotificationPublisher publisher = qm.getNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherName());
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + UUID.randomUUID().toString()).request()
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
        NotificationRule rule = qm.createNotificationRule("Example Rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = target(V1_NOTIFICATION_RULE + "/" + rule.getUuid().toString() + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }
}
