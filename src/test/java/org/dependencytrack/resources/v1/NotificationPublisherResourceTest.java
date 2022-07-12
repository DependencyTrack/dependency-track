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

import alpine.common.util.UuidUtil;
import alpine.model.ConfigProperty;
import alpine.notification.NotificationLevel;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.dependencytrack.notification.publisher.Publisher;
import org.dependencytrack.notification.publisher.SendMailPublisher;
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
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.UUID;

public class NotificationPublisherResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(NotificationPublisherResource.class)
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
    public void getAllNotificationPublishersTest() {
        Response response = target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(7, json.size());
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
        Response response = target(V1_NOTIFICATION_PUBLISHER).request()
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
        Response response = target(V1_NOTIFICATION_PUBLISHER).request()
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
        Response response = target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(publisher, MediaType.APPLICATION_JSON));
        Assert.assertEquals(409, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("The notification with the name "+DefaultNotificationPublishers.SLACK.getPublisherName()+" already exist", body);
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
        Response response = target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(publisher, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("The class "+NotificationPublisherResource.class.getName()+" does not implement "+ Publisher.class.getName(), body);
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
        Response response = target(V1_NOTIFICATION_PUBLISHER).request()
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
                (Class) SendMailPublisher.class, "template", "text/html",
                false
        );
        notificationPublisher.setName("Updated Publisher name");
        Response response = target(V1_NOTIFICATION_PUBLISHER).request()
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
                (Class) SendMailPublisher.class, "template", "text/html",
                false
        );
        notificationPublisher = qm.detach(NotificationPublisher.class, notificationPublisher.getId());
        notificationPublisher.setUuid(UUID.randomUUID());
        Response response = target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(notificationPublisher, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The UUID of the notification publisher could not be found.", body);
    }

    @Test
    public void updateExistingDefaultNotificationPublisherTest() {
        NotificationPublisher notificationPublisher = qm.getDefaultNotificationPublisher((Class) SendMailPublisher.class);
        notificationPublisher.setName(notificationPublisher.getName() + " Updated");
        Response response = target(V1_NOTIFICATION_PUBLISHER).request()
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
                (Class) SendMailPublisher.class, "template", "text/html",
                false
        );
        notificationPublisher = qm.detach(NotificationPublisher.class, notificationPublisher.getId());
        notificationPublisher.setName(DefaultNotificationPublishers.MS_TEAMS.getPublisherName());
        Response response = target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(notificationPublisher, MediaType.APPLICATION_JSON));
        Assert.assertEquals(409, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("An existing publisher with the name '"+DefaultNotificationPublishers.MS_TEAMS.getPublisherName()+"' already exist", body);
    }

    @Test
    public void updateNotificationPublisherWithInvalidClassTest() {
        NotificationPublisher notificationPublisher = qm.createNotificationPublisher(
                "Example Publisher", "Publisher description",
                (Class) SendMailPublisher.class, "template", "text/html",
                false
        );
        notificationPublisher.setPublisherClass("unknownClass");
        Response response = target(V1_NOTIFICATION_PUBLISHER).request()
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
                (Class) SendMailPublisher.class, "template", "text/html",
                false
        );
        notificationPublisher.setPublisherClass(NotificationPublisherResource.class.getName());
        Response response = target(V1_NOTIFICATION_PUBLISHER).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(notificationPublisher, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The class "+NotificationPublisherResource.class.getName()+" does not implement "+ Publisher.class.getName(), body);
    }

    @Test
    public void deleteNotificationPublisherWithNoRulesTest() {
        NotificationPublisher publisher = qm.createNotificationPublisher(
                "Example Publisher", "Publisher description",
                (Class) SendMailPublisher.class, "template", "text/html",
                false
        );
        Response response = target(V1_NOTIFICATION_PUBLISHER + "/" + publisher.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(204, response.getStatus(), 0);
        Assert.assertNull(qm.getObjectByUuid(NotificationPublisher.class, publisher.getUuid()));
    }

    @Test
    public void deleteNotificationPublisherWithLinkedNotificationRulesTest() {
        NotificationPublisher publisher = qm.createNotificationPublisher(
                "Example Publisher", "Publisher description",
                (Class) SendMailPublisher.class, "template", "text/html",
                false
        );
        NotificationRule firstRule = qm.createNotificationRule("Example Rule 1", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        NotificationRule secondRule = qm.createNotificationRule("Example Rule 2", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        Response response = target(V1_NOTIFICATION_PUBLISHER + "/" + publisher.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(204, response.getStatus(), 0);
        Assert.assertNull(qm.getObjectByUuid(NotificationPublisher.class, publisher.getUuid()));
        Assert.assertNull(qm.getObjectByUuid(NotificationRule.class, firstRule.getUuid()));
        Assert.assertNull(qm.getObjectByUuid(NotificationRule.class, secondRule.getUuid()));
    }

    @Test
    public void deleteUnknownNotificationPublisherTest() {
        Response response = target(V1_NOTIFICATION_PUBLISHER + "/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void deleteDefaultNotificationPublisherTest() {
        NotificationPublisher notificationPublisher = qm.getDefaultNotificationPublisher((Class) SendMailPublisher.class);
        Response response = target(V1_NOTIFICATION_PUBLISHER + "/" + notificationPublisher.getUuid()).request()
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
        Response response = target(V1_NOTIFICATION_PUBLISHER + "/test/smtp").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assert.assertEquals(200, response.getStatus(), 0);
    }

    @Test
    public void restoreDefaultTemplatesTest() {
        NotificationPublisher slackPublisher = qm.getDefaultNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherClass());
        slackPublisher.setName(slackPublisher.getName()+" Updated");
        qm.persist(slackPublisher);
        qm.detach(NotificationPublisher.class, slackPublisher.getId());
        ConfigProperty property = qm.getConfigProperty(
                ConfigPropertyConstants.NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED.getGroupName(),
                ConfigPropertyConstants.NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED.getPropertyName()
        );
        property.setPropertyValue("true");
        qm.persist(property);
        qm.detach(ConfigProperty.class, property.getId());
        Response response = target(V1_NOTIFICATION_PUBLISHER + "/restoreDefaultTemplates").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        qm.getPersistenceManager().refreshAll();
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertFalse(qm.isEnabled(ConfigPropertyConstants.NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED));
        slackPublisher = qm.getDefaultNotificationPublisher(DefaultNotificationPublishers.SLACK.getPublisherClass());
        Assert.assertEquals(DefaultNotificationPublishers.SLACK.getPublisherName(), slackPublisher.getName());
    }
}
