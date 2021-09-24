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
import alpine.util.UuidUtil;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import javax.json.JsonArray;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

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
        Assert.assertEquals(6, json.size());
        Assert.assertEquals("Console", json.getJsonObject(1).getString("name"));
        Assert.assertEquals("Displays notifications on the system console", json.getJsonObject(1).getString("description"));
        Assert.assertEquals("text/plain", json.getJsonObject(1).getString("templateMimeType"));
        Assert.assertNotNull("template");
        Assert.assertTrue(json.getJsonObject(1).getBoolean("defaultPublisher"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getJsonObject(1).getString("uuid")));
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
}
