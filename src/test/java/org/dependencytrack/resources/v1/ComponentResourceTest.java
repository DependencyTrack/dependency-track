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
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Test;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.UUID;

public class ComponentResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(ComponentResource.class)
                        .register(ApiFilter.class)
                        .register(AuthenticationFilter.class)))
                .build();
    }

    @Test
    public void getComponentsDefaultRequestTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        for (int i=0; i<1000; i++) {
            Component component = new Component();
            component.setProject(project);
            component.setName("Component Name");
            component.setVersion(String.valueOf(i));
            qm.createComponent(component, false);
        }
        Response response = target(V1_COMPONENT).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(405, response.getStatus()); // No longer prohibited in DT 4.0+
    }

    @Test
    public void getComponentByUuidTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component = qm.createComponent(component, false);
        Response response = target(V1_COMPONENT + "/" + component.getUuid())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getString("name"));
    }

    @Test
    public void getComponentByInvalidUuidTest() {
        Response response = target(V1_COMPONENT + "/" + UUID.randomUUID())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The component could not be found.", body);
    }

    @Test
    public void getComponentByHashTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setSha1("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        component = qm.createComponent(component, false);
        Response response = target(V1_COMPONENT + "/hash/" + component.getSha1())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(response.getHeaderString(TOTAL_COUNT_HEADER), "1");
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getComponentByInvalidHashTest() {
        Response response = target(V1_COMPONENT + "/hash/c5a8829aa3da800216b933e265dd0b97eb6f9341")
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(response.getHeaderString(TOTAL_COUNT_HEADER), "0");
    }

    @Test
    public void createComponentTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        Response response = target(V1_COMPONENT + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(component, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("My Component", json.getString("name"));
        Assert.assertEquals("1.0", json.getString("version"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
    }

    @Test
    public void updateComponentTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        component.setDescription("Test component");
        Response response = target(V1_COMPONENT).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(component, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("My Component", json.getString("name"));
        Assert.assertEquals("1.0", json.getString("version"));
        Assert.assertEquals("Test component", json.getString("description"));
    }

    @Test
    public void updateComponentEmptyNameTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        component.setName(" ");
        Response response = target(V1_COMPONENT).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(component, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
    }

    @Test
    public void deleteComponentTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        Response response = target(V1_COMPONENT + "/" + component.getUuid().toString())
                .request().header(X_API_KEY, apiKey).delete();
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void deleteComponentInvalidUuidTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);
        Response response = target(V1_COMPONENT + "/" + UUID.randomUUID())
                .request().header(X_API_KEY, apiKey).delete();
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void internalComponentIdentificationTest() {
        Response response = target(V1_COMPONENT + "/internal/identify")
                .request().header(X_API_KEY, apiKey).get();
        Assert.assertEquals(204, response.getStatus(), 0);
    }

}
