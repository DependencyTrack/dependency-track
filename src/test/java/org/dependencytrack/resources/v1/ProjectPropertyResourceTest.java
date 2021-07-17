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
import alpine.model.IConfigProperty;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectProperty;
import org.glassfish.jersey.client.ClientProperties;
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

public class ProjectPropertyResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(ProjectPropertyResource.class)
                        .register(ApiFilter.class)
                        .register(AuthenticationFilter.class)))
                .build();
    }

    @Test
    public void getPropertiesTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        qm.createProjectProperty(project, "mygroup", "prop1", "value1", IConfigProperty.PropertyType.STRING, "Test Property 1");
        qm.createProjectProperty(project, "mygroup", "prop2", "value2", IConfigProperty.PropertyType.ENCRYPTEDSTRING, "Test Property 2");
        Response response = target(V1_PROJECT + "/" + project.getUuid().toString() + "/property").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(2, json.size());
        Assert.assertEquals("mygroup", json.getJsonObject(0).getString("groupName"));
        Assert.assertEquals("prop1", json.getJsonObject(0).getString("propertyName"));
        Assert.assertEquals("value1", json.getJsonObject(0).getString("propertyValue"));
        Assert.assertEquals("STRING", json.getJsonObject(0).getString("propertyType"));
        Assert.assertEquals("Test Property 1", json.getJsonObject(0).getString("description"));
        Assert.assertEquals("mygroup", json.getJsonObject(1).getString("groupName"));
        Assert.assertEquals("prop2", json.getJsonObject(1).getString("propertyName"));
        Assert.assertEquals("HiddenDecryptedPropertyPlaceholder", json.getJsonObject(1).getString("propertyValue"));
        Assert.assertEquals("ENCRYPTEDSTRING", json.getJsonObject(1).getString("propertyType"));
        Assert.assertEquals("Test Property 2", json.getJsonObject(1).getString("description"));
    }

    @Test
    public void getPropertiesInvalidTest() {
       Response response = target(V1_PROJECT + "/" + UUID.randomUUID().toString() + "/property").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void createPropertyTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("mygroup");
        property.setPropertyName("prop1");
        property.setPropertyValue("value1");
        property.setPropertyType(IConfigProperty.PropertyType.STRING);
        property.setDescription("Test Property 1");
        Response response = target(V1_PROJECT + "/" + project.getUuid().toString() + "/property").request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(property, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("mygroup", json.getString("groupName"));
        Assert.assertEquals("prop1", json.getString("propertyName"));
        Assert.assertEquals("value1", json.getString("propertyValue"));
        Assert.assertEquals("STRING", json.getString("propertyType"));
        Assert.assertEquals("Test Property 1", json.getString("description"));
    }

    @Test
    public void createPropertyEncryptedTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("mygroup");
        property.setPropertyName("prop1");
        property.setPropertyValue("value1");
        property.setPropertyType(IConfigProperty.PropertyType.ENCRYPTEDSTRING);
        property.setDescription("Test Property 1");
        Response response = target(V1_PROJECT + "/" + project.getUuid().toString() + "/property").request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(property, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("mygroup", json.getString("groupName"));
        Assert.assertEquals("prop1", json.getString("propertyName"));
        Assert.assertEquals("HiddenDecryptedPropertyPlaceholder", json.getString("propertyValue"));
        Assert.assertEquals("ENCRYPTEDSTRING", json.getString("propertyType"));
        Assert.assertEquals("Test Property 1", json.getString("description"));
    }

    @Test
    public void createPropertyDuplicateTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        qm.createProjectProperty(project, "mygroup", "prop1", "value1", IConfigProperty.PropertyType.STRING, null);
        String uuid = project.getUuid().toString();
        qm.close();
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("mygroup");
        property.setPropertyName("prop1");
        property.setPropertyValue("value1");
        property.setPropertyType(IConfigProperty.PropertyType.STRING);
        property.setDescription("Test Property 1");
        Response response = target(V1_PROJECT + "/" + uuid + "/property").request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(property, MediaType.APPLICATION_JSON));
        Assert.assertEquals(409, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("A property with the specified project/group/name combination already exists.", body);
    }

    @Test
    public void createPropertyInvalidTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("mygroup");
        property.setPropertyName("prop1");
        property.setPropertyValue("value1");
        property.setPropertyType(IConfigProperty.PropertyType.STRING);
        property.setDescription("Test Property 1");
        Response response = target(V1_PROJECT + "/" + UUID.randomUUID() + "/property").request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(property, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void updatePropertyTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        String uuid = project.getUuid().toString();
        ProjectProperty property = qm.createProjectProperty(project, "mygroup", "prop1", "value1", IConfigProperty.PropertyType.STRING, null);
        qm.getPersistenceManager().detachCopy(property);
        qm.close();
        property.setPropertyValue("updatedValue");
        Response response = target(V1_PROJECT + "/" + uuid + "/property").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(property, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("mygroup", json.getString("groupName"));
        Assert.assertEquals("prop1", json.getString("propertyName"));
        Assert.assertEquals("updatedValue", json.getString("propertyValue"));
        Assert.assertEquals("STRING", json.getString("propertyType"));
    }

    @Test
    public void updatePropertyInvalidTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("mygroup");
        property.setPropertyName("prop1");
        property.setPropertyValue("value1");
        property.setPropertyType(IConfigProperty.PropertyType.STRING);
        property.setDescription("Test Property 1");
        Response response = target(V1_PROJECT + "/" + UUID.randomUUID().toString() + "/property").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(property, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    //@Test
    // TODO: The workaround for Jersey (DELETE with body) no longer throws an exception, but produces a 400. Unable to test at this time
    public void deletePropertyTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        ProjectProperty property = qm.createProjectProperty(project, "mygroup", "prop1", "value1", IConfigProperty.PropertyType.STRING, null);
        String uuid = project.getUuid().toString();
        qm.getPersistenceManager().detachCopy(property);
        qm.close();
        Response response = target(V1_PROJECT + "/" + uuid + "/property").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(property, MediaType.APPLICATION_JSON)); // HACK
        Assert.assertEquals(204, response.getStatus(), 0);
    }
}
