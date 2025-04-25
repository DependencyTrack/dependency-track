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

import alpine.model.IConfigProperty;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectProperty;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.UUID;

class ProjectPropertyResourceTest extends ResourceTest {

    @RegisterExtension
    public static JerseyTestExtension jersey = new JerseyTestExtension(
            () -> new ResourceConfig(ProjectPropertyResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @Test
    void getPropertiesTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        qm.createProjectProperty(project, "mygroup", "prop1", "value1", IConfigProperty.PropertyType.STRING, "Test Property 1");
        qm.createProjectProperty(project, "mygroup", "prop2", "value2", IConfigProperty.PropertyType.ENCRYPTEDSTRING, "Test Property 2");
        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid().toString() + "/property").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(2, json.size());
        Assertions.assertEquals("mygroup", json.getJsonObject(0).getString("groupName"));
        Assertions.assertEquals("prop1", json.getJsonObject(0).getString("propertyName"));
        Assertions.assertEquals("value1", json.getJsonObject(0).getString("propertyValue"));
        Assertions.assertEquals("STRING", json.getJsonObject(0).getString("propertyType"));
        Assertions.assertEquals("Test Property 1", json.getJsonObject(0).getString("description"));
        Assertions.assertEquals("mygroup", json.getJsonObject(1).getString("groupName"));
        Assertions.assertEquals("prop2", json.getJsonObject(1).getString("propertyName"));
        Assertions.assertEquals("HiddenDecryptedPropertyPlaceholder", json.getJsonObject(1).getString("propertyValue"));
        Assertions.assertEquals("ENCRYPTEDSTRING", json.getJsonObject(1).getString("propertyType"));
        Assertions.assertEquals("Test Property 2", json.getJsonObject(1).getString("description"));
    }

    @Test
    void getPropertiesInvalidTest() {
       Response response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID().toString() + "/property").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The project could not be found.", body);
    }

    @Test
    void createPropertyTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("mygroup");
        property.setPropertyName("prop1");
        property.setPropertyValue("value1");
        property.setPropertyType(IConfigProperty.PropertyType.STRING);
        property.setDescription("Test Property 1");
        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid().toString() + "/property").request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(property, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("mygroup", json.getString("groupName"));
        Assertions.assertEquals("prop1", json.getString("propertyName"));
        Assertions.assertEquals("value1", json.getString("propertyValue"));
        Assertions.assertEquals("STRING", json.getString("propertyType"));
        Assertions.assertEquals("Test Property 1", json.getString("description"));
    }

    @Test
    void createPropertyEncryptedTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("mygroup");
        property.setPropertyName("prop1");
        property.setPropertyValue("value1");
        property.setPropertyType(IConfigProperty.PropertyType.ENCRYPTEDSTRING);
        property.setDescription("Test Property 1");
        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid().toString() + "/property").request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(property, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("mygroup", json.getString("groupName"));
        Assertions.assertEquals("prop1", json.getString("propertyName"));
        Assertions.assertEquals("HiddenDecryptedPropertyPlaceholder", json.getString("propertyValue"));
        Assertions.assertEquals("ENCRYPTEDSTRING", json.getString("propertyType"));
        Assertions.assertEquals("Test Property 1", json.getString("description"));
    }

    @Test
    void createPropertyDuplicateTest() {
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
        Response response = jersey.target(V1_PROJECT + "/" + uuid + "/property").request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(property, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(409, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("A property with the specified project/group/name combination already exists.", body);
    }

    @Test
    void createPropertyInvalidTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("mygroup");
        property.setPropertyName("prop1");
        property.setPropertyValue("value1");
        property.setPropertyType(IConfigProperty.PropertyType.STRING);
        property.setDescription("Test Property 1");
        Response response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID() + "/property").request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(property, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The project could not be found.", body);
    }

    @Test
    void updatePropertyTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        String uuid = project.getUuid().toString();
        ProjectProperty property = qm.createProjectProperty(project, "mygroup", "prop1", "value1", IConfigProperty.PropertyType.STRING, null);
        qm.getPersistenceManager().detachCopy(property);
        qm.close();
        property.setPropertyValue("updatedValue");
        Response response = jersey.target(V1_PROJECT + "/" + uuid + "/property").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(property, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("mygroup", json.getString("groupName"));
        Assertions.assertEquals("prop1", json.getString("propertyName"));
        Assertions.assertEquals("updatedValue", json.getString("propertyValue"));
        Assertions.assertEquals("STRING", json.getString("propertyType"));
    }

    @Test
    void updatePropertyInvalidTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("mygroup");
        property.setPropertyName("prop1");
        property.setPropertyValue("value1");
        property.setPropertyType(IConfigProperty.PropertyType.STRING);
        property.setDescription("Test Property 1");
        Response response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID().toString() + "/property").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(property, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The project could not be found.", body);
    }

    @Test
    void deletePropertyTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        ProjectProperty property = qm.createProjectProperty(project, "mygroup", "prop1", "value1", IConfigProperty.PropertyType.STRING, null);
        String uuid = project.getUuid().toString();
        qm.getPersistenceManager().detachCopy(property);
        qm.close();
        Response response = jersey.target(V1_PROJECT + "/" + uuid + "/property").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(property, MediaType.APPLICATION_JSON)); // HACK
        Assertions.assertEquals(204, response.getStatus(), 0);
    }
}
