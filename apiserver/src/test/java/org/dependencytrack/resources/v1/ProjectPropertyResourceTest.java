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

import alpine.model.IConfigProperty.PropertyType;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthFeature;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.secret.management.SecretManager;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.UUID;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class ProjectPropertyResourceTest extends ResourceTest {

    private static final SecretManager secretManager = mock(SecretManager.class);

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(ProjectPropertyResource.class)
                    .register(ApiFilter.class)
                    .register(AuthFeature.class)
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bind(secretManager).to(SecretManager.class);
                        }
                    }));

    @Test
    public void getPropertiesTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_READ);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        qm.createProjectProperty(project, "mygroup", "prop1", "value1", PropertyType.STRING, "Test Property 1");
        qm.createProjectProperty(project, "mygroup", "prop2", "value2", PropertyType.STRING, "Test Property 2");
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
        Assertions.assertEquals("value2", json.getJsonObject(1).getString("propertyValue"));
        Assertions.assertEquals("STRING", json.getJsonObject(1).getString("propertyType"));
        Assertions.assertEquals("Test Property 2", json.getJsonObject(1).getString("description"));
    }

    @Test
    public void getPropertiesInvalidTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_READ);

        Response response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID().toString() + "/property").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The project could not be found.", body);
    }

    @Test
    public void getPropertiesAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_READ);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_PROJECT + "/" + project.getUuid() + "/property")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void createPropertyTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("mygroup");
        property.setPropertyName("prop1");
        property.setPropertyValue("value1");
        property.setPropertyType(PropertyType.STRING);
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
    public void createPropertyDuplicateTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        qm.createProjectProperty(project, "mygroup", "prop1", "value1", PropertyType.STRING, null);
        String uuid = project.getUuid().toString();
        qm.close();
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("mygroup");
        property.setPropertyName("prop1");
        property.setPropertyValue("value1");
        property.setPropertyType(PropertyType.STRING);
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
    public void createPropertyInvalidTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("mygroup");
        property.setPropertyName("prop1");
        property.setPropertyValue("value1");
        property.setPropertyType(PropertyType.STRING);
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
    public void createPropertyAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_PROJECT + "/" + project.getUuid() + "/property")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "foo",
                          "propertyName": "bar",
                          "propertyValue": "baz",
                          "propertyType": "STRING"
                        }
                        """));

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(201);
    }

    @Test
    public void updatePropertyTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        String uuid = project.getUuid().toString();
        ProjectProperty property = qm.createProjectProperty(project, "mygroup", "prop1", "value1", PropertyType.STRING, null);
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
    public void updatePropertyInvalidTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("mygroup");
        property.setPropertyName("prop1");
        property.setPropertyValue("value1");
        property.setPropertyType(PropertyType.STRING);
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
    public void updatePropertyAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("foo");
        property.setPropertyName("bar");
        property.setPropertyValue("baz");
        property.setPropertyType(PropertyType.STRING);
        qm.persist(property);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_PROJECT + "/" + project.getUuid() + "/property")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "foo",
                          "propertyName": "bar",
                          "propertyValue": "qux",
                          "propertyType": "STRING"
                        }
                        """));

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void deletePropertyTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_DELETE);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        ProjectProperty property = qm.createProjectProperty(project, "mygroup", "prop1", "value1", PropertyType.STRING, null);
        String uuid = project.getUuid().toString();
        qm.getPersistenceManager().detachCopy(property);
        qm.close();
        Response response = jersey.target(V1_PROJECT + "/" + uuid + "/property").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(property, MediaType.APPLICATION_JSON)); // HACK
        Assertions.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void deletePropertyAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_DELETE);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("foo");
        property.setPropertyName("bar");
        property.setPropertyValue("baz");
        property.setPropertyType(PropertyType.STRING);
        qm.persist(property);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_PROJECT + "/" + project.getUuid() + "/property")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method("DELETE", Entity.json(/* language=JSON */ """
                        {
                          "groupName": "foo",
                          "propertyName": "bar"
                        }
                        """));

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(204);
    }

}
