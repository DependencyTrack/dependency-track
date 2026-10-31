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
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.jdbi.ProjectPropertyDao;
import org.dependencytrack.persistence.jdbi.ProjectPropertyDao.ProjectPropertyRow;
import org.dependencytrack.secret.management.SecretManager;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;

import java.util.UUID;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.mockito.Mockito.mock;

public class ProjectPropertyResourceTest extends ResourceTest {

    private static final SecretManager secretManager = mock(SecretManager.class);

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(new ResourceConfig(ProjectPropertyResource.class)
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
        useJdbiHandle(handle -> handle.attach(ProjectPropertyDao.class)
                .createProperty(
                        project.getUuid(),
                        new ProjectPropertyRow("mygroup", "prop1", "value1", PropertyType.STRING, "Test Property 1")));
        useJdbiHandle(handle -> handle.attach(ProjectPropertyDao.class)
                .createProperty(
                        project.getUuid(),
                        new ProjectPropertyRow("mygroup", "prop2", "value2", PropertyType.STRING, "Test Property 2")));
        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid().toString() + "/property")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "groupName": "mygroup",
                    "propertyName": "prop1",
                    "propertyValue": "value1",
                    "propertyType": "STRING",
                    "description": "Test Property 1"
                  },
                  {
                    "groupName": "mygroup",
                    "propertyName": "prop2",
                    "propertyValue": "value2",
                    "propertyType": "STRING",
                    "description": "Test Property 2"
                  }
                ]
                """);
    }

    @Test
    public void getPropertiesInvalidTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_READ);

        Response response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID().toString() + "/property")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "Project could not be found"
                }
                """);
    }

    @Test
    public void getPropertiesAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_READ);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier =
                () -> jersey.target(V1_PROJECT + "/" + project.getUuid() + "/property")
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
        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid().toString() + "/property")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "mygroup",
                          "propertyName": "prop1",
                          "propertyValue": "value1",
                          "propertyType": "STRING",
                          "description": "Test Property 1"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "groupName": "mygroup",
                  "propertyName": "prop1",
                  "propertyValue": "value1",
                  "propertyType": "STRING",
                  "description": "Test Property 1"
                }
                """);

        final ProjectPropertyRow storedProperty = withJdbiHandle(
                handle -> handle.attach(ProjectPropertyDao.class).getProperty(project.getUuid(), "mygroup", "prop1"));
        assertThat(storedProperty).isNotNull();
        assertThat(storedProperty.propertyValue()).isEqualTo("value1");
    }

    @Test
    void createPropertyShouldNotPersistPropertyWithInvalidValue() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final Response response = jersey.target(V1_PROJECT + "/" + project.getUuid() + "/property")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "mygroup",
                          "propertyName": "prop1",
                          "propertyValue": "notAnInteger",
                          "propertyType": "INTEGER"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response))
                .isEqualTo("The property expected an integer and an integer was not sent.");

        final ProjectPropertyRow storedProperty = withJdbiHandle(
                handle -> handle.attach(ProjectPropertyDao.class).getProperty(project.getUuid(), "mygroup", "prop1"));
        assertThat(storedProperty).isNull();
    }

    @Test
    public void createPropertyDuplicateTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        useJdbiHandle(handle -> handle.attach(ProjectPropertyDao.class)
                .createProperty(
                        project.getUuid(),
                        new ProjectPropertyRow("mygroup", "prop1", "value1", PropertyType.STRING, null)));
        String uuid = project.getUuid().toString();
        qm.close();
        Response response = jersey.target(V1_PROJECT + "/" + uuid + "/property")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "mygroup",
                          "propertyName": "prop1",
                          "propertyValue": "value1",
                          "propertyType": "STRING",
                          "description": "Test Property 1"
                        }
                        """));
        Assertions.assertEquals(409, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("A property with the specified project/group/name combination already exists.", body);
    }

    @Test
    public void createPropertyInvalidTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Response response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID() + "/property")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "mygroup",
                          "propertyName": "prop1",
                          "propertyValue": "value1",
                          "propertyType": "STRING",
                          "description": "Test Property 1"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "Project could not be found"
                }
                """);
    }

    @Test
    public void createPropertyAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier =
                () -> jersey.target(V1_PROJECT + "/" + project.getUuid() + "/property")
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
        useJdbiHandle(handle -> handle.attach(ProjectPropertyDao.class)
                .createProperty(
                        project.getUuid(),
                        new ProjectPropertyRow("mygroup", "prop1", "value1", PropertyType.STRING, null)));
        qm.close();
        Response response = jersey.target(V1_PROJECT + "/" + uuid + "/property")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "mygroup",
                          "propertyName": "prop1",
                          "propertyValue": "updatedValue"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "groupName": "mygroup",
                  "propertyName": "prop1",
                  "propertyValue": "updatedValue",
                  "propertyType": "STRING"
                }
                """);

        final ProjectPropertyRow storedProperty = withJdbiHandle(handle ->
                handle.attach(ProjectPropertyDao.class).getProperty(UUID.fromString(uuid), "mygroup", "prop1"));
        assertThat(storedProperty).isNotNull();
        assertThat(storedProperty.propertyValue()).isEqualTo("updatedValue");
    }

    @Test
    void updatePropertyShouldReturnNotFoundWhenPropertyDoesNotExist() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final Response response = jersey.target(V1_PROJECT + "/" + project.getUuid() + "/property")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "mygroup",
                          "propertyName": "prop1",
                          "propertyValue": "value1"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "Project property could not be found"
                }
                """);
    }

    @Test
    public void updatePropertyInvalidTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Response response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID().toString() + "/property")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "mygroup",
                          "propertyName": "prop1",
                          "propertyValue": "value1"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "Project could not be found"
                }
                """);
    }

    @Test
    public void updatePropertyAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        useJdbiHandle(handle -> handle.attach(ProjectPropertyDao.class)
                .createProperty(
                        project.getUuid(), new ProjectPropertyRow("foo", "bar", "baz", PropertyType.STRING, null)));

        final Supplier<Response> responseSupplier =
                () -> jersey.target(V1_PROJECT + "/" + project.getUuid() + "/property")
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
        useJdbiHandle(handle -> handle.attach(ProjectPropertyDao.class)
                .createProperty(
                        project.getUuid(),
                        new ProjectPropertyRow("mygroup", "prop1", "value1", PropertyType.STRING, null)));
        String uuid = project.getUuid().toString();
        qm.close();
        Response response = jersey.target(V1_PROJECT + "/" + uuid + "/property")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.json(/* language=JSON */ """
                        {
                          "groupName": "mygroup",
                          "propertyName": "prop1"
                        }
                        """)); // HACK
        Assertions.assertEquals(204, response.getStatus(), 0);

        final ProjectPropertyRow storedProperty = withJdbiHandle(handle ->
                handle.attach(ProjectPropertyDao.class).getProperty(UUID.fromString(uuid), "mygroup", "prop1"));
        assertThat(storedProperty).isNull();
    }

    @Test
    void deletePropertyShouldReturnNotFoundWhenPropertyDoesNotExist() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_DELETE);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final Response response = jersey.target(V1_PROJECT + "/" + project.getUuid() + "/property")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method("DELETE", Entity.json(/* language=JSON */ """
                        {
                          "groupName": "mygroup",
                          "propertyName": "prop1"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "Project property could not be found"
                }
                """);
    }

    @Test
    public void deletePropertyAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_DELETE);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        useJdbiHandle(handle -> handle.attach(ProjectPropertyDao.class)
                .createProperty(
                        project.getUuid(), new ProjectPropertyRow("foo", "bar", "baz", PropertyType.STRING, null)));

        final Supplier<Response> responseSupplier =
                () -> jersey.target(V1_PROJECT + "/" + project.getUuid() + "/property")
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
