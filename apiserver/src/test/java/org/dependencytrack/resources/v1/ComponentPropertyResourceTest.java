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
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentProperty;
import org.dependencytrack.model.Project;
import org.dependencytrack.secret.management.SecretManager;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.UUID;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.mockito.Mockito.mock;

public class ComponentPropertyResourceTest extends ResourceTest {

    private static final SecretManager secretManager = mock(SecretManager.class);

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(ComponentPropertyResource.class)
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
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final var propertyA = new ComponentProperty();
        propertyA.setComponent(component);
        propertyA.setGroupName("foo-a");
        propertyA.setPropertyName("bar-a");
        propertyA.setPropertyValue("baz-a");
        propertyA.setPropertyType(PropertyType.STRING);
        propertyA.setDescription("qux-a");
        qm.persist(propertyA);

        final var propertyB = new ComponentProperty();
        propertyB.setComponent(component);
        propertyB.setGroupName("foo-b");
        propertyB.setPropertyName("bar-b");
        propertyB.setPropertyValue("baz-b");
        propertyB.setPropertyType(PropertyType.STRING);
        propertyB.setDescription("qux-b");
        qm.persist(propertyB);

        final Response response = jersey.target("%s/%s/property".formatted(V1_COMPONENT, component.getUuid())).request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThatJson(getPlainTextBody(response))
                .withMatcher("property-a-uuid", equalTo(propertyA.getUuid().toString()))
                .withMatcher("property-b-uuid", equalTo(propertyB.getUuid().toString()))
                .isEqualTo("""
                        [
                          {
                            "groupName": "foo-a",
                            "propertyName": "bar-a",
                            "propertyValue": "baz-a",
                            "propertyType": "STRING",
                            "description": "qux-a",
                            "uuid": "${json-unit.matches:property-a-uuid}"
                          },
                          {
                            "groupName": "foo-b",
                            "propertyName": "bar-b",
                            "propertyValue": "baz-b",
                            "propertyType": "STRING",
                            "description": "qux-b",
                            "uuid": "${json-unit.matches:property-b-uuid}"
                          }
                        ]
                        """);
    }

    @Test
    public void getPropertiesInvalidTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Response response = jersey.target("%s/%s/property".formatted(V1_COMPONENT, UUID.randomUUID())).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).isEqualTo("The component could not be found.");
    }

    @Test
    public void getPropertiesAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target("%s/%s/property".formatted(V1_COMPONENT, component.getUuid())).request()
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

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Response response = jersey.target("%s/%s/property".formatted(V1_COMPONENT, component.getUuid())).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "groupName": "foo",
                          "propertyName": "bar",
                          "propertyValue": "baz",
                          "propertyType": "STRING",
                          "description": "qux"
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(201);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "groupName": "foo",
                  "propertyName": "bar",
                  "propertyValue": "baz",
                  "propertyType": "STRING",
                  "description": "qux",
                  "uuid": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    public void createPropertyWithoutGroupTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Response response = jersey.target("%s/%s/property".formatted(V1_COMPONENT, component.getUuid())).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "propertyName": "bar",
                          "propertyValue": "baz",
                          "propertyType": "STRING",
                          "description": "qux"
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(201);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "propertyName": "bar",
                  "propertyValue": "baz",
                  "propertyType": "STRING",
                  "description": "qux",
                  "uuid": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    public void createPropertyDuplicateTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final var property = new ComponentProperty();
        property.setComponent(component);
        property.setGroupName("foo");
        property.setPropertyName("bar");
        property.setPropertyValue("baz");
        property.setPropertyType(PropertyType.STRING);
        qm.persist(property);

        final Response response = jersey.target("%s/%s/property".formatted(V1_COMPONENT, component.getUuid())).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "groupName": "foo",
                          "propertyName": "bar",
                          "propertyValue": "baz",
                          "propertyType": "STRING",
                          "description": "qux"
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(409);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).isEqualTo("""
                A property with the specified component/group/name/value combination already exists.""");
    }

    @Test
    public void createPropertyComponentNotFoundTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Response response = jersey.target("%s/%s/property".formatted(V1_COMPONENT, UUID.randomUUID())).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "groupName": "foo",
                          "propertyName": "bar",
                          "propertyValue": "baz",
                          "propertyType": "STRING",
                          "description": "qux"
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).isEqualTo("The component could not be found.");
    }

    @Test
    public void createPropertyAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target("%s/%s/property".formatted(V1_COMPONENT, component.getUuid())).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "foo",
                          "propertyName": "bar",
                          "propertyValue": "baz",
                          "propertyType": "STRING",
                          "description": "qux"
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
    public void deletePropertyTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_DELETE);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final var property = new ComponentProperty();
        property.setComponent(component);
        property.setGroupName("foo");
        property.setPropertyName("bar");
        property.setPropertyValue("baz");
        property.setPropertyType(PropertyType.STRING);
        qm.persist(property);

        final Response response = jersey.target("%s/%s/property/%s".formatted(V1_COMPONENT, component.getUuid(), property.getUuid())).request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(getPlainTextBody(response)).isEmpty();
    }

    @Test
    public void deletePropertyAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_DELETE);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final var property = new ComponentProperty();
        property.setComponent(component);
        property.setGroupName("foo");
        property.setPropertyName("bar");
        property.setPropertyValue("baz");
        property.setPropertyType(PropertyType.STRING);
        qm.persist(property);

        final Supplier<Response> responseSupplier = () -> jersey
                .target("%s/%s/property/%s".formatted(V1_COMPONENT, component.getUuid(), property.getUuid())).request()
                .header(X_API_KEY, apiKey)
                .delete();

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
