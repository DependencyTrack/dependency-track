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

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFeature;
import alpine.server.filters.AuthorizationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.github.packageurl.PackageURL;
import jakarta.json.JsonArray;
import jakarta.ws.rs.core.Response;
import net.javacrumbs.jsonunit.core.Option;
import org.apache.http.HttpStatus;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.hamcrest.CoreMatchers.equalTo;

public class DependencyGraphResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(DependencyGraphResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class)
                    .register(AuthorizationFeature.class));

    @Test
    public void getComponentsAndServicesByComponentUuidTests() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final int nbIteration = 100;
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        final List<Component> components = new ArrayList<>(nbIteration);
        final List<ServiceComponent> serviceComponents = new ArrayList<>(nbIteration);

        for (int i = 0; i < nbIteration; i++) {
            Component component = new Component();
            component.setProject(project);
            component.setName("Component Name");
            component.setVersion(String.valueOf(i));
            components.add(qm.createComponent(component, false));
        }

        for (int i = 0; i < nbIteration; i++) {
            ServiceComponent service = new ServiceComponent();
            service.setProject(project);
            service.setName("Component Name");
            service.setVersion(String.valueOf(i));
            serviceComponents.add(qm.createServiceComponent(service, false));
        }

        final Component rootComponent = new Component();
        rootComponent.setProject(project);
        rootComponent.setName("Root Component Name");
        rootComponent.setVersion("1.0.0");

        final ArrayNode jsonArray = Mappers.jsonMapper().createArrayNode();
        for (Component component : components) {
            jsonArray.add(new ComponentIdentity(component).toJSON());
        }

        for(ServiceComponent serviceComponent : serviceComponents) {
            jsonArray.add(new ComponentIdentity(serviceComponent).toJSON());
        }

        rootComponent.setDirectDependencies(jsonArray.toString());

        final UUID rootUuid = qm.createComponent(rootComponent, false).getUuid();

        final Response response = jersey.target(V1_DEPENDENCY_GRAPH + "/component/" + rootUuid.toString() + "/directDependencies")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);

        final JsonArray json = parseJsonArray(response);

        assertThat(json.size()).isEqualTo(nbIteration * 2);
    }

    @Test
    public void getComponentsAndServicesByComponentUuidWithRepositoryMetaTests() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final int nbIteration = 100;
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        final String purlTemplate = "pkg:maven/%s/%s@%s?type=jar";
        final String nameTemplate = "fakePackage-%d";
        final String namespaceTemplate = "com.fake.package%d";

        final String latestVersion = "1.0.0";

        final List<Component> components = new ArrayList<>(nbIteration);
        final List<ServiceComponent> serviceComponents = new ArrayList<>(nbIteration);

        final var packageMetadataList = new ArrayList<PackageMetadata>(nbIteration);
        for (int i = 0; i < nbIteration; i++) {
            Component component = new Component();
            component.setProject(project);
            component.setName("Component Name");
            component.setVersion(String.valueOf(i));

            final String name = String.format(nameTemplate, i);
            final String namespace = String.format(namespaceTemplate, i);
            final String purl = String.format(purlTemplate, namespace, name, latestVersion);

            packageMetadataList.add(new PackageMetadata(
                    new PackageURL(String.format("pkg:maven/%s/%s", namespace, name)),
                    latestVersion,
                    null,
                    Instant.now(),
                    null,
                    null));

            component.setPurl(purl);
            components.add(qm.createComponent(component, false));
        }
        useJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(packageMetadataList));

        for (int i = 0; i < nbIteration; i++) {
            ServiceComponent service = new ServiceComponent();
            service.setProject(project);
            service.setName("Component Name");
            service.setVersion(String.valueOf(i));
            serviceComponents.add(qm.createServiceComponent(service, false));
        }

        final Component rootComponent = new Component();
        rootComponent.setProject(project);
        rootComponent.setName("Root Component Name");
        rootComponent.setVersion("1.0.0");

        final ArrayNode jsonArray = Mappers.jsonMapper().createArrayNode();
        for (Component component : components) {
            jsonArray.add(new ComponentIdentity(component).toJSON());
        }

        for(ServiceComponent serviceComponent : serviceComponents) {
            jsonArray.add(new ComponentIdentity(serviceComponent).toJSON());
        }

        rootComponent.setDirectDependencies(jsonArray.toString());

        final UUID rootUuid = qm.createComponent(rootComponent, false).getUuid();

        final Response response = jersey.target(V1_DEPENDENCY_GRAPH + "/component/" + rootUuid.toString() + "/directDependencies")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);

        final JsonArray json = parseJsonArray(response);

        assertThat(json.size()).isEqualTo(nbIteration * 2);
    }

    @Test
    public void getComponentsAndServicesByComponentUuidAclTest() {
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
                .target(V1_DEPENDENCY_GRAPH + "/component/" + component.getUuid() + "/directDependencies").request()
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
    public void getComponentsAndServicesByProjectUuidTests() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final int nbIteration = 100;
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        final List<Component> components = new ArrayList<>(nbIteration);
        final List<ServiceComponent> serviceComponents = new ArrayList<>(nbIteration);

        for (int i = 0; i < nbIteration; i++) {
            Component component = new Component();
            component.setProject(project);
            component.setName("Component Name");
            component.setVersion(String.valueOf(i));
            components.add(qm.createComponent(component, false));
        }

        for (int i = 0; i < nbIteration; i++) {
            ServiceComponent service = new ServiceComponent();
            service.setProject(project);
            service.setName("Component Name");
            service.setVersion(String.valueOf(i));
            serviceComponents.add(qm.createServiceComponent(service, false));
        }

        final ArrayNode jsonArray = Mappers.jsonMapper().createArrayNode();
        for (Component component : components) {
            jsonArray.add(new ComponentIdentity(component).toJSON());
        }

        for(ServiceComponent serviceComponent : serviceComponents) {
            jsonArray.add(new ComponentIdentity(serviceComponent).toJSON());
        }

        project.setDirectDependencies(jsonArray.toString());
        qm.updateProject(project, false);

        final Response response = jersey.target(V1_DEPENDENCY_GRAPH + "/project/" + project.getUuid().toString() + "/directDependencies")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);

        final JsonArray json = parseJsonArray(response);

        assertThat(json.size()).isEqualTo(nbIteration * 2);
    }

    @Test
    public void getComponentsAndServicesByProjectUuidWithRepositoryMetaTests() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final int nbIteration = 100;
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        final String purlTemplate = "pkg:maven/%s/%s@%s?type=jar";
        final String nameTemplate = "fakePackage-%d";
        final String namespaceTemplate = "com.fake.package%d";

        final String latestVersion = "1.0.0";

        final List<Component> components = new ArrayList<>(nbIteration);
        final List<ServiceComponent> serviceComponents = new ArrayList<>(nbIteration);

        final var packageMetadataList = new ArrayList<PackageMetadata>(nbIteration);
        for (int i = 0; i < nbIteration; i++) {
            Component component = new Component();
            component.setProject(project);
            component.setName("Component Name");
            component.setVersion(String.valueOf(i));

            final String name = String.format(nameTemplate, i);
            final String namespace = String.format(namespaceTemplate, i);
            final String purl = String.format(purlTemplate, namespace, name, latestVersion);

            packageMetadataList.add(new PackageMetadata(
                    new PackageURL(String.format("pkg:maven/%s/%s", namespace, name)),
                    latestVersion,
                    null,
                    Instant.now(),
                    null,
                    null));

            component.setPurl(purl);
            components.add(qm.createComponent(component, false));
        }
        useJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(packageMetadataList));

        for (int i = 0; i < nbIteration; i++) {
            ServiceComponent service = new ServiceComponent();
            service.setProject(project);
            service.setName("Component Name");
            service.setVersion(String.valueOf(i));
            serviceComponents.add(qm.createServiceComponent(service, false));
        }

        final ArrayNode jsonArray = Mappers.jsonMapper().createArrayNode();
        for (Component component : components) {
            jsonArray.add(new ComponentIdentity(component).toJSON());
        }

        for(ServiceComponent serviceComponent : serviceComponents) {
            jsonArray.add(new ComponentIdentity(serviceComponent).toJSON());
        }

        project.setDirectDependencies(jsonArray.toString());
        qm.updateProject(project, false);

        final Response response = jersey.target(V1_DEPENDENCY_GRAPH + "/project/" + project.getUuid().toString() + "/directDependencies")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);

        final JsonArray json = parseJsonArray(response);

        assertThat(json.size()).isEqualTo(nbIteration * 2);
    }

    @Test
    public void getComponentsAndServicesByProjectUuidWithComponentsWithoutPurlTest() throws Exception {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var componentWithPurl = new Component();
        componentWithPurl.setProject(project);
        componentWithPurl.setName("acme-lib-a");
        componentWithPurl.setVersion("2.0.0");
        componentWithPurl.setPurl("pkg:pypi/acme-lib-a@2.0.0");
        qm.persist(componentWithPurl);

        final var componentWithoutPurl = new Component();
        componentWithoutPurl.setProject(project);
        componentWithoutPurl.setName("acme-lib-b");
        componentWithoutPurl.setVersion("3.0.0");
        qm.persist(componentWithoutPurl);

        useJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(List.of(
                new PackageMetadata(
                        new PackageURL("pkg:pypi/acme-lib-a"),
                        "2.0.2",
                        null,
                        Instant.now(),
                        null,
                        null))));

        project.setDirectDependencies("""
                [
                  {"uuid": "%s"},
                  {"uuid": "%s"}
                ]
                """.formatted(componentWithPurl.getUuid(), componentWithoutPurl.getUuid()));
        qm.persist(project);

        final Response response = jersey.target("%s/project/%s/directDependencies".formatted(V1_DEPENDENCY_GRAPH, project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .withMatcher("componentWithPurlUuid", equalTo(componentWithPurl.getUuid().toString()))
                .withMatcher("componentWithoutPurlUuid", equalTo(componentWithoutPurl.getUuid().toString()))
                .isEqualTo("""
                        [
                          {
                            "uuid": "${json-unit.matches:componentWithoutPurlUuid}",
                            "name": "acme-lib-b",
                            "version": "3.0.0"
                          },
                          {
                            "uuid": "${json-unit.matches:componentWithPurlUuid}",
                            "name": "acme-lib-a",
                            "version":"2.0.0",
                            "purl": "pkg:pypi/acme-lib-a@2.0.0",
                            "latestVersion":"2.0.2"
                          }
                        ]
                        """);
    }

    @Test
    public void getComponentsAndServicesByProjectUuidAclTest() {
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
                .target(V1_DEPENDENCY_GRAPH + "/project/" + project.getUuid() + "/directDependencies").request()
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

}
