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

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import com.github.packageurl.PackageURL;
import org.apache.http.HttpStatus;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.*;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.json.JSONArray;
import org.junit.Test;

import javax.json.JsonArray;
import javax.ws.rs.core.Response;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class DependencyGraphResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                        new ResourceConfig(DependencyGraphResource.class)
                                .register(ApiFilter.class)
                                .register(AuthenticationFilter.class)))
                .build();
    }


    @Test
    public void getComponentsAndServicesByComponentUuidTests() {
        final int nbIteration = 100;
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);

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

        final JSONArray jsonArray = new JSONArray();
        for (Component component : components) {
            jsonArray.put(new ComponentIdentity(component).toJSON());
        }

        for(ServiceComponent serviceComponent : serviceComponents) {
            jsonArray.put(new ComponentIdentity(serviceComponent).toJSON());
        }

        rootComponent.setDirectDependencies(jsonArray.toString());

        final UUID rootUuid = qm.createComponent(rootComponent, false).getUuid();

        final Response response = target(V1_DEPENDENCY_GRAPH + "/component/" + rootUuid.toString() + "/directDependencies")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);

        final JsonArray json = parseJsonArray(response);

        assertThat(json.size()).isEqualTo(nbIteration * 2);
    }

    @Test
    public void getComponentsAndServicesByComponentUuidWithRepositoryMetaTests() {
        final int nbIteration = 100;
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);

        final String purlTemplate = "pkg:maven/%s/%s@%s?type=jar";
        final String nameTemplate = "fakePackage-%d";
        final String namespaceTemplate = "com.fake.package%d";

        final String latestVersion = "1.0.0";

        final List<Component> components = new ArrayList<>(nbIteration);
        final List<ServiceComponent> serviceComponents = new ArrayList<>(nbIteration);

        String purl;
        String name;
        String namespace;
        RepositoryMetaComponent repositoryMetaComponent;
        for (int i = 0; i < nbIteration; i++) {
            Component component = new Component();
            component.setProject(project);
            component.setName("Component Name");
            component.setVersion(String.valueOf(i));
            try {
                name = String.format(nameTemplate, i);
                namespace = String.format(namespaceTemplate, i);
                purl = String.format(purlTemplate, namespace, name, latestVersion);

                repositoryMetaComponent = new RepositoryMetaComponent();
                repositoryMetaComponent.setRepositoryType(RepositoryType.MAVEN);
                repositoryMetaComponent.setName(name);
                repositoryMetaComponent.setNamespace(namespace);
                repositoryMetaComponent.setPublished(new Date());
                repositoryMetaComponent.setLastCheck(new Date());
                repositoryMetaComponent.setLatestVersion(latestVersion);
                qm.synchronizeRepositoryMetaComponent(repositoryMetaComponent);
            } catch (Exception e) {
                purl = null;
                repositoryMetaComponent = null;
            }
            component.setPurl(purl);
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

        final JSONArray jsonArray = new JSONArray();
        for (Component component : components) {
            jsonArray.put(new ComponentIdentity(component).toJSON());
        }

        for(ServiceComponent serviceComponent : serviceComponents) {
            jsonArray.put(new ComponentIdentity(serviceComponent).toJSON());
        }

        rootComponent.setDirectDependencies(jsonArray.toString());

        final UUID rootUuid = qm.createComponent(rootComponent, false).getUuid();

        final Response response = target(V1_DEPENDENCY_GRAPH + "/component/" + rootUuid.toString() + "/directDependencies")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);

        final JsonArray json = parseJsonArray(response);

        assertThat(json.size()).isEqualTo(nbIteration * 2);
    }

    @Test
    public void getComponentsAndServicesByProjectUuidTests() {
        final int nbIteration = 100;
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);

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

        final JSONArray jsonArray = new JSONArray();
        for (Component component : components) {
            jsonArray.put(new ComponentIdentity(component).toJSON());
        }

        for(ServiceComponent serviceComponent : serviceComponents) {
            jsonArray.put(new ComponentIdentity(serviceComponent).toJSON());
        }

        project.setDirectDependencies(jsonArray.toString());
        qm.updateProject(project, false);

        final Response response = target(V1_DEPENDENCY_GRAPH + "/project/" + project.getUuid().toString() + "/directDependencies")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);

        final JsonArray json = parseJsonArray(response);

        assertThat(json.size()).isEqualTo(nbIteration * 2);
    }

    @Test
    public void getComponentsAndServicesByProjectUuidWithRepositoryMetaTests() {
        final int nbIteration = 100;
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);

        final String purlTemplate = "pkg:maven/%s/%s@%s?type=jar";
        final String nameTemplate = "fakePackage-%d";
        final String namespaceTemplate = "com.fake.package%d";

        final String latestVersion = "1.0.0";

        final List<Component> components = new ArrayList<>(nbIteration);
        final List<ServiceComponent> serviceComponents = new ArrayList<>(nbIteration);

        String purl;
        String name;
        String namespace;
        RepositoryMetaComponent repositoryMetaComponent;
        for (int i = 0; i < nbIteration; i++) {
            Component component = new Component();
            component.setProject(project);
            component.setName("Component Name");
            component.setVersion(String.valueOf(i));
            try {
                name = String.format(nameTemplate, i);
                namespace = String.format(namespaceTemplate, i);
                purl = String.format(purlTemplate, namespace, name, latestVersion);

                repositoryMetaComponent = new RepositoryMetaComponent();
                repositoryMetaComponent.setRepositoryType(RepositoryType.MAVEN);
                repositoryMetaComponent.setName(name);
                repositoryMetaComponent.setNamespace(namespace);
                repositoryMetaComponent.setPublished(new Date());
                repositoryMetaComponent.setLastCheck(new Date());
                repositoryMetaComponent.setLatestVersion(latestVersion);
                qm.synchronizeRepositoryMetaComponent(repositoryMetaComponent);
            } catch (Exception e) {
                purl = null;
                repositoryMetaComponent = null;
            }
            component.setPurl(purl);
            components.add(qm.createComponent(component, false));
        }

        for (int i = 0; i < nbIteration; i++) {
            ServiceComponent service = new ServiceComponent();
            service.setProject(project);
            service.setName("Component Name");
            service.setVersion(String.valueOf(i));
            serviceComponents.add(qm.createServiceComponent(service, false));
        }

        final JSONArray jsonArray = new JSONArray();
        for (Component component : components) {
            jsonArray.put(new ComponentIdentity(component).toJSON());
        }

        for(ServiceComponent serviceComponent : serviceComponents) {
            jsonArray.put(new ComponentIdentity(serviceComponent).toJSON());
        }

        project.setDirectDependencies(jsonArray.toString());
        qm.updateProject(project, false);

        final Response response = target(V1_DEPENDENCY_GRAPH + "/project/" + project.getUuid().toString() + "/directDependencies")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);

        final JsonArray json = parseJsonArray(response);

        assertThat(json.size()).isEqualTo(nbIteration * 2);
    }
}
