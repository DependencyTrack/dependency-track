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

import alpine.filters.AuthenticationFilter;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.resources.v1.vo.DependencyRequest;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Test;
import javax.json.JsonArray;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.UUID;

public class DependencyResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(DependencyResource.class)
                        .register(AuthenticationFilter.class)))
                .build();
    }

    @Test
    public void getDependenciesByProjectTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component a1 = createComponent("Component A", "1.0");
        Component a2 = createComponent("Component A", "2.0");
        Component b = createComponent("Component B", "1.0");
        Component c = createComponent("Component C", "1.0");
        qm.createDependencyIfNotExist(project, a1, null, null);
        qm.createDependencyIfNotExist(project, a2, null, null);
        qm.createDependencyIfNotExist(project, b, null, null);
        Response response = target(V1_DEPENDENCY + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(3, json.size());
        Assert.assertEquals("Component A", json.getJsonObject(0).getJsonObject("component").getString("name"));
        Assert.assertEquals("2.0", json.getJsonObject(0).getJsonObject("component").getString("version"));
        Assert.assertEquals("Component A", json.getJsonObject(1).getJsonObject("component").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(1).getJsonObject("component").getString("version"));
        Assert.assertEquals("Component B", json.getJsonObject(2).getJsonObject("component").getString("name"));
    }

    @Test
    public void getDependenciesByProjectInvalidTest() {
        Response response = target(V1_DEPENDENCY + "/project/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void getDependenciesByComponentTest() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Project p2 = qm.createProject("Acme Example", null, "2.0", null, null, null, true, false);
        qm.createProject("Acme Example", null, "3.0", null, null, null, true, false);
        Component component = createComponent("Component A", "1.0");
        qm.createDependencyIfNotExist(p1, component, null, null);
        qm.createDependencyIfNotExist(p2, component, null, null);
        Response response = target(V1_DEPENDENCY + "/component/" + component.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(2), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(2, json.size());
        Assert.assertEquals("Acme Example", json.getJsonObject(0).getJsonObject("project").getString("name"));
        Assert.assertEquals("1.0", json.getJsonObject(0).getJsonObject("project").getString("version"));
        Assert.assertEquals("Acme Example", json.getJsonObject(1).getJsonObject("project").getString("name"));
        Assert.assertEquals("2.0", json.getJsonObject(1).getJsonObject("project").getString("version"));
    }

    @Test
    public void getDependenciesByComponentInvalidTest() {
        Response response = target(V1_DEPENDENCY + "/component/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The component could not be found.", body);
    }

    @Test
    public void addDependencyTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c1 = createComponent("Component A", "1.0");
        Component c2 = createComponent("Component B", "1.0");
        String[] components = {c1.getUuid().toString(), c2.getUuid().toString()};
        DependencyRequest request = new DependencyRequest(project.getUuid().toString(), components, null);
        Response response = target(V1_DEPENDENCY).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void addDependencyInvalidProjectTest() {
        Component c1 = createComponent("Component A", "1.0");
        Component c2 = createComponent("Component B", "1.0");
        String[] components = {c1.getUuid().toString(), c2.getUuid().toString()};
        DependencyRequest request = new DependencyRequest(UUID.randomUUID().toString(), components, null);
        Response response = target(V1_DEPENDENCY).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void addDependencyInvalidComponentTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        String[] components = {UUID.randomUUID().toString(), UUID.randomUUID().toString()};
        DependencyRequest request = new DependencyRequest(project.getUuid().toString(), components, null);
        Response response = target(V1_DEPENDENCY).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("A component could not be found.", body);
    }

    //@Test
    // TODO: The workaround for Jersey (DELETE with body) no longer throws an exception, but produces a 400. Unable to test at this time
    public void removeDependencyTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c1 = createComponent("Component A", "1.0");
        Component c2 = createComponent("Component B", "2.0");
        qm.createDependencyIfNotExist(project, c1, null, null);
        qm.createDependencyIfNotExist(project, c2, null, null);
        String[] components = {c1.getUuid().toString(), c2.getUuid().toString()};
        DependencyRequest request = new DependencyRequest(project.getUuid().toString(), components, null);
        Response response = target(V1_DEPENDENCY).request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(request, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    private Component createComponent(String name, String version) {
        Component component = new Component();
        component.setName(name);
        component.setVersion(version);
        return qm.createComponent(component, false);
    }
}
