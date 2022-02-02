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
import org.apache.commons.io.FileUtils;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.resources.v1.vo.BomSubmitRequest;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Test;
import javax.json.JsonObject;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.File;
import java.util.Base64;
import java.util.UUID;

public class BomResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(BomResource.class)
                        .register(ApiFilter.class)
                        .register(AuthenticationFilter.class)
                        .register(MultiPartFeature.class)))
                .build();
    }

    @Test
    public void exportProjectAsCycloneDxTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c = new Component();
        c.setProject(project);
        c.setName("sample-component");
        c.setVersion("1.0");
        Component component = qm.createComponent(c, false);
        Response response = target(V1_BOM + "/cyclonedx/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertTrue(body.startsWith("{"));
    }

    @Test
    public void exportProjectAsCycloneDxInvalidTest() {
        Response response = target(V1_BOM + "/cyclonedx/project/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void exportComponentAsCycloneDx() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, false, false);
        Component c = new Component();
        c.setProject(project);
        c.setName("sample-component");
        c.setVersion("1.0");
        Component component = qm.createComponent(c, false);
        Response response = target(V1_BOM + "/cyclonedx/component/" + component.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertTrue(body.startsWith("{"));
    }

    @Test
    public void exportComponentAsCycloneDxInvalid() {
        Response response = target(V1_BOM + "/cyclonedx/component/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The component could not be found.", body);
    }

    @Test
    public void uploadBomTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD);
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        File file = new File(Thread.currentThread().getContextClassLoader().getResource("bom-1.xml").getFile());
        String bomString = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(file));
        BomSubmitRequest request = new BomSubmitRequest(project.getUuid().toString(), null, null, false, bomString);
        Response response = target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertNotNull(json.getString("token"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("token")));
    }

    @Test
    public void uploadBomInvalidProjectTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD);
        File file = new File(Thread.currentThread().getContextClassLoader().getResource("bom-1.xml").getFile());
        String bomString = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(file));
        BomSubmitRequest request = new BomSubmitRequest(UUID.randomUUID().toString(), null, null, false, bomString);
        Response response = target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void uploadBomAutoCreateTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        File file = new File(Thread.currentThread().getContextClassLoader().getResource("bom-1.xml").getFile());
        String bomString = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(file));
        BomSubmitRequest request = new BomSubmitRequest(null, "Acme Example", "1.0", true, bomString);
        Response response = target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertNotNull(json.getString("token"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("token")));
        Project project = qm.getProject("Acme Example", "1.0");
        Assert.assertNotNull(project);
    }

    @Test
    public void uploadBomUnauthorizedTest() throws Exception {
        File file = new File(Thread.currentThread().getContextClassLoader().getResource("bom-1.xml").getFile());
        String bomString = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(file));
        BomSubmitRequest request = new BomSubmitRequest(null, "Acme Example", "1.0", true, bomString);
        Response response = target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(401, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("The principal does not have permission to create project.", body);
    }
}
