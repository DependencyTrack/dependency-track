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
import org.apache.commons.io.FileUtils;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.resources.v1.vo.ScanSubmitRequest;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.File;
import java.util.Base64;
import java.util.UUID;

public class ScanResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(ScanResource.class)
                        .register(AuthenticationFilter.class)
                        .register(MultiPartFeature.class)))
                .build();
    }

    @Before
    public void before() throws Exception {
        super.before();
        qm.createConfigProperty(
                ConfigPropertyConstants.ACCEPT_ARTIFACT_DEPENDENCYCHECK.getGroupName(),
                ConfigPropertyConstants.ACCEPT_ARTIFACT_DEPENDENCYCHECK.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCEPT_ARTIFACT_DEPENDENCYCHECK.getPropertyType(),
                null
        );
    }

    @Test
    public void uploadScanTest() throws Exception {
        initializeWithPermissions(Permissions.SCAN_UPLOAD);
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        File file = new File(Thread.currentThread().getContextClassLoader().getResource("dependency-check-report.xml").getFile());
        String scanString = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(file));
        ScanSubmitRequest request = new ScanSubmitRequest(project.getUuid().toString(), null, null, false, scanString);
        Response response = target(V1_SCAN).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
    }

    @Test
    public void uploadScanInvalidProjectTest() throws Exception {
        initializeWithPermissions(Permissions.SCAN_UPLOAD);
        File file = new File(Thread.currentThread().getContextClassLoader().getResource("dependency-check-report.xml").getFile());
        String scanString = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(file));
        ScanSubmitRequest request = new ScanSubmitRequest(UUID.randomUUID().toString(), null, null, false, scanString);
        Response response = target(V1_SCAN).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void uploadScanAutoCreateTest() throws Exception {
        initializeWithPermissions(Permissions.SCAN_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        File file = new File(Thread.currentThread().getContextClassLoader().getResource("dependency-check-report.xml").getFile());
        String scanString = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(file));
        ScanSubmitRequest request = new ScanSubmitRequest(null, "Acme Example", "1.0", true, scanString);
        Response response = target(V1_SCAN).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        Project project = qm.getProject("Acme Example", "1.0");
        Assert.assertNotNull(project);
    }

    @Test
    public void uploadScanUnauthorizedTest() throws Exception {
        File file = new File(Thread.currentThread().getContextClassLoader().getResource("dependency-check-report.xml").getFile());
        String scanString = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(file));
        ScanSubmitRequest request = new ScanSubmitRequest(null, "Acme Example", "1.0", true, scanString);
        Response response = target(V1_SCAN).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(401, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("The principal does not have permission to create project.", body);
    }
}
