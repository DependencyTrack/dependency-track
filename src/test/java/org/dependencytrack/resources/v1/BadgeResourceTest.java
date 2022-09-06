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

import alpine.model.IConfigProperty;
import alpine.server.filters.ApiFilter;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Project;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Test;

import javax.ws.rs.core.Response;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.dependencytrack.model.ConfigPropertyConstants.GENERAL_BADGE_ENABLED;

public class BadgeResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                        new ResourceConfig(BadgeResource.class)
                                .register(ApiFilter.class)))
                .build();
    }

    @Override
    public void before() throws Exception {
        super.before();
        qm.createConfigProperty(GENERAL_BADGE_ENABLED.getGroupName(), GENERAL_BADGE_ENABLED.getPropertyName(), "true", IConfigProperty.PropertyType.BOOLEAN, "Badge enabled");
    }

    @Test
    public void projectVulnerabilitiesByUuidTest() {
        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = target(V1_BADGE + "/vulns/project/" + project.getUuid()).request()
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectVulnerabilitiesByUuidProjectDisabledTest() {
        disableBadge();
        Response response = target(V1_BADGE + "/vulns/project/" + UUID.randomUUID()).request()
                .get(Response.class);
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void projectVulnerabilitiesByUuidProjectNotFoundTest() {
        Response response = target(V1_BADGE + "/vulns/project/" + UUID.randomUUID()).request()
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void projectVulnerabilitiesByNameAndVersionTest() {
        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = target(V1_BADGE + "/vulns/project/Acme%20Example/1.0.0").request()
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectVulnerabilitiesByNameAndVersionDisabledTest() {
        disableBadge();
        Response response = target(V1_BADGE + "/vulns/project/ProjectNameDoesNotExist/1.0.0").request()
                .get(Response.class);
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void projectVulnerabilitiesByNameAndVersionProjectNotFoundTest() {
        Response response = target(V1_BADGE + "/vulns/project/ProjectNameDoesNotExist/1.0.0").request()
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void projectVulnerabilitiesByNameAndVersionVersionNotFoundTest() {
        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = target(V1_BADGE + "/vulns/project/Acme%20Example/1.2.0").request()
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void projectPolicyViolationsByUuidTest() {
        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = target(V1_BADGE + "/violations/project/" + project.getUuid()).request()
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectPolicyViolationsByUuidProjectDisabledTest() {
        disableBadge();
        Response response = target(V1_BADGE + "/violations/project/" + UUID.randomUUID()).request()
                .get(Response.class);
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void projectPolicyViolationsByUuidProjectNotFoundTest() {
        Response response = target(V1_BADGE + "/violations/project/" + UUID.randomUUID()).request()
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void projectPolicyViolationsByNameAndVersionTest() {
        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = target(V1_BADGE + "/violations/project/Acme%20Example/1.0.0").request()
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectPolicyViolationsByNameAndVersionDisabledTest() {
        disableBadge();
        Response response = target(V1_BADGE + "/violations/project/ProjectNameDoesNotExist/1.0.0").request()
                .get(Response.class);
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void projectPolicyViolationsByNameAndVersionProjectNotFoundTest() {
        Response response = target(V1_BADGE + "/violations/project/ProjectNameDoesNotExist/1.0.0").request()
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void projectPolicyViolationsByNameAndVersionVersionNotFoundTest() {
        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = target(V1_BADGE + "/violations/project/Acme%20Example/1.2.0").request()
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    private void disableBadge() {
        qm.getConfigProperty(GENERAL_BADGE_ENABLED.getGroupName(), GENERAL_BADGE_ENABLED.getPropertyName())
                .setPropertyValue("false");
    }

    private boolean isLikelySvg(String body) {
        try {
            InputStream is = new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8));
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            db.parse(is);
            return body.startsWith("<svg");
        } catch (Exception e) {
            return false;
        }
    }
}
