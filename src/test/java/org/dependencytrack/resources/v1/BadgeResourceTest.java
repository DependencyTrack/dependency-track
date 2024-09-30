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
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.ws.rs.core.Response;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.model.ConfigPropertyConstants.GENERAL_BADGE_ENABLED;

public class BadgeResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(BadgeResource.class)
                    .register(ApiFilter.class));

    @Override
    public void before() throws Exception {
        super.before();
        qm.createConfigProperty(GENERAL_BADGE_ENABLED.getGroupName(), GENERAL_BADGE_ENABLED.getPropertyName(), "false", IConfigProperty.PropertyType.BOOLEAN, "Unauthenticated access to badge enabled");
    }

    @Test
    public void projectVulnerabilitiesByUuidTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/" + project.getUuid())
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectVulnerabilitiesByUuidWithHeaderAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectVulnerabilitiesByUuidMissingAuthenticationWithUnauthenticatedAccessEnabledTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);
        enableUnauthenticatedBadgeAccess();

        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/" + project.getUuid()).request()
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectVulnerabilitiesByUuidProjectNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Response response = jersey.target(V1_BADGE + "/vulns/project/" + UUID.randomUUID())
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void projectVulnerabilitiesByUuidMissingAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/" + project.getUuid()).request()
                .get(Response.class);
        Assert.assertEquals(401, response.getStatus(), 0);
    }

    @Test
    public void projectVulnerabilitiesByUuidMissingPermissionTest() {
        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/" + project.getUuid())
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    public void projectVulnerabilitiesByUuidWithAclAccessTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                null
        );

        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0.0");
        project.setAccessTeams(List.of(team));
        qm.persist(project);

        Response response = jersey.target(V1_BADGE + "/vulns/project/" + project.getUuid())
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectVulnerabilitiesByUuidWithAclAccessWithHeaderAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                null
        );

        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0.0");
        project.setAccessTeams(List.of(team));
        qm.persist(project);

        Response response = jersey.target(V1_BADGE + "/vulns/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectVulnerabilitiesByUuidWithAclNoAccessTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                null
        );

        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0.0");
        qm.persist(project);

        Response response = jersey.target(V1_BADGE + "/vulns/project/" + project.getUuid())
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    public void projectVulnerabilitiesByNameAndVersionTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/Acme%20Example/1.0.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectVulnerabilitiesByNameAndVersionWithHeaderAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);
        enableUnauthenticatedBadgeAccess();

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/Acme%20Example/1.0.0").request()
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectVulnerabilitiesByNameAndVersionMissingAuthenticationWithUnauthenticatedAccessEnabledTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/Acme%20Example/1.0.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectVulnerabilitiesByNameAndVersionProjectNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Response response = jersey.target(V1_BADGE + "/vulns/project/ProjectNameDoesNotExist/1.0.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void projectVulnerabilitiesByNameAndVersionVersionNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/Acme%20Example/1.2.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void projectVulnerabilitiesByNameAndVersionMissingAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/Acme%20Example/1.0.0").request()
                .get(Response.class);
        Assert.assertEquals(401, response.getStatus(), 0);
    }

    @Test
    public void projectVulnerabilitiesByNameAndVersionMissingPermissionTest() {
        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/Acme%20Example/1.0.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    public void projectVulnerabilitiesByNameAndVersionWithAclAccessTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                null
        );

        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0.0");
        project.setAccessTeams(List.of(team));
        qm.persist(project);

        Response response = jersey.target(V1_BADGE + "/vulns/project/Acme%20Example/1.0.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectVulnerabilitiesByNameAndVersionWithAclAccessWithHeaderAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                null
        );

        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0.0");
        project.setAccessTeams(List.of(team));
        qm.persist(project);

        Response response = jersey.target(V1_BADGE + "/vulns/project/Acme%20Example/1.0.0").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectVulnerabilitiesByNameAndVersionWithAclNoAccessTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                null
        );

        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0.0");
        qm.persist(project);

        Response response = jersey.target(V1_BADGE + "/vulns/project/Acme%20Example/1.0.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    public void projectPolicyViolationsByUuidTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/" + project.getUuid())
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectPolicyViolationsByUuidWithHeaderAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectPolicyViolationsByUuidMissingAuthenticationWithUnauthenticatedAccessEnabledTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);
        enableUnauthenticatedBadgeAccess();

        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/" + project.getUuid())
                .request()
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectPolicyViolationsByUuidProjectNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Response response = jersey.target(V1_BADGE + "/violations/project/" + UUID.randomUUID())
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void projectPolicyViolationsByUuidMissingAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/" + project.getUuid()).request()
                .get(Response.class);
        Assert.assertEquals(401, response.getStatus(), 0);
    }

    @Test
    public void projectPolicyViolationsByUuidMissingPermissionTest() {
        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/" + project.getUuid())
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    public void projectPolicyViolationsByUuidWithAclAccessTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                null
        );

        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0.0");
        project.setAccessTeams(List.of(team));
        qm.persist(project);

        Response response = jersey.target(V1_BADGE + "/violations/project/" + project.getUuid())
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectPolicyViolationsByUuidWithAclAccessWithHeaderAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                null
        );

        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0.0");
        project.setAccessTeams(List.of(team));
        qm.persist(project);

        Response response = jersey.target(V1_BADGE + "/violations/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectPolicyViolationsByUuidWithAclNoAccessTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                null
        );

        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0.0");
        qm.persist(project);

        Response response = jersey.target(V1_BADGE + "/violations/project/" + project.getUuid())
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    public void projectPolicyViolationsByNameAndVersionTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/Acme%20Example/1.0.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectPolicyViolationsByNameAndVersionWithHeaderAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/Acme%20Example/1.0.0").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectPolicyViolationsByNameAndVersionMissingAuthenticationWithUnauthenticatedAccessEnabledTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);
        enableUnauthenticatedBadgeAccess();

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/Acme%20Example/1.0.0")
                .request()
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectPolicyViolationsByNameAndVersionProjectNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Response response = jersey.target(V1_BADGE + "/violations/project/ProjectNameDoesNotExist/1.0.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void projectPolicyViolationsByNameAndVersionVersionNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/Acme%20Example/1.2.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void projectPolicyViolationsByNameAndVersionMissingAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/Acme%20Example/1.0.0").request()
                .get(Response.class);
        Assert.assertEquals(401, response.getStatus(), 0);
    }

    @Test
    public void projectPolicyViolationsByNameAndVersionMissingPermissionTest() {
        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/Acme%20Example/1.0.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    public void projectPolicyViolationsByNameAndVersionWithAclAccessTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                null
        );

        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        project.setAccessTeams(List.of(team));
        qm.persist(project);

        Response response = jersey.target(V1_BADGE + "/violations/project/Acme%20Example/1.0.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectPolicyViolationsByNameAndVersionWithAclAccessWithHeaderAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                null
        );

        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        project.setAccessTeams(List.of(team));
        qm.persist(project);

        Response response = jersey.target(V1_BADGE + "/violations/project/Acme%20Example/1.0.0").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assert.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    public void projectPolicyViolationsByNameAndVersionWithAclNoAccessTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                null
        );

        Project project = new Project();
        project.setName("Acme Example");
        project.setVersion("1.0.0");
        qm.persist(project);

        Response response = jersey.target(V1_BADGE + "/violations/project/Acme%20Example/1.0.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assert.assertEquals(403, response.getStatus(), 0);
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

    private void enableUnauthenticatedBadgeAccess() {
        qm.getConfigProperty(GENERAL_BADGE_ENABLED.getGroupName(), GENERAL_BADGE_ENABLED.getPropertyName())
                .setPropertyValue("true");
    }
}
