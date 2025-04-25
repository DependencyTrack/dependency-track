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
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.model.ConfigPropertyConstants.GENERAL_BADGE_ENABLED;

class BadgeResourceTest extends ResourceTest {

    @RegisterExtension
    public static JerseyTestExtension jersey = new JerseyTestExtension(
            () -> new ResourceConfig(BadgeResource.class)
                    .register(ApiFilter.class));

    @BeforeEach
    public void before() throws Exception {
        qm.createConfigProperty(GENERAL_BADGE_ENABLED.getGroupName(), GENERAL_BADGE_ENABLED.getPropertyName(), "false", IConfigProperty.PropertyType.BOOLEAN, "Unauthenticated access to badge enabled");
    }

    @Test
    void projectVulnerabilitiesByUuidTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/" + project.getUuid())
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectVulnerabilitiesByUuidWithHeaderAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectVulnerabilitiesByUuidMissingAuthenticationWithUnauthenticatedAccessEnabledTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);
        enableUnauthenticatedBadgeAccess();

        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/" + project.getUuid()).request()
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectVulnerabilitiesByUuidProjectNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Response response = jersey.target(V1_BADGE + "/vulns/project/" + UUID.randomUUID())
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assertions.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    void projectVulnerabilitiesByUuidMissingAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/" + project.getUuid()).request()
                .get(Response.class);
        Assertions.assertEquals(401, response.getStatus(), 0);
    }

    @Test
    void projectVulnerabilitiesByUuidMissingPermissionTest() {
        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/" + project.getUuid())
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assertions.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    void projectVulnerabilitiesByUuidWithAclAccessTest() {
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
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectVulnerabilitiesByUuidWithAclAccessWithHeaderAuthenticationTest() {
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
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectVulnerabilitiesByUuidWithAclNoAccessTest() {
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
        Assertions.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    void projectVulnerabilitiesByNameAndVersionTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/Acme%20Example/1.0.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectVulnerabilitiesByNameAndVersionWithHeaderAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);
        enableUnauthenticatedBadgeAccess();

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/Acme%20Example/1.0.0").request()
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectVulnerabilitiesByNameAndVersionMissingAuthenticationWithUnauthenticatedAccessEnabledTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/Acme%20Example/1.0.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectVulnerabilitiesByNameAndVersionProjectNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Response response = jersey.target(V1_BADGE + "/vulns/project/ProjectNameDoesNotExist/1.0.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assertions.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    void projectVulnerabilitiesByNameAndVersionVersionNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/Acme%20Example/1.2.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assertions.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    void projectVulnerabilitiesByNameAndVersionMissingAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/Acme%20Example/1.0.0").request()
                .get(Response.class);
        Assertions.assertEquals(401, response.getStatus(), 0);
    }

    @Test
    void projectVulnerabilitiesByNameAndVersionMissingPermissionTest() {
        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/vulns/project/Acme%20Example/1.0.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assertions.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    void projectVulnerabilitiesByNameAndVersionWithAclAccessTest() {
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
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectVulnerabilitiesByNameAndVersionWithAclAccessWithHeaderAuthenticationTest() {
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
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectVulnerabilitiesByNameAndVersionWithAclNoAccessTest() {
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
        Assertions.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    void projectPolicyViolationsByUuidTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/" + project.getUuid())
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectPolicyViolationsByUuidWithHeaderAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectPolicyViolationsByUuidMissingAuthenticationWithUnauthenticatedAccessEnabledTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);
        enableUnauthenticatedBadgeAccess();

        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/" + project.getUuid())
                .request()
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectPolicyViolationsByUuidProjectNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Response response = jersey.target(V1_BADGE + "/violations/project/" + UUID.randomUUID())
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assertions.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    void projectPolicyViolationsByUuidMissingAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/" + project.getUuid()).request()
                .get(Response.class);
        Assertions.assertEquals(401, response.getStatus(), 0);
    }

    @Test
    void projectPolicyViolationsByUuidMissingPermissionTest() {
        Project project = qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/" + project.getUuid())
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assertions.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    void projectPolicyViolationsByUuidWithAclAccessTest() {
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
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectPolicyViolationsByUuidWithAclAccessWithHeaderAuthenticationTest() {
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
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectPolicyViolationsByUuidWithAclNoAccessTest() {
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
        Assertions.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    void projectPolicyViolationsByNameAndVersionTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/Acme%20Example/1.0.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectPolicyViolationsByNameAndVersionWithHeaderAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/Acme%20Example/1.0.0").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectPolicyViolationsByNameAndVersionMissingAuthenticationWithUnauthenticatedAccessEnabledTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);
        enableUnauthenticatedBadgeAccess();

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/Acme%20Example/1.0.0")
                .request()
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectPolicyViolationsByNameAndVersionProjectNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        Response response = jersey.target(V1_BADGE + "/violations/project/ProjectNameDoesNotExist/1.0.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assertions.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    void projectPolicyViolationsByNameAndVersionVersionNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/Acme%20Example/1.2.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assertions.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    void projectPolicyViolationsByNameAndVersionMissingAuthenticationTest() {
        initializeWithPermissions(Permissions.VIEW_BADGES);

        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/Acme%20Example/1.0.0").request()
                .get(Response.class);
        Assertions.assertEquals(401, response.getStatus(), 0);
    }

    @Test
    void projectPolicyViolationsByNameAndVersionMissingPermissionTest() {
        qm.createProject("Acme Example", null, "1.0.0", null, null, null, true, false);
        Response response = jersey.target(V1_BADGE + "/violations/project/Acme%20Example/1.0.0")
                .queryParam(API_KEY, apiKey)
                .request()
                .get(Response.class);
        Assertions.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    void projectPolicyViolationsByNameAndVersionWithAclAccessTest() {
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
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectPolicyViolationsByNameAndVersionWithAclAccessWithHeaderAuthenticationTest() {
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
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals("image/svg+xml", response.getHeaderString("Content-Type"));
        Assertions.assertTrue(isLikelySvg(getPlainTextBody(response)));
    }

    @Test
    void projectPolicyViolationsByNameAndVersionWithAclNoAccessTest() {
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
        Assertions.assertEquals(403, response.getStatus(), 0);
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
