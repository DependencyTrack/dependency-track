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

import alpine.model.ManagedUser;
import alpine.model.Permission;
import alpine.model.Team;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;

public class PermissionResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(PermissionResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @Before
    public void before() throws Exception {
        super.before();
        final var generator = new DefaultObjectGenerator();
        generator.loadDefaultPermissions();
    }

    @Test
    public void getAllPermissionsTest() {
        Response response = jersey.target(V1_PERMISSION).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        [
                          {
                            "description": "Allows the management of users, teams, and API keys",
                            "name": "ACCESS_MANAGEMENT"
                          },
                          {
                            "description": "Allows the ability to upload CycloneDX Software Bill of Materials (SBOM)",
                            "name": "BOM_UPLOAD"
                          },
                          {
                            "description": "Allows the creation, modification, and deletion of policy",
                            "name": "POLICY_MANAGEMENT"
                          },
                          {
                            "description": "Provides the ability to make analysis decisions on policy violations",
                            "name": "POLICY_VIOLATION_ANALYSIS"
                          },
                          {
                            "description": "Allows the creation, modification, and deletion of data in the portfolio",
                            "name": "PORTFOLIO_MANAGEMENT"
                          },
                          {
                            "description": "Provides the ability to optionally create project (if non-existent) on BOM or scan upload",
                            "name": "PROJECT_CREATION_UPLOAD"
                          },
                          {
                            "description": "Allows the configuration of the system including notifications, repositories, and email settings",
                            "name": "SYSTEM_CONFIGURATION"
                          },
                          {
                            "description": "Allows the modification and deletion of tags",
                            "name": "TAG_MANAGEMENT"
                          },
                          {
                            "description": "Provides the ability to view policy violations",
                            "name": "VIEW_POLICY_VIOLATION"
                          },
                          {
                            "description": "Provides the ability to view the portfolio of projects, components, and licenses",
                            "name": "VIEW_PORTFOLIO"
                          },
                          {
                            "description": "Provides the ability to view the vulnerabilities projects are affected by",
                            "name": "VIEW_VULNERABILITY"
                          },
                          {
                            "description": "Provides the ability to make analysis decisions on vulnerabilities",
                            "name": "VULNERABILITY_ANALYSIS"
                          },
                          {
                            "description": "Allows management of internally-defined vulnerabilities",
                            "name": "VULNERABILITY_MANAGEMENT"
                          }
                        ]
                        """);
    }

    @Test
    public void addPermissionToUserTest() {
        ManagedUser user = qm.createManagedUser("user1", TEST_USER_PASSWORD_HASH);
        String username = user.getUsername();
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("user1", json.getString("username"));
        Assert.assertEquals(1, json.getJsonArray("permissions").size());
        Assert.assertEquals("PORTFOLIO_MANAGEMENT", json.getJsonArray("permissions").getJsonObject(0).getString("name"));
    }

    @Test
    public void addPermissionToUserInvalidUserTest() {
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/blah").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The user could not be found.", body);
    }

    @Test
    public void addPermissionToUserInvalidPermissionTest() {
        ManagedUser user = qm.createManagedUser("user1", TEST_USER_PASSWORD_HASH);
        String username = user.getUsername();
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/BLAH/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The permission could not be found.", body);
    }

    @Test
    public void addPermissionToUserDuplicateTest() {
        ManagedUser user = qm.createManagedUser("user1", TEST_USER_PASSWORD_HASH);
        String username = user.getUsername();
        Permission permission = qm.getPermission(Permissions.PORTFOLIO_MANAGEMENT.name());
        user.getPermissions().add(permission);
        qm.persist(user);
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void removePermissionFromUserTest() {
        ManagedUser user = qm.createManagedUser("user1", TEST_USER_PASSWORD_HASH);
        String username = user.getUsername();
        Permission permission = qm.getPermission(Permissions.PORTFOLIO_MANAGEMENT.name());
        user.getPermissions().add(permission);
        qm.persist(user);
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("user1", json.getString("username"));
        Assert.assertEquals(0, json.getJsonArray("permissions").size());
    }

    @Test
    public void removePermissionFromUserInvalidUserTest() {
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/blah").request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The user could not be found.", body);
    }

    @Test
    public void removePermissionFromUserInvalidPermissionTest() {
        ManagedUser user = qm.createManagedUser("user1", TEST_USER_PASSWORD_HASH);
        String username = user.getUsername();
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/BLAH/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The permission could not be found.", body);
    }

    @Test
    public void removePermissionFromUserNoChangesTest() {
        ManagedUser user = qm.createManagedUser("user1", TEST_USER_PASSWORD_HASH);
        String username = user.getUsername();
        Response response = jersey.target(V1_PERMISSION + "/BOM_UPLOAD/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void addPermissionToTeamTest() {
        Team team = qm.createTeam("team1", false);
        String teamUuid = team.getUuid().toString();
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("team1", json.getString("name"));
        Assert.assertEquals(1, json.getJsonArray("permissions").size());
        Assert.assertEquals("PORTFOLIO_MANAGEMENT", json.getJsonArray("permissions").getJsonObject(0).getString("name"));
    }

    @Test
    public void addPermissionToTeamInvalidTeamTest() {
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The team could not be found.", body);
    }

    @Test
    public void addPermissionToTeamInvalidPermissionTest() {
        Team team = qm.createTeam("team1", false);
        String teamUuid = team.getUuid().toString();
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/BLAH/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The permission could not be found.", body);
    }

    @Test
    public void addPermissionToTeamDuplicateTest() {
        Team team = qm.createTeam("team1", false);
        String teamUuid = team.getUuid().toString();
        Permission permission = qm.getPermission(Permissions.PORTFOLIO_MANAGEMENT.name());
        team.getPermissions().add(permission);
        qm.persist(team);
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void removePermissionFromTeamTest() {
        Team team = qm.createTeam("team1", false);
        String teamUuid = team.getUuid().toString();
        Permission permission = qm.getPermission(Permissions.PORTFOLIO_MANAGEMENT.name());
        team.getPermissions().add(permission);
        qm.persist(team);
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("team1", json.getString("name"));
        Assert.assertEquals(0, json.getJsonArray("permissions").size());
    }

    @Test
    public void removePermissionFromTeamInvalidTeamTest() {
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The team could not be found.", body);
    }

    @Test
    public void removePermissionFromTeamInvalidPermissionTest() {
        Team team = qm.createTeam("team1", false);
        String teamUuid = team.getUuid().toString();
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/BLAH/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The permission could not be found.", body);
    }

    @Test
    public void removePermissionFromTeamNoChangesTest() {
        Team team = qm.createTeam("team1", false);
        String teamUuid = team.getUuid().toString();
        Response response = jersey.target(V1_PERMISSION + "/BOM_UPLOAD/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }
}
