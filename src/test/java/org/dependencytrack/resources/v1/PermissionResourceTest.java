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

import alpine.auth.PasswordService;
import alpine.filters.ApiFilter;
import alpine.filters.AuthenticationFilter;
import alpine.model.ManagedUser;
import alpine.model.Permission;
import alpine.model.Team;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.UUID;

public class PermissionResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(PermissionResource.class)
                        .register(ApiFilter.class)
                        .register(AuthenticationFilter.class)))
                .build();
    }

    @Before
    public void before() throws Exception {
        super.before();
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        generator.contextInitialized(null);
    }

    @Test
    public void getAllPermissionsTest() {
        Response response = target(V1_PERMISSION).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(10, json.size());
        Assert.assertEquals("ACCESS_MANAGEMENT", json.getJsonObject(0).getString("name"));
        Assert.assertEquals("Allows the management of users, teams, and API keys", json.getJsonObject(0).getString("description"));
    }

    @Test
    public void addPermissionToUserTest() {
        ManagedUser user = qm.createManagedUser("user1", new String(PasswordService.createHash("password".toCharArray())));
        String username = user.getUsername();
        qm.close();
        Response response = target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/" + username).request()
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
        Response response = target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/blah").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The user could not be found.", body);
    }

    @Test
    public void addPermissionToUserInvalidPermissionTest() {
        ManagedUser user = qm.createManagedUser("user1", new String(PasswordService.createHash("password".toCharArray())));
        String username = user.getUsername();
        qm.close();
        Response response = target(V1_PERMISSION + "/BLAH/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The permission could not be found.", body);
    }

    @Test
    public void addPermissionToUserDuplicateTest() {
        ManagedUser user = qm.createManagedUser("user1", new String(PasswordService.createHash("password".toCharArray())));
        String username = user.getUsername();
        Permission permission = qm.getPermission(Permissions.PORTFOLIO_MANAGEMENT.name());
        user.getPermissions().add(permission);
        qm.persist(user);
        qm.close();
        Response response = target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void removePermissionFromUserTest() {
        ManagedUser user = qm.createManagedUser("user1", new String(PasswordService.createHash("password".toCharArray())));
        String username = user.getUsername();
        Permission permission = qm.getPermission(Permissions.PORTFOLIO_MANAGEMENT.name());
        user.getPermissions().add(permission);
        qm.persist(user);
        qm.close();
        Response response = target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/" + username).request()
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
        Response response = target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/blah").request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The user could not be found.", body);
    }

    @Test
    public void removePermissionFromUserInvalidPermissionTest() {
        ManagedUser user = qm.createManagedUser("user1", new String(PasswordService.createHash("password".toCharArray())));
        String username = user.getUsername();
        qm.close();
        Response response = target(V1_PERMISSION + "/BLAH/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The permission could not be found.", body);
    }

    @Test
    public void removePermissionFromUserNoChangesTest() {
        ManagedUser user = qm.createManagedUser("user1", new String(PasswordService.createHash("password".toCharArray())));
        String username = user.getUsername();
        Response response = target(V1_PERMISSION + "/BOM_UPLOAD/user/" + username).request()
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
        Response response = target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + teamUuid).request()
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
        Response response = target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + UUID.randomUUID().toString()).request()
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
        Response response = target(V1_PERMISSION + "/BLAH/team/" + teamUuid).request()
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
        Response response = target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + teamUuid).request()
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
        Response response = target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + teamUuid).request()
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
        Response response = target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + UUID.randomUUID().toString()).request()
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
        Response response = target(V1_PERMISSION + "/BLAH/team/" + teamUuid).request()
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
        Response response = target(V1_PERMISSION + "/BOM_UPLOAD/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(304, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }
}
