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
import alpine.server.filters.AuthFeature;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.DatabaseSeedingInitTask;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

public class PermissionResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(PermissionResource.class)
                    .register(ApiFilter.class)
                    .register(AuthFeature.class));

    @BeforeEach
    public void before() throws Exception {
        super.before();

        useJdbiTransaction(DatabaseSeedingInitTask::seedDefaultPermissions);
    }

    @Test
    public void getAllPermissionsTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ);

        Response response = jersey.target(V1_PERMISSION).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(42, json.size());
        Assertions.assertEquals("ACCESS_MANAGEMENT", json.getJsonObject(0).getString("name"));
        Assertions.assertEquals("Allows the management of users, teams, and API keys", json.getJsonObject(0).getString("description"));
    }

    @Test
    public void addPermissionToUserTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        ManagedUser user = qm.createManagedUser("user1", TEST_USER_PASSWORD_HASH);
        String username = user.getUsername();
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("user1", json.getString("username"));
        Assertions.assertEquals(1, json.getJsonArray("permissions").size());
        Assertions.assertEquals("PORTFOLIO_MANAGEMENT", json.getJsonArray("permissions").getJsonObject(0).getString("name"));
    }

    @Test
    public void addPermissionToUserInvalidUserTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/blah").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The user could not be found.", body);
    }

    @Test
    public void addPermissionToUserInvalidPermissionTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        ManagedUser user = qm.createManagedUser("user1", TEST_USER_PASSWORD_HASH);
        String username = user.getUsername();
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/BLAH/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The permission could not be found.", body);
    }

    @Test
    public void addPermissionToUserDuplicateTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        ManagedUser user = qm.createManagedUser("user1", TEST_USER_PASSWORD_HASH);
        String username = user.getUsername();
        Permission permission = qm.getPermission(Permissions.PORTFOLIO_MANAGEMENT.name());
        user.getPermissions().add(permission);
        qm.persist(user);
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(304, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void removePermissionFromUserTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_DELETE);

        ManagedUser user = qm.createManagedUser("user1", TEST_USER_PASSWORD_HASH);
        String username = user.getUsername();
        Permission permission = qm.getPermission(Permissions.PORTFOLIO_MANAGEMENT.name());
        user.getPermissions().add(permission);
        qm.persist(user);
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("user1", json.getString("username"));
        Assertions.assertEquals(0, json.getJsonArray("permissions").size());
    }

    @Test
    public void removePermissionFromUserInvalidUserTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_DELETE);

        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/user/blah").request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The user could not be found.", body);
    }

    @Test
    public void removePermissionFromUserInvalidPermissionTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_DELETE);

        ManagedUser user = qm.createManagedUser("user1", TEST_USER_PASSWORD_HASH);
        String username = user.getUsername();
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/BLAH/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The permission could not be found.", body);
    }

    @Test
    public void removePermissionFromUserNoChangesTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_DELETE);

        ManagedUser user = qm.createManagedUser("user1", TEST_USER_PASSWORD_HASH);
        String username = user.getUsername();
        Response response = jersey.target(V1_PERMISSION + "/BOM_UPLOAD/user/" + username).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(304, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void addPermissionToTeamTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        Team team = qm.createTeam("team1");
        String teamUuid = team.getUuid().toString();
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("team1", json.getString("name"));
        Assertions.assertEquals(1, json.getJsonArray("permissions").size());
        Assertions.assertEquals("PORTFOLIO_MANAGEMENT", json.getJsonArray("permissions").getJsonObject(0).getString("name"));
    }

    @Test
    public void addPermissionToTeamInvalidTeamTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The team could not be found.", body);
    }

    @Test
    public void addPermissionToTeamInvalidPermissionTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        Team team = qm.createTeam("team1");
        String teamUuid = team.getUuid().toString();
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/BLAH/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The permission could not be found.", body);
    }

    @Test
    public void addPermissionToTeamDuplicateTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        Team team = qm.createTeam("team1");
        String teamUuid = team.getUuid().toString();
        Permission permission = qm.getPermission(Permissions.PORTFOLIO_MANAGEMENT.name());
        team.getPermissions().add(permission);
        qm.persist(team);
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(304, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void removePermissionFromTeamTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_DELETE);

        Team team = qm.createTeam("team1");
        String teamUuid = team.getUuid().toString();
        Permission permission = qm.getPermission(Permissions.PORTFOLIO_MANAGEMENT.name());
        team.getPermissions().add(permission);
        qm.persist(team);
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("team1", json.getString("name"));
        Assertions.assertEquals(0, json.getJsonArray("permissions").size());
    }

    @Test
    public void removePermissionFromTeamInvalidTeamTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_DELETE);

        Response response = jersey.target(V1_PERMISSION + "/PORTFOLIO_MANAGEMENT/team/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The team could not be found.", body);
    }

    @Test
    public void removePermissionFromTeamInvalidPermissionTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_DELETE);

        Team team = qm.createTeam("team1");
        String teamUuid = team.getUuid().toString();
        qm.close();
        Response response = jersey.target(V1_PERMISSION + "/BLAH/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The permission could not be found.", body);
    }

    @Test
    public void removePermissionFromTeamNoChangesTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_DELETE);

        Team team = qm.createTeam("team1");
        String teamUuid = team.getUuid().toString();
        Response response = jersey.target(V1_PERMISSION + "/BOM_UPLOAD/team/" + teamUuid).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(304, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void setUserPermissionsTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        String username = qm.createManagedUser("user2", TEST_USER_PASSWORD_HASH).getUsername();
        String endpoint = V1_PERMISSION + "/user";

        List<Permission> permissionSet1 = List.of(
                qm.getPermission("ACCESS_MANAGEMENT"),
                qm.getPermission("ACCESS_MANAGEMENT_CREATE"),
                qm.getPermission("ACCESS_MANAGEMENT_DELETE"));

        List<Permission> permissionSet2 = List.of(
                qm.getPermission("BOM_UPLOAD"),
                qm.getPermission("VIEW_PORTFOLIO"),
                qm.getPermission("PORTFOLIO_MANAGEMENT"),
                qm.getPermission("PORTFOLIO_MANAGEMENT_CREATE"));

        JsonObject permissionRequest1 = Json.createObjectBuilder()
                .add("username", username)
                .add("permissions", Json.createArrayBuilder(permissionSet1.stream().map(Permission::getName).toList()))
                .build();

        JsonObject permissionRequest2 = Json.createObjectBuilder()
                .add("username", username)
                .add("permissions", Json.createArrayBuilder(permissionSet2.stream().map(Permission::getName).toList()))
                .build();

        // Test initial assignment.
        Response response = jersey.target(endpoint)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(permissionRequest1.toString(), MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus());

        JsonObject jsonResponse = parseJsonObject(response);

        Assertions.assertNotNull(jsonResponse, "JSON response should not be null");
        Assertions.assertEquals(permissionSet1.size(), jsonResponse.getJsonArray("permissions").size());

        ManagedUser user = qm.getManagedUser(username);
        List<Permission> userPermissions = user.getPermissions();

        Assertions.assertEquals(userPermissions.size(), 3, "User should have 3 permissions assigned");
        Assertions.assertTrue(userPermissions.equals(permissionSet1),
                "User should have all permissions assigned: " + userPermissions);

        // Test replacement.
        response = jersey.target(endpoint)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(permissionRequest2.toString(), MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus());

        // Refresh
        user = qm.getManagedUser(username);
        userPermissions = user.getPermissions();

        Assertions.assertTrue(Collections.disjoint(userPermissions, permissionSet1),
                "User should not have any of the old permissions assigned");
        Assertions.assertTrue(userPermissions.containsAll(permissionSet2),
                "User should have all new permissions assigned: " + userPermissions);

    }

    @Test
    public void setUserPermissionsInvalidTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        qm.createManagedUser("user2", TEST_USER_PASSWORD_HASH);

        // Create a raw JSON payload with invalid permissions.
        JsonObject requestBody = Json.createObjectBuilder()
                .add("username", "user2")
                .add("permissions", Json.createArrayBuilder()
                        .add("Invalid")
                        .add("Permission")
                        .add("List")
                        .add("Four"))
                .build();

        Response response = jersey.target(V1_PERMISSION + "/user")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(requestBody.toString(), MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus());

        JsonObject jsonResponse = parseJsonObject(response);
        String detail = jsonResponse.get("detail").toString();
        Assertions.assertNotNull(jsonResponse);

        List<String> allPerms = qm.getPermissions().stream()
                .map(Permission::getName)
                .toList();

        // Verify that the request was parsed correctly but contained invalid permissions.
        Assertions.assertTrue(allPerms.stream().allMatch(perm -> detail.contains(perm)));
    }

    @Test
    public void setTeamPermissionsTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        UUID teamUuid = qm.createTeam("team1").getUuid();
        String endpoint = V1_PERMISSION + "/team";

        List<Permission> permissionSet1 = List.of(
                qm.getPermission("ACCESS_MANAGEMENT"),
                qm.getPermission("ACCESS_MANAGEMENT_CREATE"),
                qm.getPermission("ACCESS_MANAGEMENT_DELETE"));

        List<Permission> permissionSet2 = List.of(
                qm.getPermission("BOM_UPLOAD"),
                qm.getPermission("VIEW_PORTFOLIO"),
                qm.getPermission("PORTFOLIO_MANAGEMENT"),
                qm.getPermission("PORTFOLIO_MANAGEMENT_CREATE"));

        JsonObject permissionRequet1 = Json.createObjectBuilder()
                .add("team", teamUuid.toString())
                .add("permissions", Json.createArrayBuilder(permissionSet1.stream().map(Permission::getName).toList()))
                .build();

        JsonObject permissionRequet2 = Json.createObjectBuilder()
                .add("team", teamUuid.toString())
                .add("permissions", Json.createArrayBuilder(permissionSet2.stream().map(Permission::getName).toList()))
                .build();

        // Test initial assignment.
        Response response = jersey.target(endpoint)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(permissionRequet1.toString(), MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus());

        JsonObject jsonResponse = parseJsonObject(response);

        Assertions.assertNotNull(jsonResponse, "JSON response should not be null");
        Assertions.assertEquals(permissionSet1.size(), jsonResponse.getJsonArray("permissions").size());

        Team team = qm.getObjectByUuid(Team.class, teamUuid);
        List<Permission> userPermissions = team.getPermissions();

        Assertions.assertEquals(userPermissions.size(), 3, "User should have 3 permissions assigned");
        Assertions.assertTrue(userPermissions.equals(permissionSet1),
                "User should have all permissions assigned: " + userPermissions);

        // Test replacement.
        response = jersey.target(endpoint)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(permissionRequet2.toString(), MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus());

        // Refresh.
        team = qm.getObjectByUuid(Team.class, teamUuid);
        userPermissions = team.getPermissions();

        Assertions.assertTrue(Collections.disjoint(userPermissions, permissionSet1),
                "User should not have any of the old permissions assigned");
        Assertions.assertTrue(userPermissions.containsAll(permissionSet2),
                "User should have all new permissions assigned: " + userPermissions);
    }

}
