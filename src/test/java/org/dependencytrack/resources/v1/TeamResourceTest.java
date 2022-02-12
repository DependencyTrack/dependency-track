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
import alpine.model.Team;
import alpine.util.UuidUtil;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.ResourceTest;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Test;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.UUID;

public class TeamResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                new ResourceConfig(TeamResource.class)
                        .register(ApiFilter.class)
                        .register(AuthenticationFilter.class)))
                .build();
    }

    @Test
    public void getTeamsTest() {
        for (int i=0; i<1000; i++) {
            qm.createTeam("Team " + i, false);
        }
        Response response = target(V1_TEAM).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(1001), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(1001, json.size()); // There's already a built-in team in ResourceTest
        Assert.assertEquals("Team 0", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getTeamTest() {
        Team team = qm.createTeam("ABC", false);
        Response response = target(V1_TEAM + "/" + team.getUuid())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getString("name"));
    }

    @Test
    public void getTeamByInvalidUuidTest() {
        Response response = target(V1_TEAM + "/" + UUID.randomUUID())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The team could not be found.", body);
    }
    
    @Test
    public void getTeamSelfTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        var response = target(V1_TEAM + "/self").request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus());
        final var json = parseJsonObject(response);
        Assert.assertEquals(team.getName(), json.getString("name"));
        Assert.assertEquals(team.getUuid().toString(), json.getString("uuid"));
        final var permissions = json.getJsonArray("permissions");
        Assert.assertEquals(2, permissions.size());
        Assert.assertEquals(Permissions.BOM_UPLOAD.toString(), permissions.get(0).asJsonObject().getString("name"));
        Assert.assertEquals(Permissions.PROJECT_CREATION_UPLOAD.toString(), permissions.get(1).asJsonObject().getString("name"));

        // missing api-key
        response = target(V1_TEAM + "/self").request().get(Response.class);
        Assert.assertEquals(401, response.getStatus());

        // wrong api-key
        response = target(V1_TEAM + "/self").request().header(X_API_KEY, "5ce9b8a5-5f18-4c1f-9eda-1611b83e8915").get(Response.class);
        Assert.assertEquals(401, response.getStatus());

        // not an api-key
        response = target(V1_TEAM + "/self").request().header("Authorization", "Bearer " + jwt).get(Response.class);
        Assert.assertEquals(400, response.getStatus());
    }

    @Test
    public void createTeamTest() {
        Team team = new Team();
        team.setName("My Team");
        Response response = target(V1_TEAM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(team, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("My Team", json.getString("name"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
    }

    @Test
    public void updateTeamTest() {
        Team team = qm.createTeam("My Team", false);
        team.setName("My New Teams Name");
        Response response = target(V1_TEAM).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(team, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("My New Teams Name", json.getString("name"));
    }

    @Test
    public void updateTeamEmptyNameTest() {
        Team team = qm.createTeam("My Team", false);
        team.setName(" ");
        Response response = target(V1_TEAM).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(team, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
    }

    @Test
    public void updateTeamInvalidTest() {
        Team team = new Team();
        team.setName("My Team");
        team.setUuid(UUID.randomUUID());
        Response response = target(V1_TEAM).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(team, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The team could not be found.", body);
    }

    //@Test
    // TODO: The workaround for Jersey (DELETE with body) no longer throws an exception, but produces a 400. Unable to test at this time
    public void deleteTeamTest() {
        Team team = qm.createTeam("My Team", false);
        Response response = target(V1_TEAM).request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(team, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void generateApiKeyTest() {
        Team team = qm.createTeam("My Team", false);
        Assert.assertEquals(0, team.getApiKeys().size());
        Response response = target(V1_TEAM + "/" + team.getUuid().toString() + "/key").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .put(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        team = qm.getTeams().get(0);
        Assert.assertEquals(1, team.getApiKeys().size());
    }

    @Test
    public void generateApiKeyInvalidTest() {
        Response response = target(V1_TEAM + "/" + UUID.randomUUID().toString() + "/key").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .put(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The team could not be found.", body);
    }

    @Test
    public void regenerateApiKeyTest() {
        Team team = qm.createTeam("My Team", true);
        Assert.assertEquals(1, team.getApiKeys().size());
        Response response = target(V1_TEAM + "/key/" + team.getApiKeys().get(0).getKey()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertNotNull(json.getString("key"));
        Assert.assertEquals(1, team.getApiKeys().size());
    }

    @Test
    public void regenerateApiKeyInvalidTest() {
        Response response = target(V1_TEAM + "/key/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The API key could not be found.", body);
    }

    @Test
    public void deleteApiKeyTest() {
        Team team = qm.createTeam("My Team", true);
        Assert.assertEquals(1, team.getApiKeys().size());
        Response response = target(V1_TEAM + "/key/" + team.getApiKeys().get(0).getKey()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void deleteApiKeyInvalidTest() {
        Response response = target(V1_TEAM + "/key/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The API key could not be found.", body);
    }
}
