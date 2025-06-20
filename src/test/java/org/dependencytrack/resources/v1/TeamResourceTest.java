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

import alpine.common.util.UuidUtil;
import alpine.model.ApiKey;
import alpine.model.ConfigProperty;
import alpine.model.ManagedUser;
import alpine.model.Permission;
import alpine.model.Team;
import alpine.server.auth.JsonWebToken;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.DefaultObjectGenerator;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.equalTo;

class TeamResourceTest extends ResourceTest {
    private String jwt;
    private Team userNotPartof;

    @RegisterExtension
    public static JerseyTestExtension jersey = new JerseyTestExtension(
            () -> new ResourceConfig(TeamResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    public void setUpUser(boolean isAdmin) {
        ManagedUser testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        jwt = new JsonWebToken().createToken(testUser);
        qm.addUserToTeam(testUser, team);
        userNotPartof = qm.createTeam("UserNotPartof");
        if (isAdmin) {
            final var generator = new DefaultObjectGenerator();
            generator.loadDefaultPermissions();
            List<Permission> permissionsList = new ArrayList<Permission>();
            final Permission adminPermission = qm.getPermission("ACCESS_MANAGEMENT");
            permissionsList.add(adminPermission);
            testUser.setPermissions(permissionsList);
        }
    }

    @Test
    void getTeamsTest() {
        for (int i=0; i<1000; i++) {
            qm.createTeam("Team " + i);
        }
        Response response = jersey.target(V1_TEAM).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(1001), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(1001, json.size()); // There's already a built-in team in ResourceTest
        Assertions.assertEquals("Team 0", json.getJsonObject(0).getString("name"));
    }

    @Test
    void getTeamTest() {
        Team team = qm.createTeam("ABC");
        Response response = jersey.target(V1_TEAM + "/" + team.getUuid())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("ABC", json.getString("name"));
    }

    @Test
    void getTeamByInvalidUuidTest() {
        Response response = jersey.target(V1_TEAM + "/" + UUID.randomUUID())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The team could not be found.", body);
    }

    @Test
    void getTeamSelfTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        var response = jersey.target(V1_TEAM + "/self").request().header(X_API_KEY, apiKey).get(Response.class);
        Assertions.assertEquals(200, response.getStatus());
        final var json = parseJsonObject(response);
        Assertions.assertEquals(team.getName(), json.getString("name"));
        Assertions.assertEquals(team.getUuid().toString(), json.getString("uuid"));
        final var permissions = json.getJsonArray("permissions");
        Assertions.assertEquals(2, permissions.size());
        Assertions.assertEquals(Permissions.BOM_UPLOAD.toString(), permissions.get(0).asJsonObject().getString("name"));
        Assertions.assertEquals(Permissions.PROJECT_CREATION_UPLOAD.toString(), permissions.get(1).asJsonObject().getString("name"));

        // missing api-key
        response = jersey.target(V1_TEAM + "/self").request().get(Response.class);
        Assertions.assertEquals(401, response.getStatus());

        // wrong api-key
        response = jersey.target(V1_TEAM + "/self").request().header(X_API_KEY, "5ce9b8a5-5f18-4c1f-9eda-1611b83e8915").get(Response.class);
        Assertions.assertEquals(401, response.getStatus());

        // not an api-key
        final ManagedUser testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        final String jwt = new JsonWebToken().createToken(testUser);
        response = jersey.target(V1_TEAM + "/self").request().header("Authorization", "Bearer " + jwt).get(Response.class);
        Assertions.assertEquals(400, response.getStatus());
    }

    @Test
    void createTeamTest() {
        Team team = new Team();
        team.setName("My Team");
        Response response = jersey.target(V1_TEAM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(team, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("My Team", json.getString("name"));
        Assertions.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
        Assertions.assertTrue(json.getJsonArray("apiKeys").isEmpty());
    }

    @Test
    void updateTeamTest() {
        Team team = qm.createTeam("My Team");
        team.setName("My New Teams Name");
        Response response = jersey.target(V1_TEAM).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(team, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("My New Teams Name", json.getString("name"));
    }

    @Test
    void updateTeamEmptyNameTest() {
        Team team = qm.createTeam("My Team");
        team.setName(" ");
        Response response = jersey.target(V1_TEAM).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(team, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
    }

    @Test
    void updateTeamInvalidTest() {
        Team team = new Team();
        team.setName("My Team");
        team.setUuid(UUID.randomUUID());
        Response response = jersey.target(V1_TEAM).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(team, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The team could not be found.", body);
    }

    @Test
    void deleteTeamTest() {
        Team team = qm.createTeam("My Team");
        Response response = jersey.target(V1_TEAM).request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(team, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assertions.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    void deleteTeamWithAclTest() {
        Team team = qm.createTeam("My Team");
        ConfigProperty aclToogle = qm.getConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName());
        if (aclToogle == null) {
            qm.createConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(), "true", ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());
        } else {
             aclToogle.setPropertyValue("true");
             qm.persist(aclToogle);
        }
        Project project = qm.createProject("Acme Example", null, "1", null, null, null, true, false);
        project.addAccessTeam(team);
        qm.persist(project);
        Response response = jersey.target(V1_TEAM).request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(team, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assertions.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    void getVisibleAdminTeams() {
        setUpUser(true);
        Response response = jersey.target(V1_TEAM + "/visible")
                .request()
                .header("Authorization", "Bearer " + jwt)
                .get();
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonArray teams = parseJsonArray(response);
        Assertions.assertEquals(2, teams.size());
        Assertions.assertEquals(this.team.getUuid().toString(), teams.getFirst().asJsonObject().getString("uuid"));
        Assertions.assertEquals(userNotPartof.getUuid().toString(), teams.get(1).asJsonObject().getString("uuid"));
    }

    @Test
    void getVisibleNotAdminTeams() {
        setUpUser(false);
        Response response = jersey.target(V1_TEAM + "/visible")
                .request()
                .header("Authorization", "Bearer " + jwt)
                .get();
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonArray teams = parseJsonArray(response);
        Assertions.assertEquals(1, teams.size());
        Assertions.assertEquals(this.team.getUuid().toString(), teams.getFirst().asJsonObject().getString("uuid"));
    }

    @Test
    void getVisibleNotAdminApiKeyTeams() {
        Response response = jersey.target(V1_TEAM + "/visible")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonArray teams = parseJsonArray(response);
        Assertions.assertEquals(1, teams.size());
        Assertions.assertEquals(this.team.getUuid().toString(), teams.getFirst().asJsonObject().getString("uuid"));
    }

    @Test
    void getVisibleAdminApiKeyTeams() {
        userNotPartof = qm.createTeam("UserNotPartof");
        final var generator = new DefaultObjectGenerator();
        generator.loadDefaultPermissions();
        List<Permission> permissionsList = new ArrayList<Permission>();
        final Permission adminPermission = qm.getPermission("ACCESS_MANAGEMENT");
        permissionsList.add(adminPermission);
        this.team.setPermissions(permissionsList);

        Response response = jersey.target(V1_TEAM + "/visible")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonArray teams = parseJsonArray(response);
        Assertions.assertEquals(2, teams.size());
        Assertions.assertEquals(this.team.getUuid().toString(), teams.getFirst().asJsonObject().getString("uuid"));
        Assertions.assertEquals(userNotPartof.getUuid().toString(), teams.get(1).asJsonObject().getString("uuid"));
    }

    @Test
    void generateApiKeyTest() {
        Team team = qm.createTeam("My Team");
        Assertions.assertEquals(0, team.getApiKeys().size());
        Response response = jersey.target(V1_TEAM + "/" + team.getUuid().toString() + "/key").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .put(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        team = qm.getTeams().get(0);
        Assertions.assertEquals(1, team.getApiKeys().size());
    }

    @Test
    void generateApiKeyInvalidTest() {
        Response response = jersey.target(V1_TEAM + "/" + UUID.randomUUID().toString() + "/key").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .put(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The team could not be found.", body);
    }

    @Test
    void regenerateApiKeyTest() {
        Team team = qm.createTeam("My Team");
        ApiKey apiKey = qm.createApiKey(team);
        Assertions.assertEquals(1, team.getApiKeys().size());
        Response response = jersey.target(V1_TEAM + "/key/" + apiKey.getPublicId()).request()
                .header(X_API_KEY, apiKey.getKey())
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("publicId", equalTo(apiKey.getPublicId()))
                .isEqualTo(/* language=JSON */ """
                        {
                          "created": "${json-unit.any-number}",
                          "publicId": "${json-unit.matches:publicId}",
                          "key": "${json-unit.regex}^odt_[0-9a-zA-Z]{8}_[0-9a-zA-Z]{32}$",
                          "legacy": false,
                          "maskedKey": "${json-unit.regex}^odt_[0-9a-zA-Z]{8}\\\\*{32}$"
                        }
                        """);
    }

    @Test
    void regenerateApiKeyLegacyTest() {
        Team team = qm.createTeam("My Team");
        ApiKey apiKey = qm.createApiKey(team);
        Assertions.assertEquals(1, team.getApiKeys().size());
        Response response = jersey.target(V1_TEAM + "/key/" + apiKey.getKey()).request()
                .header(X_API_KEY, apiKey.getKey())
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("publicId", equalTo(apiKey.getPublicId()))
                .isEqualTo(/* language=JSON */ """
                        {
                          "created": "${json-unit.any-number}",
                          "publicId": "${json-unit.matches:publicId}",
                          "key": "${json-unit.regex}^odt_[0-9a-zA-Z]{8}_[0-9a-zA-Z]{32}$",
                          "legacy": false,
                          "maskedKey": "${json-unit.regex}^odt_[0-9a-zA-Z]{8}\\\\*{32}$"
                        }
                        """);
    }

    @Test
    void regenerateApiKeyInvalidTest() {
        Response response = jersey.target(V1_TEAM + "/key/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The API key could not be found.", body);
    }

    @Test
    void deleteApiKeyTest() {
        Team team = qm.createTeam("My Team");
        ApiKey apiKey = qm.createApiKey(team);
        Assertions.assertEquals(1, team.getApiKeys().size());
        Response response = jersey.target(V1_TEAM + "/key/" + apiKey.getPublicId()).request()
                .header(X_API_KEY, apiKey.getKey())
                .delete();
        Assertions.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    void deleteApiKeyLegacyTest() {
        Team team = qm.createTeam("My Team");
        ApiKey apiKey = qm.createApiKey(team);
        Assertions.assertEquals(1, team.getApiKeys().size());
        Response response = jersey.target(V1_TEAM + "/key/" + apiKey.getKey()).request()
                .header(X_API_KEY, apiKey.getKey())
                .delete();
        Assertions.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    void deleteApiKeyInvalidTest() {
        Response response = jersey.target(V1_TEAM + "/key/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The API key could not be found.", body);
    }

    @Test
    void updateApiKeyCommentTest() {
        final Team team = qm.createTeam("foo");
        final ApiKey apiKey = qm.createApiKey(team);

        assertThat(apiKey.getCreated()).isNotNull();
        assertThat(apiKey.getLastUsed()).isNull();
        assertThat(apiKey.getComment()).isNull();

        final Response response = jersey.target("%s/key/%s/comment".formatted(V1_TEAM, apiKey.getPublicId())).request()
                .header(X_API_KEY, this.apiKey)
                .post(Entity.entity("Some comment 123", MediaType.TEXT_PLAIN));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("publicId", equalTo(apiKey.getPublicId()))
                .withMatcher("maskedKey", equalTo(apiKey.getMaskedKey()))
                .isEqualTo("""
                        {
                          "publicId": "${json-unit.matches:publicId}",
                          "maskedKey": "${json-unit.matches:maskedKey}",
                          "created": "${json-unit.any-number}",
                          "legacy": false,
                          "comment": "Some comment 123"
                        }
                        """);
    }

    @Test
    void updateApiKeyCommentLegacyTest() {
        final Team team = qm.createTeam("foo");
        final ApiKey apiKey = qm.createApiKey(team);

        assertThat(apiKey.getCreated()).isNotNull();
        assertThat(apiKey.getLastUsed()).isNull();
        assertThat(apiKey.getComment()).isNull();

        final Response response = jersey.target("%s/key/%s/comment".formatted(V1_TEAM, apiKey.getKey())).request()
                .header(X_API_KEY, this.apiKey)
                .post(Entity.entity("Some comment 123", MediaType.TEXT_PLAIN));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("publicId", equalTo(apiKey.getPublicId()))
                .withMatcher("maskedKey", equalTo(apiKey.getMaskedKey()))
                .isEqualTo(/* language=JSON */ """
                        {
                          "publicId": "${json-unit.matches:publicId}",
                          "maskedKey": "${json-unit.matches:maskedKey}",
                          "created": "${json-unit.any-number}",
                          "legacy": false,
                          "comment": "Some comment 123"
                        }
                        """);
    }

    @Test
    void updateApiKeyCommentNotFoundTest() {
        final Response response = jersey.target("%s/key/does-not-exist/comment".formatted(V1_TEAM)).request()
                .header(X_API_KEY, this.apiKey)
                .post(Entity.entity("Some comment 123", MediaType.TEXT_PLAIN));

        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The API key could not be found.");
    }

}
