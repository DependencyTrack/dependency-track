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

import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
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
import org.dependencytrack.model.IdentifiableObject;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.UUID;

class UserResourceAuthenticatedTest extends ResourceTest {

    @RegisterExtension
    public static JerseyTestExtension jersey = new JerseyTestExtension(
            () -> new ResourceConfig(UserResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    private ManagedUser testUser;
    private String jwt;

    @BeforeEach
    public void before() throws Exception {
        testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        this.jwt = new JsonWebToken().createToken(testUser);
        qm.addUserToTeam(testUser, team);
    }

    @AfterEach
    public void after() {
        qm.delete(testUser);
    }

    @Test
    void getManagedUsersTest() {
        for (int i=0; i<1000; i++) {
            qm.createManagedUser("managed-user-" + i, TEST_USER_PASSWORD_HASH);
        }
        Response response = jersey.target(V1_USER + "/managed").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(1001), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(1001, json.size()); // There's already a built-in managed user in ResourceTest
        Assertions.assertEquals("managed-user-0", json.getJsonObject(0).getString("username"));
    }

    @Test
    void getLdapUsersTest() {
        for (int i=0; i<1000; i++) {
            qm.createLdapUser("ldap-user-" + i);
        }
        Response response = jersey.target(V1_USER + "/ldap").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(1000), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(1000, json.size());
        Assertions.assertEquals("ldap-user-0", json.getJsonObject(0).getString("username"));
    }

    @Test
    void getSelfTest() {
        Response response = jersey.target(V1_USER + "/self").request()
                .header("Authorization", "Bearer " + jwt)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("testuser", json.getString("username"));
    }

    @Test
    void getSelfNonUserTest() {
        Response response = jersey.target(V1_USER + "/self").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(401, response.getStatus(), 0);
    }

    @Test
    void updateSelfTest() {
        ManagedUser user = new ManagedUser();
        user.setUsername(testUser.getUsername());
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        Response response = jersey.target(V1_USER + "/self").request()
                .header("Authorization", "Bearer " + jwt)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("Captain BlackBeard", json.getString("fullname"));
        Assertions.assertEquals("blackbeard@example.com", json.getString("email"));
    }

    @Test
    void updateSelfInvalidFullnameTest() {
        ManagedUser user = new ManagedUser();
        user.setUsername(testUser.getUsername());
        user.setFullname("");
        user.setEmail("blackbeard@example.com");
        Response response = jersey.target(V1_USER + "/self").request()
                .header("Authorization", "Bearer " + jwt)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assertions.assertEquals("Full name is required.", body);
    }

    @Test
    void updateSelfInvalidEmailTest() {
        ManagedUser user = new ManagedUser();
        user.setUsername(testUser.getUsername());
        user.setFullname("Captain BlackBeard");
        user.setEmail("");
        Response response = jersey.target(V1_USER + "/self").request()
                .header("Authorization", "Bearer " + jwt)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assertions.assertEquals("Email address is required.", body);
    }

    @Test
    void updateSelfUnauthorizedTest() {
        ManagedUser user = new ManagedUser();
        user.setUsername(testUser.getUsername());
        Response response = jersey.target(V1_USER + "/self").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(401, response.getStatus(), 0);
    }

    @Test
    void updateSelfPasswordsTest() {
        ManagedUser user = new ManagedUser();
        user.setUsername(testUser.getUsername());
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setNewPassword("newPassword");
        user.setConfirmPassword("newPassword");
        Response response = jersey.target(V1_USER + "/self").request()
                .header("Authorization", "Bearer " + jwt)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("Captain BlackBeard", json.getString("fullname"));
        Assertions.assertEquals("blackbeard@example.com", json.getString("email"));
    }

    @Test
    void updateSelfPasswordMismatchTest() {
        ManagedUser user = new ManagedUser();
        user.setUsername(testUser.getUsername());
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setNewPassword("newPassword");
        user.setConfirmPassword("blah");
        Response response = jersey.target(V1_USER + "/self").request()
                .header("Authorization", "Bearer " + jwt)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assertions.assertEquals("Passwords do not match.", body);
    }

    @Test
    void createLdapUserTest() {
        LdapUser user = new LdapUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/ldap").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("blackbeard", json.getString("username"));
    }

    @Test
    void createLdapUserInvalidUsernameTest() {
        LdapUser user = new LdapUser();
        user.setUsername("");
        Response response = jersey.target(V1_USER + "/ldap").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assertions.assertEquals("Username cannot be null or blank.", body);
    }

    @Test
    void createLdapUserDuplicateUsernameTest() {
        qm.createLdapUser("blackbeard");
        LdapUser user = new LdapUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/ldap").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(409, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assertions.assertEquals("A user with the same username already exists. Cannot create new user.", body);
    }

    @Test
    void deleteLdapUserTest() {
        qm.createLdapUser("blackbeard");
        LdapUser user = new LdapUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/ldap").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(user, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assertions.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    void createManagedUserTest() {
        ManagedUser user = new ManagedUser();
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setUsername("blackbeard");
        user.setNewPassword("password");
        user.setConfirmPassword("password");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("Captain BlackBeard", json.getString("fullname"));
        Assertions.assertEquals("blackbeard@example.com", json.getString("email"));
        Assertions.assertEquals("blackbeard", json.getString("username"));
    }

    @Test
    void createManagedUserInvalidUsernameTest() {
        ManagedUser user = new ManagedUser();
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setUsername("");
        user.setNewPassword("password");
        user.setConfirmPassword("password");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("Username cannot be null or blank.", body);
    }

    @Test
    void createManagedUserInvalidFullnameTest() {
        ManagedUser user = new ManagedUser();
        user.setFullname("");
        user.setEmail("blackbeard@example.com");
        user.setUsername("blackbeard");
        user.setNewPassword("password");
        user.setConfirmPassword("password");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The users full name is missing.", body);
    }

    @Test
    void createManagedUserInvalidEmailTest() {
        ManagedUser user = new ManagedUser();
        user.setFullname("Captain BlackBeard");
        user.setEmail("");
        user.setUsername("blackbeard");
        user.setNewPassword("password");
        user.setConfirmPassword("password");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The users email address is missing.", body);
    }

    @Test
    void createManagedUserInvalidPasswordTest() {
        ManagedUser user = new ManagedUser();
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setUsername("blackbeard");
        user.setNewPassword("");
        user.setConfirmPassword("password");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("A password must be set.", body);
    }

    @Test
    void createManagedUserPasswordMismatchTest() {
        ManagedUser user = new ManagedUser();
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setUsername("blackbeard");
        user.setNewPassword("password");
        user.setConfirmPassword("blah");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The passwords do not match.", body);
    }

    @Test
    void createManagedUserDuplicateUsernameTest() {
        qm.createManagedUser("blackbeard", TEST_USER_PASSWORD_HASH);
        ManagedUser user = new ManagedUser();
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setUsername("blackbeard");
        user.setNewPassword("password");
        user.setConfirmPassword("password");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(409, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("A user with the same username already exists. Cannot create new user.", body);
    }

    @Test
    void updateManagedUserTest() {
        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        ManagedUser user = new ManagedUser();
        user.setUsername("blackbeard");
        user.setFullname("Dr BlackBeard, Ph.D.");
        user.setEmail("blackbeard@example.com");
        user.setForcePasswordChange(true);
        user.setNonExpiryPassword(true);
        user.setSuspended(true);
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("Dr BlackBeard, Ph.D.", json.getString("fullname"));
        Assertions.assertEquals("blackbeard@example.com", json.getString("email"));
        Assertions.assertTrue(json.getBoolean("forcePasswordChange"));
        Assertions.assertTrue(json.getBoolean("nonExpiryPassword"));
        Assertions.assertTrue(json.getBoolean("suspended"));
    }

    @Test
    void updateManagedUserInvalidFullnameTest() {
        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        ManagedUser user = new ManagedUser();
        user.setUsername("blackbeard");
        user.setFullname("");
        user.setEmail("blackbeard@example.com");
        user.setForcePasswordChange(true);
        user.setNonExpiryPassword(true);
        user.setSuspended(true);
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The users full name is missing.", body);
    }

    @Test
    void updateManagedUserInvalidEmailTest() {
        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        ManagedUser user = new ManagedUser();
        user.setUsername("blackbeard");
        user.setFullname("Captain BlackBeard");
        user.setEmail("");
        user.setForcePasswordChange(true);
        user.setNonExpiryPassword(true);
        user.setSuspended(true);
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The users email address is missing.", body);
    }

    @Test
    void updateManagedUserInvalidUsernameTest() {
        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        ManagedUser user = new ManagedUser();
        user.setUsername("");
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setForcePasswordChange(true);
        user.setNonExpiryPassword(true);
        user.setSuspended(true);
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + jwt)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The user could not be found.", body);
    }

    @Test
    void deleteManagedUserTest() {
        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        ManagedUser user = new ManagedUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(user, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assertions.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    void createOidcUserTest() {
        final OidcUser user = new OidcUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/oidc").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("blackbeard", json.getString("username"));
    }

    @Test
    void createOidcUserDuplicateUsernameTest() {
        qm.createOidcUser("blackbeard");
        final OidcUser user = new OidcUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/oidc").request()
                .header("Authorization", "Bearer " + jwt)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(409, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assertions.assertEquals("A user with the same username already exists. Cannot create new user.", body);
    }

    @Test
    void deleteOidcUserTest() {
        qm.createOidcUser("blackbeard");
        OidcUser user = new OidcUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/oidc").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(user, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assertions.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    void addTeamToUserTest() {
        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        Team team = qm.createTeam("Pirates");
        IdentifiableObject ido = new IdentifiableObject();
        ido.setUuid(team.getUuid().toString());
        ManagedUser user = new ManagedUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/blackbeard/membership").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(ido, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("Captain BlackBeard", json.getString("fullname"));
        Assertions.assertEquals("blackbeard@example.com", json.getString("email"));
        Assertions.assertFalse(json.getBoolean("forcePasswordChange"));
        Assertions.assertFalse(json.getBoolean("nonExpiryPassword"));
        Assertions.assertFalse(json.getBoolean("suspended"));
    }

    @Test
    void addTeamToUserInvalidTeamTest() {
        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        IdentifiableObject ido = new IdentifiableObject();
        ido.setUuid(UUID.randomUUID().toString());
        ManagedUser user = new ManagedUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/blackbeard/membership").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(ido, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The team could not be found.", body);
    }

    @Test
    void addTeamToUserInvalidUserTest() {
        Team team = qm.createTeam("Pirates");
        IdentifiableObject ido = new IdentifiableObject();
        ido.setUuid(team.getUuid().toString());
        ManagedUser user = new ManagedUser();
        user.setUsername("blah");
        Response response = jersey.target(V1_USER + "/blackbeard/membership").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(ido, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The user could not be found.", body);
    }

    @Test
    void addTeamToUserDuplicateMembershipTest() {
        Team team = qm.createTeam("Pirates");
        ManagedUser user = qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        qm.addUserToTeam(user, team);
        IdentifiableObject ido = new IdentifiableObject();
        ido.setUuid(team.getUuid().toString());
        Response response = jersey.target(V1_USER + "/blackbeard/membership").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(ido, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(304, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        // TODO: Possible bug in Jersey? The response entity is set in the resource, but blank in the actual response.
        //Assertions.assertEquals("The user is already a member of the specified team.", body);
    }

    @Test
    void removeTeamFromUserTest() {
        Team team = qm.createTeam("Pirates");
        ManagedUser user = qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        qm.addUserToTeam(user, team);
        IdentifiableObject ido = new IdentifiableObject();
        ido.setUuid(team.getUuid().toString());
        Response response = jersey.target(V1_USER + "/blackbeard/membership").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(ido, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assertions.assertEquals(200, response.getStatus(), 0);
    }
}
