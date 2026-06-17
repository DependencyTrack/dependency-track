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
import alpine.model.User;
import alpine.model.UserSession;
import alpine.server.auth.SessionTokenService;
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
import org.dependencytrack.model.IdentifiableObject;
import org.dependencytrack.notification.NotificationScope;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.notification.NotificationTestUtil.createCatchAllNotificationRule;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_USER_CREATED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_USER_DELETED;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.notification.proto.v1.Scope.SCOPE_SYSTEM;

class UserResourceAuthenticatedTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(UserResource.class)
                    .register(ApiFilter.class)
                    .register(AuthFeature.class));

    private ManagedUser testUser;
    private String sessionToken;

    @BeforeEach
    void beforeEach() {
        testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        this.sessionToken = new SessionTokenService().createSession(testUser.getId());
        qm.addUserToTeam(testUser, team);
    }

    @Test
    void getManagedUsersTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ);

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
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_READ);

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
                .header("Authorization", "Bearer " + sessionToken)
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
                .header("Authorization", "Bearer " + sessionToken)
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
                .header("Authorization", "Bearer " + sessionToken)
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
                .header("Authorization", "Bearer " + sessionToken)
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
                .header("Authorization", "Bearer " + sessionToken)
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
                .header("Authorization", "Bearer " + sessionToken)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assertions.assertEquals("Passwords do not match.", body);
    }

    @Test
    void createLdapUserTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        createCatchAllNotificationRule(qm, NotificationScope.SYSTEM);

        LdapUser user = new LdapUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/ldap").request()
                .header("Authorization", "Bearer " + sessionToken)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("blackbeard", json.getString("username"));

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_SYSTEM);
            assertThat(notification.getGroup()).isEqualTo(GROUP_USER_CREATED);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
            assertThat(notification.getTitle()).isEqualTo("User Created");
            assertThat(notification.getContent()).isEqualTo("User blackbeard was created");
        });
    }

    @Test
    void createLdapUserInvalidUsernameTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        LdapUser user = new LdapUser();
        user.setUsername("");
        Response response = jersey.target(V1_USER + "/ldap").request()
                .header("Authorization", "Bearer " + sessionToken)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assertions.assertEquals("Username cannot be null or blank.", body);
    }

    @Test
    void createLdapUserDuplicateUsernameTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        qm.createLdapUser("blackbeard");
        LdapUser user = new LdapUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/ldap").request()
                .header("Authorization", "Bearer " + sessionToken)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(409, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assertions.assertEquals("A user with the same username already exists. Cannot create new user.", body);
    }

    @Test
    void deleteLdapUserTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_DELETE);

        createCatchAllNotificationRule(qm, NotificationScope.SYSTEM);

        qm.createLdapUser("blackbeard");
        LdapUser user = new LdapUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/ldap").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(user, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assertions.assertEquals(204, response.getStatus(), 0);

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_SYSTEM);
            assertThat(notification.getGroup()).isEqualTo(GROUP_USER_DELETED);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
            assertThat(notification.getTitle()).isEqualTo("User Deleted");
            assertThat(notification.getContent()).isEqualTo("User blackbeard was deleted");
        });
    }

    @Test
    void createManagedUserTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        createCatchAllNotificationRule(qm, NotificationScope.SYSTEM);

        ManagedUser user = new ManagedUser();
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setUsername("blackbeard");
        user.setNewPassword("password");
        user.setConfirmPassword("password");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + sessionToken)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("Captain BlackBeard", json.getString("fullname"));
        Assertions.assertEquals("blackbeard@example.com", json.getString("email"));
        Assertions.assertEquals("blackbeard", json.getString("username"));

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_SYSTEM);
            assertThat(notification.getGroup()).isEqualTo(GROUP_USER_CREATED);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
            assertThat(notification.getTitle()).isEqualTo("User Created");
            assertThat(notification.getContent()).isEqualTo("User blackbeard was created");
        });
    }

    @Test
    void createManagedUserInvalidUsernameTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        ManagedUser user = new ManagedUser();
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setUsername("");
        user.setNewPassword("password");
        user.setConfirmPassword("password");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + sessionToken)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("Username cannot be null or blank.", body);
    }

    @Test
    void createManagedUserInvalidFullnameTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        ManagedUser user = new ManagedUser();
        user.setFullname("");
        user.setEmail("blackbeard@example.com");
        user.setUsername("blackbeard");
        user.setNewPassword("password");
        user.setConfirmPassword("password");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + sessionToken)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The users full name is missing.", body);
    }

    @Test
    void createManagedUserInvalidEmailTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        ManagedUser user = new ManagedUser();
        user.setFullname("Captain BlackBeard");
        user.setEmail("");
        user.setUsername("blackbeard");
        user.setNewPassword("password");
        user.setConfirmPassword("password");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + sessionToken)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The users email address is missing.", body);
    }

    @Test
    void createManagedUserInvalidPasswordTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        ManagedUser user = new ManagedUser();
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setUsername("blackbeard");
        user.setNewPassword("");
        user.setConfirmPassword("password");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + sessionToken)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("A password must be set.", body);
    }

    @Test
    void createManagedUserPasswordMismatchTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        ManagedUser user = new ManagedUser();
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setUsername("blackbeard");
        user.setNewPassword("password");
        user.setConfirmPassword("blah");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + sessionToken)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The passwords do not match.", body);
    }

    @Test
    void createManagedUserDuplicateUsernameTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        qm.createManagedUser("blackbeard", TEST_USER_PASSWORD_HASH);
        ManagedUser user = new ManagedUser();
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setUsername("blackbeard");
        user.setNewPassword("password");
        user.setConfirmPassword("password");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + sessionToken)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(409, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("A user with the same username already exists. Cannot create new user.", body);
    }

    @Test
    void updateManagedUserTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        ManagedUser user = new ManagedUser();
        user.setUsername("blackbeard");
        user.setFullname("Dr BlackBeard, Ph.D.");
        user.setEmail("blackbeard@example.com");
        user.setForcePasswordChange(true);
        user.setNonExpiryPassword(true);
        user.setSuspended(true);
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + sessionToken)
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
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        ManagedUser user = new ManagedUser();
        user.setUsername("blackbeard");
        user.setFullname("");
        user.setEmail("blackbeard@example.com");
        user.setForcePasswordChange(true);
        user.setNonExpiryPassword(true);
        user.setSuspended(true);
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + sessionToken)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The users full name is missing.", body);
    }

    @Test
    void updateManagedUserInvalidEmailTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        ManagedUser user = new ManagedUser();
        user.setUsername("blackbeard");
        user.setFullname("Captain BlackBeard");
        user.setEmail("");
        user.setForcePasswordChange(true);
        user.setNonExpiryPassword(true);
        user.setSuspended(true);
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + sessionToken)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The users email address is missing.", body);
    }

    @Test
    void updateManagedUserInvalidUsernameTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        ManagedUser user = new ManagedUser();
        user.setUsername("");
        user.setFullname("Captain BlackBeard");
        user.setEmail("blackbeard@example.com");
        user.setForcePasswordChange(true);
        user.setNonExpiryPassword(true);
        user.setSuspended(true);
        Response response = jersey.target(V1_USER + "/managed").request()
                .header("Authorization", "Bearer " + sessionToken)
                .post(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The user could not be found.", body);
    }

    @Test
    void deleteManagedUserTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_DELETE);

        createCatchAllNotificationRule(qm, NotificationScope.SYSTEM);

        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com", TEST_USER_PASSWORD_HASH, false, false, false);
        ManagedUser user = new ManagedUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/managed").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(user, MediaType.APPLICATION_JSON)); // HACK
        // Hack: Workaround to https://github.com/eclipse-ee4j/jersey/issues/3798
        Assertions.assertEquals(204, response.getStatus(), 0);

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_SYSTEM);
            assertThat(notification.getGroup()).isEqualTo(GROUP_USER_DELETED);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
            assertThat(notification.getTitle()).isEqualTo("User Deleted");
            assertThat(notification.getContent()).isEqualTo("User blackbeard was deleted");
        });
    }

    @Test
    void createOidcUserTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        createCatchAllNotificationRule(qm, NotificationScope.SYSTEM);

        final OidcUser user = new OidcUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/oidc").request()
                .header("Authorization", "Bearer " + sessionToken)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(201, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals("blackbeard", json.getString("username"));

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_SYSTEM);
            assertThat(notification.getGroup()).isEqualTo(GROUP_USER_CREATED);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
            assertThat(notification.getTitle()).isEqualTo("User Created");
            assertThat(notification.getContent()).isEqualTo("User blackbeard was created");
        });
    }

    @Test
    void createOidcUserDuplicateUsernameTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_CREATE);

        qm.createOidcUser("blackbeard");
        final OidcUser user = new OidcUser();
        user.setUsername("blackbeard");
        Response response = jersey.target(V1_USER + "/oidc").request()
                .header("Authorization", "Bearer " + sessionToken)
                .put(Entity.entity(user, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(409, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assertions.assertEquals("A user with the same username already exists. Cannot create new user.", body);
    }

    @Test
    void deleteOidcUserTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_DELETE);

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
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

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
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

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
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

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
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

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
        //Assert.assertEquals("The user is already a member of the specified team.", body);
    }

    @Test
    void removeTeamFromUserTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_DELETE);

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

    @Test
    void setUserTeamsTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        String username = qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com",
        TEST_USER_PASSWORD_HASH, false, false, false).getUsername();
        String endpoint = V1_USER + "/membership";
        List<Team> teamSet1 = List.of(
            qm.createTeam("Pirates"),
            qm.createTeam("Penguins"),
            qm.createTeam("Steelers"),
            qm.createTeam("Red Sox"),
            qm.createTeam("Cubs")
        );

        List<Team> teamSet2 = List.of(
            qm.createTeam("Yankees"),
            qm.createTeam("Dodgers"),
            qm.createTeam("Giants")
        );

        JsonObject teamRequest1 = Json.createObjectBuilder()
                .add("username", username)
                .add("teams", Json.createArrayBuilder(
                    teamSet1.stream().map(Team::getUuid).map(UUID::toString).toList()))
                .build();

        JsonObject teamRequest2 = Json.createObjectBuilder()
                .add("username", username)
                .add("teams", Json.createArrayBuilder(
                    teamSet2.stream().map(Team::getUuid).map(UUID::toString).toList()))
                .build();

        Response response = jersey.target(endpoint).request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .put(Entity.entity(teamRequest1.toString(), MediaType.APPLICATION_JSON));

        Assertions.assertEquals(200, response.getStatus());

        User user = qm.getManagedUser("blackbeard");
        List<Team> userTeams = user.getTeams();

        Assertions.assertEquals(userTeams.size(), teamSet1.size());
        Assertions.assertTrue(userTeams.containsAll(teamSet1));

        response = jersey.target(endpoint).request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .put(Entity.entity(teamRequest2.toString(), MediaType.APPLICATION_JSON));

        user = qm.getUser("blackbeard");
        userTeams = user.getTeams();

        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals(userTeams.size(), teamSet2.size());
        Assertions.assertTrue(Collections.disjoint(userTeams, teamSet1));
        Assertions.assertTrue(userTeams.containsAll(teamSet2));
    }

    @Test
    void setUserTeamsInvalidTest() {
        initializeWithPermissions(Permissions.ACCESS_MANAGEMENT_UPDATE);

        String endpoint = V1_USER + "/membership";
        qm.createManagedUser("blackbeard", "Captain BlackBeard", "blackbeard@example.com",
                TEST_USER_PASSWORD_HASH, false, false, false);
        UUID teamUuid = qm.createTeam("Pirates").getUuid();

        JsonObject badTeamBody = Json.createObjectBuilder()
            .add("username", "blackbeard")
            .add("teams", Json.createArrayBuilder().add(UUID.randomUUID().toString()))
            .build();

        JsonObject unknownUserBody = Json.createObjectBuilder()
            .add("username", "unknown")
            .add("teams", Json.createArrayBuilder().add(teamUuid.toString()))
            .build();
        // invalid uuid
        Response response = jersey.target(endpoint).request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .put(Entity.entity(badTeamBody.toString(), MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus());

        // unknown user
        response = jersey.target(endpoint).request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .put(Entity.entity(unknownUserBody.toString(), MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus());

    }

    @Test
    void shouldReturnEffectivePermissions() {
        final var viewPortfolio = qm.createPermission(Permissions.VIEW_PORTFOLIO.name(), null);
        final var bomUpload = qm.createPermission(Permissions.BOM_UPLOAD.name(), null);
        team.setPermissions(List.of(viewPortfolio, bomUpload));
        qm.persist(team);

        final Response response = jersey
                .target(V1_USER + "/self/permissions")
                .request()
                .header("Authorization", "Bearer " + sessionToken)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonArray json = parseJsonArray(response);
        assertThat(json).isNotNull();
        assertThat(json.getValuesAs(jakarta.json.JsonString::getString))
                .containsExactlyInAnyOrder("VIEW_PORTFOLIO", "BOM_UPLOAD");
    }

    @Test
    void shouldReturnEmptyPermissionsWhenNoneAssigned() {
        final Response response = jersey
                .target(V1_USER + "/self/permissions")
                .request()
                .header("Authorization", "Bearer " + sessionToken)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonArray json = parseJsonArray(response);
        assertThat(json).isEmpty();
    }

    @Test
    void shouldRejectGetSelfPermissionsWithApiKey() {
        final Response response = jersey
                .target(V1_USER + "/self/permissions")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void shouldLogoutAndInvalidateSession() {
        // Verify the session is valid before logout.
        final Response beforeResponse = jersey
                .target(V1_USER + "/self")
                .request()
                .header("Authorization", "Bearer " + sessionToken)
                .get(Response.class);
        assertThat(beforeResponse.getStatus()).isEqualTo(200);

        // Logout.
        final Response logoutResponse = jersey
                .target(V1_USER + "/logout")
                .request()
                .header("Authorization", "Bearer " + sessionToken)
                .post(Entity.json(""));
        assertThat(logoutResponse.getStatus()).isEqualTo(204);

        // Verify the session is no longer valid.
        final Response afterResponse = jersey
                .target(V1_USER + "/self")
                .request()
                .header("Authorization", "Bearer " + sessionToken)
                .get(Response.class);
        assertThat(afterResponse.getStatus()).isEqualTo(401);
    }

    @Test
    void shouldReturnNoContentWhenLoggingOutWithApiKey() {
        final Response response = jersey
                .target(V1_USER + "/logout")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(""));
        assertThat(response.getStatus()).isEqualTo(204);
    }

    @Test
    void shouldRejectExpiredSession() {
        final List<UserSession> sessions = qm.getPersistenceManager()
                .newQuery(UserSession.class, "user == :user")
                .setParameters(testUser)
                .executeList();
        assertThat(sessions).hasSize(1);
        sessions.getFirst().setExpiresAt(new Date(System.currentTimeMillis() - 3_600_000));

        final Response response = jersey
                .target(V1_USER + "/self")
                .request()
                .header("Authorization", "Bearer " + sessionToken)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void shouldRejectSuspendedUserWithValidSession() {
        testUser.setSuspended(true);
        qm.persist(testUser);

        final Response response = jersey
                .target(V1_USER + "/self")
                .request()
                .header("Authorization", "Bearer " + sessionToken)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void shouldDeleteExpiredSessions() {
        new SessionTokenService().createSession(testUser.getId());

        final List<UserSession> sessions = qm.getPersistenceManager()
                .newQuery(UserSession.class)
                .executeList();
        for (final UserSession session : sessions) {
            session.setExpiresAt(new Date(System.currentTimeMillis() - 3_600_000));
        }
        qm.getPersistenceManager().makePersistentAll(sessions);

        final int deleted = new SessionTokenService().deleteExpiredSessions();
        assertThat(deleted).isEqualTo(2);

        final List<UserSession> remaining = qm.getPersistenceManager()
                .newQuery(UserSession.class, "user == :user")
                .setParameters(testUser)
                .executeList();
        assertThat(remaining).isEmpty();
    }

    @Test
    void shouldNotRevokeSessionOfDifferentUser() {
        final ManagedUser otherUser = qm.createManagedUser("otheruser", TEST_USER_PASSWORD_HASH);
        qm.addUserToTeam(otherUser, team);
        final String otherToken = new SessionTokenService().createSession(otherUser.getId());

        final Response beforeResponse = jersey
                .target(V1_USER + "/self")
                .request()
                .header("Authorization", "Bearer " + otherToken)
                .get(Response.class);
        assertThat(beforeResponse.getStatus()).isEqualTo(200);

        final boolean deleted = new SessionTokenService().deleteSession(otherToken, testUser.getId());
        assertThat(deleted).isFalse();

        final Response afterResponse = jersey
                .target(V1_USER + "/self")
                .request()
                .header("Authorization", "Bearer " + otherToken)
                .get(Response.class);
        assertThat(afterResponse.getStatus()).isEqualTo(200);
    }

}
