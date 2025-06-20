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
import alpine.server.auth.PasswordService;
import alpine.server.filters.ApiFilter;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

class UserResourceUnauthenticatedTest extends ResourceTest {

    @RegisterExtension
    public static JerseyTestExtension jersey = new JerseyTestExtension(
            () -> new ResourceConfig(UserResource.class)
                    .register(ApiFilter.class));

    private ManagedUser testUser;

    @BeforeEach
    public void before() throws Exception {
        testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        qm.addUserToTeam(testUser, team);
    }

    @Test
    void validateCredentialsTest() {
        Form form = new Form();
        form.param("username", "testuser");
        form.param("password", "testuser");
        Response response = jersey.target(V1_USER + "/login").request()
                .accept(MediaType.TEXT_PLAIN)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assertions.assertEquals(200, response.getStatus(), 0);
        String token = getPlainTextBody(response);
        Assertions.assertNotNull(token);
        //Assertions.assertEquals(token, response.getCookies().get("Authorization-Token").getValue());
    }

    @Test
    void validateCredentialsSuspendedTest() {
        ManagedUser user = qm.getManagedUser("testuser");
        user.setSuspended(true);
        qm.persist(user);
        Form form = new Form();
        form.param("username", "testuser");
        form.param("password", "testuser");
        Response response = jersey.target(V1_USER + "/login").request()
                .accept(MediaType.TEXT_PLAIN)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assertions.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    void validateCredentialsUnauthorizedTest() {
        Form form = new Form();
        form.param("username", "testuser");
        form.param("password", "wrong");
        Response response = jersey.target(V1_USER + "/login").request()
                .accept(MediaType.TEXT_PLAIN)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assertions.assertEquals(401, response.getStatus(), 0);
    }

    @Test
    void validateOidcAccessTokenOidcNotAvailableTest() {
        final Form form = new Form();
        form.param("accessToken", "accessToken");

        final Response response = jersey.target(V1_USER + "/oidc/login").request()
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));

        // OIDC is disabled by default
        Assertions.assertEquals(204, response.getStatus());
    }

    @Test
    void forceChangePasswordTest() {
        Form form = new Form();
        form.param("username", "testuser");
        form.param("password", "testuser");
        form.param("newPassword", "Password1!");
        form.param("confirmPassword", "Password1!");
        Assertions.assertTrue(PasswordService.matches("testuser".toCharArray(), testUser));
        Response response = jersey.target(V1_USER + "/forceChangePassword").request()
                .accept(MediaType.TEXT_PLAIN)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assertions.assertEquals(200, response.getStatus(), 0);
        qm.getPersistenceManager().refresh(testUser);
        Assertions.assertTrue(PasswordService.matches("Password1!".toCharArray(), testUser));
    }

    @Test
    void forceChangePasswordFlagResetTest() {
        testUser.setForcePasswordChange(true);
        qm.persist(testUser);
        qm.getPersistenceManager().refresh(testUser);
        Assertions.assertTrue(testUser.isForcePasswordChange());
        Form form = new Form();
        form.param("username", "testuser");
        form.param("password", "testuser");
        form.param("newPassword", "Password1!");
        form.param("confirmPassword", "Password1!");
        Assertions.assertTrue(PasswordService.matches("testuser".toCharArray(), testUser));
        Response response = jersey.target(V1_USER + "/forceChangePassword").request()
                .accept(MediaType.TEXT_PLAIN)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assertions.assertEquals(200, response.getStatus(), 0);
        qm.getPersistenceManager().refresh(testUser);
        Assertions.assertTrue(PasswordService.matches("Password1!".toCharArray(), testUser));
        Assertions.assertFalse(testUser.isForcePasswordChange());
    }

    @Test
    void forceChangePasswordMismatchTest() {
        Form form = new Form();
        form.param("username", "testuser");
        form.param("password", "testuser");
        form.param("newPassword", "Password1!");
        form.param("confirmPassword", "blah");
        Response response = jersey.target(V1_USER + "/forceChangePassword").request()
                .accept(MediaType.TEXT_PLAIN)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assertions.assertEquals(406, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The passwords do not match. Password not changed.", body);
    }

    @Test
    void forceChangePasswordUnchangedTest() {
        Form form = new Form();
        form.param("username", "testuser");
        form.param("password", "testuser");
        form.param("newPassword", "testuser");
        form.param("confirmPassword", "testuser");
        Response response = jersey.target(V1_USER + "/forceChangePassword").request()
                .accept(MediaType.TEXT_PLAIN)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assertions.assertEquals(406, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("Existing password is the same as new password. Password not changed.", body);
    }

    @Test
    void forceChangePasswordSuspendedTest() {
        testUser.setSuspended(true);
        qm.persist(testUser);
        Form form = new Form();
        form.param("username", "testuser");
        form.param("password", "testuser");
        form.param("newPassword", "Password1!");
        form.param("confirmPassword", "Password1!");
        Response response = jersey.target(V1_USER + "/forceChangePassword").request()
                .accept(MediaType.TEXT_PLAIN)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assertions.assertEquals(403, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("SUSPENDED", body);
    }

    @Test
    void forceChangePasswordInvalidCredsTest() {
        Form form = new Form();
        form.param("username", "testuser");
        form.param("password", "blah");
        form.param("newPassword", "Password1!");
        form.param("confirmPassword", "Password1!");
        Response response = jersey.target(V1_USER + "/forceChangePassword").request()
                .accept(MediaType.TEXT_PLAIN)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assertions.assertEquals(401, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("INVALID_CREDENTIALS", body);
    }
}
