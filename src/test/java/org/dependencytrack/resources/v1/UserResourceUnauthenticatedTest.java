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
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

public class UserResourceUnauthenticatedTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(UserResource.class)
                    .register(ApiFilter.class));

    private ManagedUser testUser;

    @Before
    public void before() throws Exception {
        super.before();
        testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        qm.addUserToTeam(testUser, team);
    }

    @Test
    public void validateCredentialsTest() {
        Form form = new Form();
        form.param("username", "testuser");
        form.param("password", "testuser");
        Response response = jersey.target(V1_USER + "/login").request()
                .accept(MediaType.TEXT_PLAIN)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assert.assertEquals(200, response.getStatus(), 0);
        String token = getPlainTextBody(response);
        Assert.assertNotNull(token);
        //Assert.assertEquals(token, response.getCookies().get("Authorization-Token").getValue());
    }

    @Test
    public void validateCredentialsSuspendedTest() {
        ManagedUser user = qm.getManagedUser("testuser");
        user.setSuspended(true);
        qm.persist(user);
        Form form = new Form();
        form.param("username", "testuser");
        form.param("password", "testuser");
        Response response = jersey.target(V1_USER + "/login").request()
                .accept(MediaType.TEXT_PLAIN)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assert.assertEquals(403, response.getStatus(), 0);
    }

    @Test
    public void validateCredentialsUnauthorizedTest() {
        Form form = new Form();
        form.param("username", "testuser");
        form.param("password", "wrong");
        Response response = jersey.target(V1_USER + "/login").request()
                .accept(MediaType.TEXT_PLAIN)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assert.assertEquals(401, response.getStatus(), 0);
    }

    @Test
    public void validateOidcAccessTokenOidcNotAvailableTest() {
        final Form form = new Form();
        form.param("accessToken", "accessToken");

        final Response response = jersey.target(V1_USER + "/oidc/login").request()
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));

        // OIDC is disabled by default
        Assert.assertEquals(204, response.getStatus());
    }

    @Test
    public void forceChangePasswordTest() {
        Form form = new Form();
        form.param("username", "testuser");
        form.param("password", "testuser");
        form.param("newPassword", "Password1!");
        form.param("confirmPassword", "Password1!");
        Assert.assertTrue(PasswordService.matches("testuser".toCharArray(), testUser));
        Response response = jersey.target(V1_USER + "/forceChangePassword").request()
                .accept(MediaType.TEXT_PLAIN)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assert.assertEquals(200, response.getStatus(), 0);
        qm.getPersistenceManager().refresh(testUser);
        Assert.assertTrue(PasswordService.matches("Password1!".toCharArray(), testUser));
    }

    @Test
    public void forceChangePasswordFlagResetTest() {
        testUser.setForcePasswordChange(true);
        qm.persist(testUser);
        qm.getPersistenceManager().refresh(testUser);
        Assert.assertTrue(testUser.isForcePasswordChange());
        Form form = new Form();
        form.param("username", "testuser");
        form.param("password", "testuser");
        form.param("newPassword", "Password1!");
        form.param("confirmPassword", "Password1!");
        Assert.assertTrue(PasswordService.matches("testuser".toCharArray(), testUser));
        Response response = jersey.target(V1_USER + "/forceChangePassword").request()
                .accept(MediaType.TEXT_PLAIN)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assert.assertEquals(200, response.getStatus(), 0);
        qm.getPersistenceManager().refresh(testUser);
        Assert.assertTrue(PasswordService.matches("Password1!".toCharArray(), testUser));
        Assert.assertFalse(testUser.isForcePasswordChange());
    }

    @Test
    public void forceChangePasswordMismatchTest() {
        Form form = new Form();
        form.param("username", "testuser");
        form.param("password", "testuser");
        form.param("newPassword", "Password1!");
        form.param("confirmPassword", "blah");
        Response response = jersey.target(V1_USER + "/forceChangePassword").request()
                .accept(MediaType.TEXT_PLAIN)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assert.assertEquals(406, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The passwords do not match. Password not changed.", body);
    }

    @Test
    public void forceChangePasswordUnchangedTest() {
        Form form = new Form();
        form.param("username", "testuser");
        form.param("password", "testuser");
        form.param("newPassword", "testuser");
        form.param("confirmPassword", "testuser");
        Response response = jersey.target(V1_USER + "/forceChangePassword").request()
                .accept(MediaType.TEXT_PLAIN)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assert.assertEquals(406, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("Existing password is the same as new password. Password not changed.", body);
    }

    @Test
    public void forceChangePasswordSuspendedTest() {
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
        Assert.assertEquals(403, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("SUSPENDED", body);
    }

    @Test
    public void forceChangePasswordInvalidCredsTest() {
        Form form = new Form();
        form.param("username", "testuser");
        form.param("password", "blah");
        form.param("newPassword", "Password1!");
        form.param("confirmPassword", "Password1!");
        Response response = jersey.target(V1_USER + "/forceChangePassword").request()
                .accept(MediaType.TEXT_PLAIN)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        Assert.assertEquals(401, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("INVALID_CREDENTIALS", body);
    }
}
