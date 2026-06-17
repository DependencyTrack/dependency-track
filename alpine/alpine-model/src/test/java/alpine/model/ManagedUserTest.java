/*
 * This file is part of Alpine.
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
package alpine.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class ManagedUserTest {

    @Test
    public void idTest() {
        ManagedUser user = new ManagedUser();
        user.setId(123L);
        Assertions.assertEquals(123L, user.getId());
    }

    @Test
    @SuppressWarnings("deprecation")
    public void usernameTest() {
        ManagedUser user = new ManagedUser();
        user.setUsername("myUsername");
        Assertions.assertEquals("myUsername", user.getUsername());
        Assertions.assertEquals("myUsername", user.getName());
    }

    @Test
    public void passwordTest() {
        ManagedUser user = new ManagedUser();
        user.setPassword("Password123!");
        user.setNewPassword("Password1234!");
        user.setConfirmPassword("Password1234!");
        Assertions.assertEquals("Password123!", user.getPassword());
        Assertions.assertEquals("Password1234!", user.getNewPassword());
        Assertions.assertEquals("Password1234!", user.getConfirmPassword());
    }

    @Test
    public void lastPasswordChangeTest() {
        Date date = new Date();
        ManagedUser user = new ManagedUser();
        user.setLastPasswordChange(date);
        Assertions.assertEquals(date, user.getLastPasswordChange());
    }

    @Test
    public void fullnameTest() {
        ManagedUser user = new ManagedUser();
        user.setFullname("My Full Name");
        Assertions.assertEquals("My Full Name", user.getFullname());
    }

    @Test
    public void emailTest() {
        ManagedUser user = new ManagedUser();
        user.setEmail("me@example.com");
        Assertions.assertEquals("me@example.com", user.getEmail());
    }

    @Test
    public void suspendedTest() {
        ManagedUser user = new ManagedUser();
        Assertions.assertFalse(user.isSuspended());
        user.setSuspended(true);
        Assertions.assertTrue(user.isSuspended());
    }

    @Test
    public void forcePasswordChangeTest() {
        ManagedUser user = new ManagedUser();
        Assertions.assertFalse(user.isForcePasswordChange());
        user.setForcePasswordChange(true);
        Assertions.assertTrue(user.isForcePasswordChange());
    }

    @Test
    public void nonExpiryPasswordTest() {
        ManagedUser user = new ManagedUser();
        Assertions.assertFalse(user.isNonExpiryPassword());
        user.setNonExpiryPassword(true);
        Assertions.assertTrue(user.isNonExpiryPassword());
    }

    @Test
    public void teamsTest() {
        List<Team> teams = new ArrayList<>();
        teams.add(new Team());
        ManagedUser user = new ManagedUser();
        user.setTeams(teams);
        Assertions.assertEquals(teams, user.getTeams());
        Assertions.assertEquals(1, user.getTeams().size());
    }

    @Test
    public void permissionsTest() {
        List<Permission> permissions = new ArrayList<>();
        permissions.add(new Permission());
        ManagedUser user = new ManagedUser();
        user.setPermissions(permissions);
        Assertions.assertEquals(permissions, user.getPermissions());
        Assertions.assertEquals(1, user.getPermissions().size());
    }
}
