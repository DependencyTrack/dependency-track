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
import java.util.List;

public class PermissionTest {

    @Test
    public void idTest() {
        Permission permission = new Permission();
        permission.setId(123L);
        Assertions.assertEquals(123L, permission.getId());
    }

    @Test
    public void nameTest() {
        Permission permission = new Permission();
        permission.setName("Permission-A");
        Assertions.assertEquals("Permission-A", permission.getName());
    }

    @Test
    public void descriptionTest() {
        Permission permission = new Permission();
        permission.setDescription("Permission A");
        Assertions.assertEquals("Permission A", permission.getDescription());
    }

    @Test
    public void teamsTest() {
        List<Team> teams = new ArrayList<>();
        teams.add(new Team());
        Permission permission = new Permission();
        permission.setTeams(teams);
        Assertions.assertEquals(teams, permission.getTeams());
        Assertions.assertEquals(1, permission.getTeams().size());
    }

    @Test
    public void ldapUsersTest() {
        List<LdapUser> users = new ArrayList<>();
        users.add(new LdapUser());
        Permission permission = new Permission();
        permission.setLdapUsers(users);
        Assertions.assertEquals(users, permission.getLdapUsers());
        Assertions.assertEquals(1, permission.getLdapUsers().size());
    }

    @Test
    public void managedUserTest() {
        List<ManagedUser> users = new ArrayList<>();
        users.add(new ManagedUser());
        Permission permission = new Permission();
        permission.setManagedUsers(users);
        Assertions.assertEquals(users, permission.getManagedUsers());
        Assertions.assertEquals(1, permission.getManagedUsers().size());
    }
}
