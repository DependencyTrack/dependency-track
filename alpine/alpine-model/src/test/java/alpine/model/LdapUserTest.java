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

public class LdapUserTest {

    @Test
    public void idTest() {
        LdapUser user = new LdapUser();
        user.setId(123L);
        Assertions.assertEquals(123L, user.getId());
    }

    @Test
    @SuppressWarnings("deprecation")
    public void usernameTest() {
        LdapUser user = new LdapUser();
        user.setUsername("myUsername");
        Assertions.assertEquals("myUsername", user.getUsername());
        Assertions.assertEquals("myUsername", user.getName());
    }

    @Test
    public void dnTest() {
        LdapUser user = new LdapUser();
        user.setDN("ou=users,o=example.com");
        Assertions.assertEquals("ou=users,o=example.com", user.getDN());
    }

    @Test
    public void teamsTest() {
        List<Team> teams = new ArrayList<>();
        teams.add(new Team());
        LdapUser user = new LdapUser();
        user.setTeams(teams);
        Assertions.assertEquals(teams, user.getTeams());
        Assertions.assertEquals(1, user.getTeams().size());
    }

    @Test
    public void emailTest() {
        LdapUser user = new LdapUser();
        user.setEmail("me@example.com");
        Assertions.assertEquals("me@example.com", user.getEmail());
    }

    @Test
    public void permissionsTest() {
        List<Permission> permissions = new ArrayList<>();
        permissions.add(new Permission());
        LdapUser user = new LdapUser();
        user.setPermissions(permissions);
        Assertions.assertEquals(permissions, user.getPermissions());
        Assertions.assertEquals(1, user.getPermissions().size());
    }
}
