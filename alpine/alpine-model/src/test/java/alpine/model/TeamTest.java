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
import java.util.UUID;

public class TeamTest {

    @Test
    public void idTest() {
        Team team = new Team();
        team.setId(123L);
        Assertions.assertEquals(123L, team.getId());
    }

    @Test
    public void nameTest() {
        Team team = new Team();
        team.setName("Team A");
        Assertions.assertEquals("Team A", team.getName());
    }

    @Test
    public void uuidTest() {
        UUID uuid = UUID.randomUUID();
        Team team = new Team();
        team.setUuid(uuid);
        Assertions.assertEquals(uuid, team.getUuid());
    }

    @Test
    public void teamsTest() {
        List<ApiKey> keys = new ArrayList<>();
        keys.add(new ApiKey());
        Team team = new Team();
        team.setApiKeys(keys);
        Assertions.assertEquals(keys, team.getApiKeys());
        Assertions.assertEquals(1, team.getApiKeys().size());
    }

    @Test
    public void ldapUsersTest() {
        List<LdapUser> users = new ArrayList<>();
        users.add(new LdapUser());
        Team team = new Team();
        team.setLdapUsers(users);
        Assertions.assertEquals(users, team.getLdapUsers());
        Assertions.assertEquals(1, team.getLdapUsers().size());
    }

    @Test
    public void managedUsersTest() {
        List<ManagedUser> users = new ArrayList<>();
        users.add(new ManagedUser());
        Team team = new Team();
        team.setManagedUsers(users);
        Assertions.assertEquals(users, team.getManagedUsers());
        Assertions.assertEquals(1, team.getManagedUsers().size());
    }

    @Test
    public void mappedLdapGroupsTest() {
        List<MappedLdapGroup> mappings = new ArrayList<>();
        mappings.add(new MappedLdapGroup());
        Team team = new Team();
        team.setMappedLdapGroups(mappings);
        Assertions.assertEquals(mappings, team.getMappedLdapGroups());
        Assertions.assertEquals(1, team.getMappedLdapGroups().size());
    }

    @Test
    public void permissionsTest() {
        List<Permission> permissions = new ArrayList<>();
        permissions.add(new Permission());
        Team team = new Team();
        team.setPermissions(permissions);
        Assertions.assertEquals(permissions, team.getPermissions());
        Assertions.assertEquals(1, team.getPermissions().size());
    }
}
