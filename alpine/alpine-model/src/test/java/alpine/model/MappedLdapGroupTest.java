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

import java.util.UUID;

public class MappedLdapGroupTest {

    @Test
    public void idTest() {
        MappedLdapGroup mapping = new MappedLdapGroup();
        mapping.setId(123L);
        Assertions.assertEquals(123L, mapping.getId());
    }

    @Test
    public void teamTest() {
        Team team = new Team();
        MappedLdapGroup mapping = new MappedLdapGroup();
        mapping.setTeam(team);
        Assertions.assertEquals(team, mapping.getTeam());
    }

    @Test
    public void dnTest() {
        MappedLdapGroup mapping = new MappedLdapGroup();
        mapping.setDn("cn=TeamA,ou=groups,o=example.com");
        Assertions.assertEquals("cn=TeamA,ou=groups,o=example.com", mapping.getDn());
    }

    @Test
    public void uuidTest() {
        UUID uuid = UUID.randomUUID();
        MappedLdapGroup mapping = new MappedLdapGroup();
        mapping.setUuid(uuid);
        Assertions.assertEquals(uuid, mapping.getUuid());
    }
}
