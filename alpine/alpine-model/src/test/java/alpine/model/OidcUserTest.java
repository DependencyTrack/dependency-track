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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Collections;

public class OidcUserTest {

    @Test
    public void testJsonSerialization() throws JsonProcessingException {
        final Team team = new Team();
        team.setName("teamName");

        final Permission permission = new Permission();
        permission.setName("permissionName");

        final OidcUser oidcUser = new OidcUser();
        oidcUser.setId(666);
        oidcUser.setUsername("username");
        oidcUser.setSubjectIdentifier("subjectIdentifier");
        oidcUser.setEmail("username@mail.local");
        oidcUser.setTeams(Collections.singletonList(team));
        oidcUser.setPermissions(Collections.singletonList(permission));

        Assertions.assertThat(new ObjectMapper().writeValueAsString(oidcUser)).isEqualTo("" +
                "{" +
                "\"username\":\"username\"," +
                "\"subjectIdentifier\":\"subjectIdentifier\"," +
                "\"email\":\"username@mail.local\"," +
                "\"teams\":[{\"name\":\"teamName\"}]," +
                "\"permissions\":[{\"name\":\"permissionName\"}]" +
                "}");
    }

    @Test
    public void testJsonDeserialization() throws JsonProcessingException {
        final OidcUser oidcUser = new ObjectMapper().readValue("" +
                "{" +
                "\"id\":666," +
                "\"username\":\"username\"," +
                "\"subjectIdentifier\":\"subjectIdentifier\"," +
                "\"email\":\"username@mail.local\"," +
                "\"teams\":[{\"name\":\"teamName\"}]," +
                "\"permissions\":[{\"name\":\"permissionName\"}]" +
                "}", OidcUser.class);

        Assertions.assertThat(oidcUser.getId()).isZero();
        Assertions.assertThat(oidcUser.getUsername()).isEqualTo("username");
        Assertions.assertThat(oidcUser.getSubjectIdentifier()).isEqualTo("subjectIdentifier");
        Assertions.assertThat(oidcUser.getEmail()).isEqualTo("username@mail.local");
        Assertions.assertThat(oidcUser.getTeams()).hasSize(1);
        Assertions.assertThat(oidcUser.getPermissions()).hasSize(1);
    }

}