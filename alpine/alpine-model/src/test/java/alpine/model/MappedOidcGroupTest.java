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

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class MappedOidcGroupTest {

    @Test
    public void testJsonSerialization() throws JsonProcessingException {
        final Team team = new Team();
        team.setName("teamName");

        final OidcGroup oidcGroup = new OidcGroup();
        oidcGroup.setName("groupName");

        final MappedOidcGroup mappedOidcGroup = new MappedOidcGroup();
        mappedOidcGroup.setId(666);
        mappedOidcGroup.setTeam(team);
        mappedOidcGroup.setGroup(oidcGroup);
        mappedOidcGroup.setUuid(UUID.fromString("6e394949-9988-4459-85e9-feda224ac321"));

        Assertions.assertThat(new ObjectMapper().writeValueAsString(mappedOidcGroup)).isEqualTo("" +
                "{" +
                "\"group\":{\"name\":\"groupName\"}," +
                "\"uuid\":\"6e394949-9988-4459-85e9-feda224ac321\"" +
                "}");
    }

    @Test
    public void testJsonDeserialization() throws JsonProcessingException {
        final MappedOidcGroup mappedOidcGroup = new ObjectMapper().readValue("" +
                "{" +
                "\"id\":666," +
                "\"group\":{\"name\":\"groupName\"}," +
                "\"team\":{\"name\":\"teamName\"}," +
                "\"uuid\":\"6e394949-9988-4459-85e9-feda224ac321\"" +
                "}", MappedOidcGroup.class);

        Assertions.assertThat(mappedOidcGroup.getId()).isZero();
        Assertions.assertThat(mappedOidcGroup.getGroup()).isNotNull();
        assertThat(mappedOidcGroup.getTeam()).isNull();
        Assertions.assertThat(mappedOidcGroup.getUuid()).isEqualTo(UUID.fromString("6e394949-9988-4459-85e9-feda224ac321"));
    }

}