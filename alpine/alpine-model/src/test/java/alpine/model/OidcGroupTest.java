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

public class OidcGroupTest {

    @Test
    public void testJsonSerialization() throws JsonProcessingException {
        final OidcGroup oidcGroup = new OidcGroup();
        oidcGroup.setId(666);
        oidcGroup.setUuid(UUID.fromString("658c7f29-7286-47c4-8d37-527d4a6c0317"));
        oidcGroup.setName("groupName");

        Assertions.assertThat(new ObjectMapper().writeValueAsString(oidcGroup)).isEqualTo("" +
                "{" +
                "\"uuid\":\"658c7f29-7286-47c4-8d37-527d4a6c0317\"," +
                "\"name\":\"groupName\"" +
                "}");
    }

    @Test
    public void testJsonDeserialization() throws JsonProcessingException {
        final OidcGroup oidcGroup = new ObjectMapper().readValue("" +
                "{" +
                "\"id\":666," +
                "\"uuid\":\"658c7f29-7286-47c4-8d37-527d4a6c0317\"," +
                "\"name\":\"groupName\"" +
                "}", OidcGroup.class);

        Assertions.assertThat(oidcGroup.getId()).isZero();
        Assertions.assertThat(oidcGroup.getUuid()).isEqualTo(UUID.fromString("658c7f29-7286-47c4-8d37-527d4a6c0317"));
        Assertions.assertThat(oidcGroup.getName()).isEqualTo("groupName");
    }

}