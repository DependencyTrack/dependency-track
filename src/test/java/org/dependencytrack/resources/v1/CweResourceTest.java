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

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.parser.common.resolver.CweDictionary;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;

class CweResourceTest extends ResourceTest {

    @RegisterExtension
    public static JerseyTestExtension jersey = new JerseyTestExtension(
            () -> new ResourceConfig(CweResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @Test
    void getCwesTest() {
        Response response = jersey.target(V1_CWE).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(String.valueOf(1429), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(100, json.size());
        Assertions.assertEquals(1, json.getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals("DEPRECATED: Location", json.getJsonObject(0).getString("name"));
    }

    @Test
    void getCwesPaginationTest() {
        int pageNumber = 1;
        final var cwesSeen = new HashSet<Integer>();
        while (cwesSeen.size() < CweDictionary.DICTIONARY.size()) {
            final Response response = jersey.target(V1_CWE)
                    .queryParam("pageSize", "100")
                    .queryParam("pageNumber", String.valueOf(pageNumber++))
                    .request()
                    .header(X_API_KEY, apiKey)
                    .get();
            assertThat(response.getStatus()).isEqualTo(200);
            assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1429");

            final JsonArray cwesPage = parseJsonArray(response);
            assertThat(cwesPage).hasSizeLessThanOrEqualTo(100);

            for (final JsonObject value : cwesPage.getValuesAs(JsonObject.class)) {
                final int cweId = value.getInt("cweId");
                assertThat(cwesSeen).doesNotContain(cweId);
                cwesSeen.add(cweId);
            }
        }
    }

    @Test
    void getCweTest() {
        Response response = jersey.target(V1_CWE + "/79").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(79, json.getInt("cweId"));
        Assertions.assertEquals("Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", json.getString("name"));
    }

}
