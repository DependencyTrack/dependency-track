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
import alpine.server.filters.AuthenticationFeature;
import alpine.server.filters.AuthorizationFeature;
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

import java.util.Comparator;
import java.util.HashSet;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class CweResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(CweResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class)
                    .register(AuthorizationFeature.class));

    @Test
    public void getCwesTest() {
        Response response = jersey.target(V1_CWE).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertEquals(
                String.valueOf(CweDictionary.DICTIONARY.size()),
                response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(100, json.size());
        Assertions.assertEquals(1, json.getJsonObject(0).getInt("cweId"));
        Assertions.assertEquals("DEPRECATED: Location", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getCwesPaginationTest() {
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
            assertThat(response.getHeaderString(TOTAL_COUNT_HEADER))
                    .isEqualTo(String.valueOf(CweDictionary.DICTIONARY.size()));

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
    public void shouldFilterByNameSubstringCaseInsensitive() {
        final Response response = jersey.target(V1_CWE)
                .queryParam("searchText", "doubled character")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "cweId": 85,
                    "name": "Doubled Character XSS Manipulations"
                  }
                ]
                """);
    }

    @Test
    public void shouldFilterByCweIdStringRegardlessOfCase() {
        final String upperBody = getPlainTextBody(jersey.target(V1_CWE)
                .queryParam("searchText", "CWE-79")
                .request()
                .header(X_API_KEY, apiKey)
                .get());
        final String lowerBody = getPlainTextBody(jersey.target(V1_CWE)
                .queryParam("searchText", "cwe-79")
                .request()
                .header(X_API_KEY, apiKey)
                .get());

        assertThatJson(upperBody).isEqualTo(lowerBody);
        assertThatJson(upperBody)
                .isArray()
                .isNotEmpty();
        assertThatJson(upperBody)
                .inPath("$[?(@.cweId == 79)].name")
                .isArray()
                .containsExactly("Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')");
    }

    @Test
    public void shouldReturnEmptyListWhenSearchTextHasNoMatches() {
        final Response response = jersey.target(V1_CWE)
                .queryParam("searchText", "no-such-cwe-xyzzy")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThatJson(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    public void shouldApplyPaginationAfterFilter() {
        final Response response = jersey.target(V1_CWE)
                .queryParam("searchText", "injection")
                .queryParam("pageSize", "5")
                .queryParam("pageNumber", "1")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        final int totalCount = Integer.parseInt(response.getHeaderString(TOTAL_COUNT_HEADER));
        assertThat(totalCount).isLessThan(CweDictionary.DICTIONARY.size());

        final String body = getPlainTextBody(response);
        assertThatJson(body).isArray().hasSizeLessThanOrEqualTo(5);
        assertThatJson(body).inPath("$[*].name")
                .isArray()
                .allSatisfy(name -> assertThat(((String) name).toLowerCase()).contains("injection"));
    }

    @Test
    public void shouldSortByCweIdAscending() {
        final Response response = jersey
                .target(V1_CWE)
                .queryParam("sortName", "cweId")
                .queryParam("sortOrder", "asc")
                .queryParam("pageSize", "3")
                .queryParam("pageNumber", "1")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$[*].cweId")
                .isArray()
                .containsExactly(1, 2, 3);
    }

    @Test
    public void shouldSortByCweIdDescending() {
        final Response response = jersey
                .target(V1_CWE)
                .queryParam("sortName", "cweId")
                .queryParam("sortOrder", "desc")
                .queryParam("pageSize", "3")
                .queryParam("pageNumber", "1")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$[*].cweId")
                .isArray()
                .isSortedAccordingTo(Comparator.comparingInt((Object cweId) -> ((Number) cweId).intValue()).reversed());
    }

    @Test
    public void shouldDefaultToAscendingWhenSortOrderOmitted() {
        final Response response = jersey
                .target(V1_CWE)
                .queryParam("sortName", "cweId")
                .queryParam("pageSize", "3")
                .queryParam("pageNumber", "1")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$[*].cweId")
                .isArray()
                .containsExactly(1, 2, 3);
    }

    @Test
    public void shouldIgnoreUnsupportedSortField() {
        final String sortedBody = getPlainTextBody(
                jersey.target(V1_CWE)
                        .queryParam("sortName", "name")
                        .queryParam("sortOrder", "asc")
                        .queryParam("pageSize", "5")
                        .queryParam("pageNumber", "1")
                        .request()
                        .header(X_API_KEY, apiKey)
                        .get());
        final String defaultBody = getPlainTextBody(
                jersey.target(V1_CWE)
                        .queryParam("pageSize", "5")
                        .queryParam("pageNumber", "1")
                        .request()
                        .header(X_API_KEY, apiKey)
                        .get());
        assertThatJson(sortedBody).isEqualTo(defaultBody);
    }

    @Test
    public void shouldCombineFilterSortAndPagination() {
        final Response response = jersey
                .target(V1_CWE)
                .queryParam("searchText", "injection")
                .queryParam("sortName", "cweId")
                .queryParam("sortOrder", "asc")
                .queryParam("pageSize", "5")
                .queryParam("pageNumber", "1")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        final int totalCount = Integer.parseInt(response.getHeaderString(TOTAL_COUNT_HEADER));
        assertThat(totalCount).isLessThan(CweDictionary.DICTIONARY.size());

        final String body = getPlainTextBody(response);
        assertThatJson(body).isArray().hasSizeLessThanOrEqualTo(5);
        assertThatJson(body).inPath("$[*].name")
                .isArray()
                .allSatisfy(name -> assertThat(((String) name).toLowerCase()).contains("injection"));
        assertThatJson(body).inPath("$[*].cweId")
                .isArray()
                .isSortedAccordingTo(Comparator.comparingInt((Object cweId) -> ((Number) cweId).intValue()));
    }

    @Test
    public void getCweTest() {
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
