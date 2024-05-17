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
package org.dependencytrack.resources;

import alpine.server.filters.ApiFilter;
import io.swagger.parser.OpenAPIParser;
import io.swagger.v3.parser.core.models.SwaggerParseResult;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.ws.rs.core.Response;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class OpenApiResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(OpenApiResource.class)
                    .register(ApiFilter.class));

    @Test
    public void testOpenApiJson() {
        final Response response = jersey.target("/openapi.json")
                // NB: Initial generation of the OpenAPI spec can take a while in CI.
                .property(ClientProperties.READ_TIMEOUT, "60000")
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/json");

        final String openApiJson = getPlainTextBody(response);
        final SwaggerParseResult parseResult = new OpenAPIParser().readContents(openApiJson, null, null);

        final List<String> validationMessages = parseResult.getMessages();
        // Version resource is defined in Alpine and outside our control.
        validationMessages.removeIf("attribute paths.'/version'(get).responses.200.description is missing"::equals);
        assertThat(validationMessages).isEmpty();
    }

    @Test
    public void testOpenApiYaml() {
        final Response response = jersey.target("/openapi.yaml")
                // NB: Initial generation of the OpenAPI spec can take a while in CI.
                .property(ClientProperties.READ_TIMEOUT, "60000")
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/yaml");

        final String openApiYaml = getPlainTextBody(response);
        final SwaggerParseResult parseResult = new OpenAPIParser().readContents(openApiYaml, null, null);

        final List<String> validationMessages = parseResult.getMessages();
        // Version resource is defined in Alpine and outside our control.
        validationMessages.removeIf("attribute paths.'/version'(get).responses.200.description is missing"::equals);
        assertThat(validationMessages).isEmpty();
    }

}