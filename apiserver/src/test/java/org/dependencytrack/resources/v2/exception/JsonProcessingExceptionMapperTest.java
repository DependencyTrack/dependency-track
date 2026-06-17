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
package org.dependencytrack.resources.v2.exception;

import alpine.server.auth.AuthenticationNotRequired;
import com.fasterxml.jackson.core.JsonGenerationException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.resources.v2.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.resources.v2.OpenApiValidationClientResponseFilter.DISABLE_OPENAPI_VALIDATION;

public class JsonProcessingExceptionMapperTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig()
                    .register(TestResource.class));

    @Test
    public void shouldReturnInternalServerErrorForServerSideJsonException() {
        final Response response = jersey.target("/test/json-generation")
                .request()
                .property(DISABLE_OPENAPI_VALIDATION, "true")
                .get();
        assertThat(response.getStatus()).isEqualTo(500);
        assertThatJson(response.readEntity(String.class)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 500,
                  "title": "Unexpected error",
                  "detail": "An error occurred that was not anticipated."
                }
                """);
    }

    @Test
    public void shouldReturnBadRequestForClientSideJsonException() {
        final Response response = jersey.target("/test")
                .request()
                .property(DISABLE_OPENAPI_VALIDATION, "true")
                .post(Entity.json("[]"));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(response.readEntity(String.class)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 400,
                  "title": "JSON Processing Failed",
                  "detail": "The provided JSON could not be processed."
                }
                """);
    }

    @Path("/test")
    public static class TestResource {

        public record TestRequest(String name) {
        }

        @POST
        @Path("/")
        @Consumes(MediaType.APPLICATION_JSON)
        @AuthenticationNotRequired
        public Response test(final TestRequest request) {
            return Response.ok(request.name()).build();
        }

        @GET
        @Path("/json-generation")
        @AuthenticationNotRequired
        @SuppressWarnings("deprecation")
        public Response jsonGeneration() throws Exception {
            throw new JsonGenerationException("boom");
        }

    }

}