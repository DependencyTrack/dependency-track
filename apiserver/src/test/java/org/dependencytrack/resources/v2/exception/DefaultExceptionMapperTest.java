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
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.ServerErrorException;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.resources.v2.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.resources.v2.OpenApiValidationClientResponseFilter.DISABLE_OPENAPI_VALIDATION;

public class DefaultExceptionMapperTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig()
                    .register(JsonProcessingExceptionMapperTest.TestResource.class));

    @Test
    public void shouldReturnInternalServerError() {
        final Response response = jersey.target("/test/error")
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
    public void shouldReturnGivenStatusForServerErrors() {
        final Response response = jersey.target("/test/server-error")
                .request()
                .property(DISABLE_OPENAPI_VALIDATION, "true")
                .get();
        assertThat(response.getStatus()).isEqualTo(503);
        assertThatJson(response.readEntity(String.class)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 503,
                  "title": "Unexpected error",
                  "detail": "An error occurred that was not anticipated."
                }
                """);
    }

    @Path("/test")
    public static class TestResource {

        @GET
        @Path("/error")
        @AuthenticationNotRequired
        public Response fail() throws Exception {
            throw new ClassNotFoundException("test");
        }

        @GET
        @Path("/server-error")
        @AuthenticationNotRequired
        public Response serverError() {
            throw new ServerErrorException(Response.status(Response.Status.SERVICE_UNAVAILABLE).build());
        }

    }

}