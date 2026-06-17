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
import jakarta.validation.constraints.Pattern;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.resources.v2.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.resources.v2.OpenApiValidationClientResponseFilter.DISABLE_OPENAPI_VALIDATION;

public class ConstraintViolationExceptionMapperTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig()
                    .register(JsonProcessingExceptionMapperTest.TestResource.class));

    @Test
    public void test() {
        final Response response = jersey.target("/test/not-a-uuid")
                .queryParam("foo", "666")
                .request()
                .property(DISABLE_OPENAPI_VALIDATION, "true")
                .get();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(response.readEntity(String.class))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "type": "about:blank",
                          "status": 400,
                          "title": "Bad Request",
                          "detail": "The request could not be processed because it failed validation.",
                          "errors": [
                            {
                              "message": "must match \\"^[a-z]+$\\"",
                              "path": "get.foo",
                              "value": "666"
                            },
                            {
                              "message": "Invalid UUID",
                              "path": "get.uuid",
                              "value": "not-a-uuid"
                            }
                          ]
                        }
                        """);
    }

    @Path("/test")
    public static class TestResource {

        @GET
        @Path("/{uuid}")
        @Produces(MediaType.APPLICATION_JSON)
        @AuthenticationNotRequired
        public Response get(@PathParam("uuid") @ValidUuid final String uuid,
                            @QueryParam("optionalUuid") @ValidUuid final String optionalUuid,
                            @QueryParam("foo") @Pattern(regexp = "^[a-z]+$") final String foo) {
            return Response.noContent().build();
        }

    }

}