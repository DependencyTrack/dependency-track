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
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.resources.v2.ResourceConfig;
import org.dependencytrack.support.jdbi.exception.QueryTimeoutException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.postgresql.util.PSQLException;
import org.postgresql.util.PSQLState;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;

import static java.util.Objects.requireNonNull;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.resources.v2.OpenApiValidationClientResponseFilter.DISABLE_OPENAPI_VALIDATION;

public class QueryTimeoutExceptionMapperTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(new ResourceConfig().register(TestResource.class));

    @Test
    public void shouldMapToTimeoutProblem() {
        final Response response = jersey.target("/test/query-timeout")
                .request()
                .property(DISABLE_OPENAPI_VALIDATION, "true")
                .get();
        assertThat(response.getStatus()).isEqualTo(504);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(response.readEntity(String.class)).isEqualTo(/* language=JSON */ """
                {
                  "type": "/problems/timeout",
                  "status": 504,
                  "title": "Request timed out",
                  "detail": "The request was aborted because it took too long to complete."
                }
                """);
    }

    @Path("/test")
    public static class TestResource {

        @GET
        @Path("/query-timeout")
        @AuthenticationNotRequired
        public Response get() {
            throw requireNonNull(QueryTimeoutException.of(
                    new PSQLException("canceling statement due to statement timeout", PSQLState.QUERY_CANCELED)));
        }
    }
}
