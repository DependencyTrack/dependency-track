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
package org.dependencytrack.resources.v1.exception;

import alpine.persistence.PaginatedResult;
import alpine.server.auth.AuthenticationNotRequired;
import alpine.server.filters.ApiFilter;
import alpine.server.resources.AlpineResource;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.persistence.QueryManager;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class NotSortableExceptionMapperTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(TestResource.class)
                    .register(ApiFilter.class)
                    .register(NotSortableExceptionMapper.class));

    @Test
    public void testFieldDoesNotExist() {
        final Response response = jersey.target("/")
                .queryParam("sortName", "foo")
                .queryParam("sortOrder", "asc")
                .request()
                .get();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response))
                .isEqualTo("""
                        {
                          "status": 400,
                          "title": "Field not sortable",
                          "detail": "Can not sort by Project#foo: The field does not exist"
                        }
                        """);
    }

    @Test
    public void testTransientField() {
        final Response response = jersey.target("/")
                .queryParam("sortName", "bomRef")
                .queryParam("sortOrder", "asc")
                .request()
                .get();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response))
                .isEqualTo("""
                        {
                          "status": 400,
                          "title": "Field not sortable",
                          "detail": "Can not sort by Project#bomRef: The field is computed and can not be queried or sorted by"
                        }
                        """);
    }

    @Test
    public void testPersistentField() {
        final Response response = jersey.target("/")
                .queryParam("sortName", "name")
                .queryParam("sortOrder", "asc")
                .request()
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/json");
        assertThatJson(getPlainTextBody(response))
                .isEqualTo("[]");
    }

    @Path("/")
    public static class TestResource extends AlpineResource {

        @GET
        @Produces(MediaType.APPLICATION_JSON)
        @AuthenticationNotRequired
        public Response get() {
            try (final var qm = new QueryManager(getAlpineRequest())) {
                final PaginatedResult projects = qm.getProjects();
                return Response
                        .status(Response.Status.OK)
                        .header("X-Total-Count", projects.getTotal())
                        .entity(projects.getObjects())
                        .build();
            }
        }

    }

}