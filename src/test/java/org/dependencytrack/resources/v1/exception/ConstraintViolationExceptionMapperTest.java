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

import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.validation.ValidUuid;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.ClassRule;
import org.junit.Test;

import javax.validation.constraints.Pattern;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class ConstraintViolationExceptionMapperTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(TestResource.class)
                    .register(ConstraintViolationExceptionMapper.class));

    @Test
    public void test() {
        final Response response = jersey.target("/not-a-uuid")
                .queryParam("foo", "666")
                .request()
                .get();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        [
                          {
                            "message": "Invalid UUID",
                            "messageTemplate": "Invalid UUID",
                            "path": "get.arg0",
                            "invalidValue": "not-a-uuid"
                          },
                          {
                            "message": "must match \\"^[a-z]+$\\"",
                            "messageTemplate": "{javax.validation.constraints.Pattern.message}",
                            "path": "get.arg2",
                            "invalidValue": "666"
                          }
                        ]
                        """);
    }

    @Path("/")
    public static class TestResource {

        @GET
        @Path("/{uuid}")
        @Produces(MediaType.APPLICATION_JSON)
        public Response get(@PathParam("uuid") @ValidUuid final String uuid,
                            @QueryParam("optionalUuid") @ValidUuid final String optionalUuid,
                            @QueryParam("foo") @Pattern(regexp = "^[a-z]+$") final String foo) {
            return Response.noContent().build();
        }

    }

}