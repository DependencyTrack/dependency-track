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

import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;

import static org.assertj.core.api.Assertions.assertThat;

public class ClientErrorExceptionMapperTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(TestResource.class)
                    .register(ClientErrorExceptionMapper.class));

    @Test
    public void testNotFound() {
        final Response response = jersey.target("/does/not/exist")
                .request()
                .get();

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void testMethodNotAllowed() {
        final Response response = jersey.target("/test/foo")
                .request()
                .delete();

        assertThat(response.getStatus()).isEqualTo(405);
    }

    @Path("/test")
    public static class TestResource {

        @GET
        @Path("/foo")
        public String foo() {
            return "foo";
        }

    }

}