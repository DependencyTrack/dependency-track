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
package org.dependencytrack.filters;

import alpine.server.auth.AuthenticationNotRequired;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static org.assertj.core.api.Assertions.assertThat;

public class DeprecationResponseFilterTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig()
                    .register(DeprecationResponseFilter.class)
                    .register(NotDeprecatedResource.class)
                    .register(DeprecatedClassResource.class));

    @Test
    void shouldNotSetHeaderWhenMethodIsNotDeprecated() {
        final Response response = jersey.target("/test/active").request().get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString("X-API-Deprecated")).isNull();
    }

    @Test
    void shouldSetHeaderWhenMethodIsDeprecated() {
        final Response response = jersey.target("/test/legacy").request().get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString("X-API-Deprecated")).isEqualTo("true");
    }

    @Test
    void shouldSetHeaderWhenDeclaringClassIsDeprecated() {
        final Response response = jersey.target("/old/anything").request().get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString("X-API-Deprecated")).isEqualTo("true");
    }

    @Test
    void shouldSetHeaderOnErrorResponseWhenMethodIsDeprecated() {
        final Response response = jersey.target("/test/legacy-broken").request().get();

        assertThat(response.getStatus()).isEqualTo(418);
        assertThat(response.getHeaderString("X-API-Deprecated")).isEqualTo("true");
    }

    @Path("/test")
    public static class NotDeprecatedResource {

        @GET
        @Path("/active")
        @AuthenticationNotRequired
        public Response active() {
            return Response.ok().build();
        }

        @GET
        @Path("/legacy")
        @Deprecated
        @AuthenticationNotRequired
        public Response legacy() {
            return Response.ok().build();
        }

        @GET
        @Path("/legacy-broken")
        @Deprecated
        @AuthenticationNotRequired
        public Response legacyBroken() {
            throw new WebApplicationException(Response.status(418).build());
        }

    }

    @Deprecated
    @Path("/old")
    public static class DeprecatedClassResource {

        @GET
        @Path("/anything")
        @AuthenticationNotRequired
        public Response anything() {
            return Response.ok().build();
        }

    }

}
