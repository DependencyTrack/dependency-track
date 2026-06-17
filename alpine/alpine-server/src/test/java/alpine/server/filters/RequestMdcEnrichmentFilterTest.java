/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.server.filters;

import alpine.server.resources.AlpineResource;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.TestProperties;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Application;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Map;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class RequestMdcEnrichmentFilterTest extends JerseyTest {

    @Path("/")
    public static class TestResource extends AlpineResource {

        @GET
        @Produces(MediaType.APPLICATION_JSON)
        public Response get() {
            return Response.ok(getRequestMetadata()).build();
        }

        @POST
        @Path("/foo/{bar}/baz")
        @Produces(MediaType.APPLICATION_JSON)
        public Response post(@PathParam("bar") final String ignored) {
            return Response.ok(getRequestMetadata()).build();
        }

        private Map<String, Object> getRequestMetadata() {
            return Map.ofEntries(
                    Map.entry("requestMethod", MDC.get("requestMethod")),
                    Map.entry("requestUri", MDC.get("requestUri")));
        }

    }

    @Override
    protected Application configure() {
        forceSet(TestProperties.CONTAINER_PORT, "0");
        return new ResourceConfig(TestResource.class)
                .register(RequestMdcEnrichmentFilter.class);
    }

    @Test
    void shouldIncludeRequestMethodAndRootUri() {
        final Response response = target("/")
                .request()
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(response.readEntity(String.class)).isEqualTo(/* language=JSON */ """
                {
                  "requestMethod": "GET",
                  "requestUri": "/"
                }
                """);
    }

    @Test
    void shouldIncludeRequestMethodAndUriWithPathParamPlaceholders() {
        final Response response = target("/foo/qux/baz")
                .request()
                .post(Entity.text(""));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(response.readEntity(String.class)).isEqualTo(/* language=JSON */ """
                {
                  "requestMethod": "POST",
                  "requestUri": "/foo/{bar}/baz"
                }
                """);
    }

}