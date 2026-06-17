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
package alpine.server.resources;

import alpine.model.About;
import alpine.server.auth.AuthenticationNotRequired;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.GenericEntity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * Bundled JAX-RS resource that displays the name of the application, version, and build timestamp.
 *
 * @see About
 * @author Steve Springett
 * @since 1.0.0
 */
@Path("/version")
@Tag(name = "version")
public final class VersionResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns application version information",
            description = "Returns a simple json object containing the name of the application and the version"
    )
    @ApiResponse(
            responseCode = "200",
            description = "Application version information",
            content = @Content(schema = @Schema(implementation = About.class))
    )
    @AuthenticationNotRequired
    public Response getVersion() {
        return Response.ok(new GenericEntity<>(new About()) { }).build();
    }

}
