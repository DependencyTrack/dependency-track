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
package org.dependencytrack.resources.v1;

import alpine.persistence.PaginatedResult;
import alpine.server.resources.AlpineResource;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * JAX-RS resources for processing CWEs.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/cwe")
@Tag(name = "cwe")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class CweResource extends AlpineResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a list of all CWEs")
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all CWEs",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of CWEs", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = Cwe.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public Response getCwes() {
        final PaginatedResult cwes = CweResolver.getInstance().all(getAlpineRequest().getPagination());
        return Response.ok(cwes.getObjects()).header(TOTAL_COUNT_HEADER, cwes.getTotal()).build();
    }

    @GET
    @Path("/{cweId}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a specific CWE")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A CWE matching the provided ID",
                    content = @Content(schema = @Schema(implementation = Cwe.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The CWE could not be found")
    })
    public Response getCwe(
            @Parameter(description = "The CWE ID of the CWE to retrieve", required = true)
            @PathParam("cweId") int cweId) {
        final Cwe cwe = CweResolver.getInstance().lookup(cweId);
        if (cwe != null) {
            return Response.ok(cwe).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).entity("The CWE could not be found.").build();
        }
    }

}
