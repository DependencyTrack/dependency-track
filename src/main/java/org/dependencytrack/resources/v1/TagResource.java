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
import alpine.server.auth.PermissionRequired;
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
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/v1/tag")
@io.swagger.v3.oas.annotations.tags.Tag(name = "tag")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class TagResource extends AlpineResource {

    @GET
    @Path("/{policyUuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all tags associated with a given policy",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all tags associated with a given policy",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of tags", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = Tag.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getTags(@Parameter(description = "The UUID of the policy", schema = @Schema(type = "string", format = "uuid"), required = true)
                            @PathParam("policyUuid") @ValidUuid String policyUuid){
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getTags(policyUuid);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }
}
