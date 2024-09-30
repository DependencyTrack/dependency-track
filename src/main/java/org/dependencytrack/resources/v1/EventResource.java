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

import alpine.event.framework.Event;
import alpine.server.resources.AlpineResource;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.resources.v1.vo.IsTokenBeingProcessedResponse;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.UUID;

/**
 * JAX-RS resources for processing Events
 *
 * @author Ralf King
 * @since 4.11.0
 */
@Path("/v1/event")
@Tag(name = "event")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class EventResource extends AlpineResource {

    @GET
    @Path("/token/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Determines if there are any tasks associated with the token that are being processed, or in the queue to be processed.",
            description = """
                    <p>
                      This endpoint is intended to be used in conjunction with other API calls which return a token for asynchronous tasks.
                      The token can then be queried using this endpoint to determine if the task is complete:
                      <ul>
                        <li>A value of <code>true</code> indicates processing is occurring.</li>
                        <li>A value of <code>false</code> indicates that no processing is occurring for the specified token.</li>
                      </ul>
                      However, a value of <code>false</code> also does not confirm the token is valid,
                      only that no processing is associated with the specified token.
                    </p>"""
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The processing status of the provided token",
                    content = @Content(schema = @Schema(implementation = IsTokenBeingProcessedResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public Response isTokenBeingProcessed (
            @Parameter(description = "The UUID of the token to query", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        final boolean value = Event.isEventBeingProcessed(UUID.fromString(uuid));
        IsTokenBeingProcessedResponse response = new IsTokenBeingProcessedResponse();
        response.setProcessing(value);
        return Response.ok(response).build();
    }
}
