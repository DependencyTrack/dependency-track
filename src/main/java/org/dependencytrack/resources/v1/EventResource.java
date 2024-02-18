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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.resources.v1;

import alpine.event.framework.Event;
import alpine.server.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import org.dependencytrack.resources.v1.vo.IsTokenBeingProcessedResponse;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.UUID;

/**
 * JAX-RS resources for processing Events
 *
 * @author Ralf King
 * @since 4.11.0
 */
@Path("/v1/event")
@Api(value = "event", authorizations = @Authorization(value = "X-Api-Key"))
public class EventResource extends AlpineResource {

    @GET
    @Path("/token/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Determines if there are any tasks associated with the token that are being processed, or in the queue to be processed.",
            notes = "This endpoint is intended to be used in conjunction with other API calls which return a token for asynchronous tasks. " +
                    "The token can then be queried using this endpoint to determine if the task is complete. " +
                    "A value of true indicates processing is occurring. A value of false indicates that no processing is " +
                    "occurring for the specified token. However, a value of false also does not confirm the token is valid, " +
                    "only that no processing is associated with the specified token.", response = IsTokenBeingProcessedResponse.class)
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    public Response isTokenBeingProcessed (
            @ApiParam(value = "The UUID of the token to query", required = true)
            @PathParam("uuid") String uuid) {
        final boolean value = Event.isEventBeingProcessed(UUID.fromString(uuid));
        IsTokenBeingProcessedResponse response = new IsTokenBeingProcessedResponse();
        response.setProcessing(value);
        return Response.ok(response).build();
    }
}
