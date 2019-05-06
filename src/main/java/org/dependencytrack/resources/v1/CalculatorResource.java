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

import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import us.springett.cvss.Cvss;
import us.springett.cvss.Score;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * JAX-RS resources for processing severity calculations.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/calculator")
@Api(value = "calculator", authorizations = @Authorization(value = "X-Api-Key"))
public class CalculatorResource extends AlpineResource {

    @GET
    @Path("/cvss")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns the CVSS base score, impact sub-score and exploitability sub-score",
            response = Score.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    public Response getCvssScores(
            @ApiParam(value = "A valid CVSSv2 or CVSSv3 vector", required = true)
            @QueryParam("vector") String vector) {
        try {
            final Cvss cvss = Cvss.fromVector(vector);
            final Score score = cvss.calculateScore();
            return Response.ok(score).build();
        } catch (NullPointerException e) {
            final String invalidVector = "An invalid CVSSv2 or CVSSv3 vector submitted.";
            return Response.status(Response.Status.BAD_REQUEST).entity(invalidVector).build();
        }
    }

}
