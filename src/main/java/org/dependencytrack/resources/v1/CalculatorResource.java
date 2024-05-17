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
import us.springett.cvss.Cvss;
import us.springett.cvss.Score;
import us.springett.owasp.riskrating.MissingFactorException;
import us.springett.owasp.riskrating.OwaspRiskRating;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * JAX-RS resources for processing severity calculations.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/calculator")
@Tag(name = "calculator")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class CalculatorResource extends AlpineResource {

    @GET
    @Path("/cvss")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns the CVSS base score, impact sub-score and exploitability sub-score")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The calculated scores",
                    content = @Content(schema = @Schema(implementation = Score.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public Response getCvssScores(
            @Parameter(description = "A valid CVSSv2 or CVSSv3 vector", required = true)
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

    @GET
    @Path("/owasp")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns the OWASP Risk Rating likelihood score, technical impact score and business impact score")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The calculated scores",
                    content = @Content(schema = @Schema(implementation = us.springett.owasp.riskrating.Score.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public Response getOwaspRRScores(
            @Parameter(description = "A valid OWASP Risk Rating vector", required = true)
            @QueryParam("vector") String vector) {
        try {
            final OwaspRiskRating owaspRiskRating = OwaspRiskRating.fromVector(vector);
            final us.springett.owasp.riskrating.Score score = owaspRiskRating.calculateScore();
            return Response.ok(score).build();
        } catch (IllegalArgumentException | MissingFactorException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

}
