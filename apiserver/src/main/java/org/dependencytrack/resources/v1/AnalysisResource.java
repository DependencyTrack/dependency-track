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

import alpine.common.validation.RegexSequence;
import alpine.common.validation.ValidationTask;
import alpine.server.auth.PermissionRequired;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.jdbi.FindingAnalysisDao;
import org.dependencytrack.persistence.jdbi.FindingAnalysisDao.AnalysisTrail;
import org.dependencytrack.persistence.jdbi.VulnerabilityDao;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.AnalysisRequest;
import org.dependencytrack.resources.v1.vo.AnalysisTrailResponse;

import jakarta.validation.Validator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * JAX-RS resources for processing analysis decisions.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
@Path("/v1/analysis")
@Tag(name = "analysis")
@SecurityRequirements({@SecurityRequirement(name = "ApiKeyAuth"), @SecurityRequirement(name = "BearerAuth")})
public class AnalysisResource extends AbstractApiResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Retrieves an analysis trail",
            description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "An analysis trail",
                        content = @Content(schema = @Schema(implementation = AnalysisTrailResponse.class))),
                @ApiResponse(responseCode = "401", description = "Unauthorized"),
                @ApiResponse(
                        responseCode = "403",
                        description = "Access to the requested project is forbidden",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
                @ApiResponse(
                        responseCode = "404",
                        description = "The component, vulnerability, or analysis could not be found")
            })
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response retrieveAnalysis(
            @Parameter(
                            description = "Ignored. The project is inferred from the component.",
                            deprecated = true,
                            schema = @Schema(type = "string", format = "uuid"))
                    @QueryParam("project")
                    @ValidUuid
                    String projectUuid,
            @Parameter(
                            description = "The UUID of the component",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @QueryParam("component")
                    @ValidUuid
                    String componentUuid,
            @Parameter(
                            description = "The UUID of the vulnerability",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @QueryParam("vulnerability")
                    @ValidUuid
                    String vulnerabilityUuid) {
        failOnValidationError(
                new ValidationTask(
                        RegexSequence.Pattern.UUID,
                        projectUuid,
                        "Project is not a valid UUID",
                        false), // this is optional
                new ValidationTask(RegexSequence.Pattern.UUID, componentUuid, "Component is not a valid UUID"),
                new ValidationTask(RegexSequence.Pattern.UUID, vulnerabilityUuid, "Vulnerability is not a valid UUID"));
        return withJdbiHandle(getAlpineRequest(), handle -> {
            final UUID parsedComponentUuid = UUID.fromString(componentUuid);
            final long componentId = requireComponentAccess(handle, parsedComponentUuid);

            final Long vulnDbId = handle.attach(VulnerabilityDao.class).getVulnDbId(UUID.fromString(vulnerabilityUuid));
            if (vulnDbId == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The vulnerability could not be found.")
                        .build();
            }

            final var analysisDao = handle.attach(FindingAnalysisDao.class);
            final AnalysisTrail trail = analysisDao.getTrail(componentId, vulnDbId);
            if (trail == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("No analysis exists.")
                        .build();
            }

            return Response.ok(AnalysisTrailResponse.of(trail)).build();
        });
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Records an analysis decision",
            description =
                    "<p>Requires permission <strong>VULNERABILITY_ANALYSIS</strong></strong> or <strong>VULNERABILITY_ANALYSIS_UPDATE</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "The created analysis",
                        content = @Content(schema = @Schema(implementation = AnalysisTrailResponse.class))),
                @ApiResponse(responseCode = "401", description = "Unauthorized"),
                @ApiResponse(
                        responseCode = "403",
                        description = "Access to the requested project is forbidden",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
                @ApiResponse(
                        responseCode = "404",
                        description = "The project, component, or vulnerability could not be found")
            })
    @PermissionRequired({
        Permissions.Constants.VULNERABILITY_ANALYSIS,
        Permissions.Constants.VULNERABILITY_ANALYSIS_UPDATE
    })
    public Response updateAnalysis(AnalysisRequest request) {
        final Validator validator = getValidator();
        failOnValidationError(
                validator.validateProperty(request, "project"),
                validator.validateProperty(request, "component"),
                validator.validateProperty(request, "vulnerability"),
                validator.validateProperty(request, "analysisState"),
                validator.validateProperty(request, "analysisJustification"),
                validator.validateProperty(request, "analysisResponse"),
                validator.validateProperty(request, "analysisDetails"),
                validator.validateProperty(request, "comment"));
        final UUID componentUuid = UUID.fromString(request.getComponent());
        final UUID vulnUuid = UUID.fromString(request.getVulnerability());
        final String commenter = getPrincipalName();

        return inJdbiTransaction(getAlpineRequest(), handle -> {
            final long componentId = requireComponentAccess(handle, componentUuid);

            final Long vulnDbId = handle.attach(VulnerabilityDao.class).getVulnDbId(vulnUuid);
            if (vulnDbId == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The vulnerability could not be found.")
                        .build();
            }

            handle.attach(FindingAnalysisDao.class)
                    .makeAnalysis(new MakeAnalysisCommand(componentId, vulnDbId)
                            .withState(request.getAnalysisState())
                            .withJustification(request.getAnalysisJustification())
                            .withResponse(request.getAnalysisResponse())
                            .withDetails(request.getAnalysisDetails())
                            .withSuppress(request.isSuppressed())
                            .withCommenter(commenter)
                            .withComment(request.getComment()));

            final var analysisDao = handle.attach(FindingAnalysisDao.class);
            return Response.ok(AnalysisTrailResponse.of(requireNonNull(analysisDao.getTrail(componentId, vulnDbId))))
                    .build();
        });
    }
}
