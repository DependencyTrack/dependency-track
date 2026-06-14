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
import jakarta.validation.Validator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.command.MakeViolationAnalysisCommand;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.ViolationAnalysisRequest;
import org.dependencytrack.resources.v1.vo.ViolationAnalysisResponse;

/**
 * JAX-RS resources for processing violation analysis decisions.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
@Path("/v1/violation/analysis")
@Tag(name = "violationanalysis")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class ViolationAnalysisResource extends AbstractApiResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Retrieves a violation analysis trail",
            description = "<p>Requires permission <strong>VIEW_POLICY_VIOLATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A violation analysis trail",
                    content = @Content(schema = @Schema(implementation = ViolationAnalysisResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The component or policy violation could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_POLICY_VIOLATION)
    public Response retrieveAnalysis(@Parameter(description = "The UUID of the component", schema = @Schema(type = "string", format = "uuid"), required = true)
                                     @QueryParam("component") @ValidUuid String componentUuid,
                                     @Parameter(description = "The UUID of the policy violation", schema = @Schema(type = "string", format = "uuid"), required = true)
                                     @QueryParam("policyViolation") @ValidUuid String violationUuid) {
        failOnValidationError(
                new ValidationTask(RegexSequence.Pattern.UUID, componentUuid, "Component is not a valid UUID"),
                new ValidationTask(RegexSequence.Pattern.UUID, violationUuid, "Policy violation is not a valid UUID")
        );

        try (final var qm = new QueryManager(getAlpineRequest())) {
            final var component = qm.getObjectByUuid(Component.class, componentUuid);
            if (component == null) {
                return Response
                        .status(Response.Status.NOT_FOUND)
                        .entity("The component could not be found.")
                        .build();
            }
            requireAccess(qm, component.getProject());

            final var policyViolation = qm.getObjectByUuid(PolicyViolation.class, violationUuid);
            if (policyViolation == null) {
                return Response
                        .status(Response.Status.NOT_FOUND)
                        .entity("The policy violation could not be found.")
                        .build();
            }

            final ViolationAnalysis analysis = qm.getViolationAnalysis(component, policyViolation);
            return Response
                    .ok(analysis != null
                            ? ViolationAnalysisResponse.of(analysis)
                            : null)
                    .build();
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Records a violation analysis decision",
            description = "<p>Requires permission <strong>POLICY_VIOLATION_ANALYSIS</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The created violation analysis",
                    content = @Content(schema = @Schema(implementation = ViolationAnalysisResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The component or policy violation could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_VIOLATION_ANALYSIS)
    public Response updateAnalysis(ViolationAnalysisRequest request) {
        final Validator validator = getValidator();
        failOnValidationError(
                validator.validateProperty(request, "component"),
                validator.validateProperty(request, "policyViolation"),
                validator.validateProperty(request, "analysisState"),
                validator.validateProperty(request, "comment")
        );

        try (final var qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                final var component = qm.getObjectByUuid(Component.class, request.getComponent());
                if (component == null) {
                    return Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The component could not be found.")
                            .build();
                }
                requireAccess(qm, component.getProject());

                final var violation = qm.getObjectByUuid(PolicyViolation.class, request.getPolicyViolation());
                if (violation == null) {
                    return Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The policy violation could not be found.")
                            .build();
                }

                final long analysisId = qm.makeViolationAnalysis(
                        new MakeViolationAnalysisCommand(component, violation)
                                .withState(request.getAnalysisState())
                                .withSuppress(request.isSuppressed())
                                .withComment(request.getComment()));

                return Response
                        .ok(ViolationAnalysisResponse.of(qm.getObjectById(ViolationAnalysis.class, analysisId)))
                        .build();
            });
        }
    }

}
