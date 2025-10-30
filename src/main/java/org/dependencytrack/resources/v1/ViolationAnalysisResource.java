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
import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.UserPrincipal;
import alpine.server.auth.PermissionRequired;
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
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.vo.ViolationAnalysisRequest;
import org.dependencytrack.util.NotificationUtil;

import jakarta.validation.Validator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

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
public class ViolationAnalysisResource extends AlpineResource {

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
                    content = @Content(schema = @Schema(implementation = ViolationAnalysis.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
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
        try (QueryManager qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, componentUuid);
            if (component == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
            final PolicyViolation policyViolation = qm.getObjectByUuid(PolicyViolation.class, violationUuid);
            if (policyViolation == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The policy violation could not be found.").build();
            }
            final ViolationAnalysis analysis = qm.getViolationAnalysis(component, policyViolation);
            return Response.ok(analysis).build();
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
                    content = @Content(schema = @Schema(implementation = ViolationAnalysis.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
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
        try (QueryManager qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, request.getComponent());
            if (component == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
            final PolicyViolation violation = qm.getObjectByUuid(PolicyViolation.class, request.getPolicyViolation());
            if (violation == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The policy violation could not be found.").build();
            }

            String commenter = null;
            if (getPrincipal() instanceof LdapUser || getPrincipal() instanceof ManagedUser || getPrincipal() instanceof OidcUser) {
                commenter = ((UserPrincipal) getPrincipal()).getUsername();
            }

            boolean analysisStateChange = false;
            boolean suppressionChange = false;
            ViolationAnalysis analysis = qm.getViolationAnalysis(component, violation);
            if (analysis != null) {
                if (request.getAnalysisState() != null && analysis.getAnalysisState() != request.getAnalysisState()) {
                    analysisStateChange = true;
                    qm.makeViolationAnalysisComment(analysis, String.format("%s → %s", analysis.getAnalysisState(), request.getAnalysisState()), commenter);
                }
                if (request.isSuppressed() != null && analysis.isSuppressed() != request.isSuppressed()) {
                    suppressionChange = true;
                    final String message = (request.isSuppressed()) ? "Suppressed" : "Unsuppressed";
                    qm.makeViolationAnalysisComment(analysis, message, commenter);
                }
                analysis = qm.makeViolationAnalysis(component, violation, request.getAnalysisState(), request.isSuppressed());
            } else {
                analysis = qm.makeViolationAnalysis(component, violation, request.getAnalysisState(), request.isSuppressed());
                analysisStateChange = true; // this is a new analysis - so set to true because it was previously null
                if (ViolationAnalysisState.NOT_SET != request.getAnalysisState()) {
                    qm.makeViolationAnalysisComment(analysis, String.format("%s → %s", ViolationAnalysisState.NOT_SET, request.getAnalysisState()), commenter);
                }
            }

            final String comment = StringUtils.trimToNull(request.getComment());
            qm.makeViolationAnalysisComment(analysis, comment, commenter);
            analysis = qm.getObjectById(ViolationAnalysis.class, analysis.getId());
            NotificationUtil.analyzeNotificationCriteria(qm, analysis, analysisStateChange, suppressionChange);
            return Response.ok(analysis).build();
        }
    }

}
