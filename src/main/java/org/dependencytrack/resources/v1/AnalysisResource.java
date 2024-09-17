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
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.vo.AnalysisRequest;
import org.dependencytrack.util.AnalysisCommentUtil;
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
 * JAX-RS resources for processing analysis decisions.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
@Path("/v1/analysis")
@Tag(name = "analysis")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class AnalysisResource extends AlpineResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Retrieves an analysis trail",
            description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "An analysis trail",
                    content = @Content(schema = @Schema(implementation = Analysis.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The project, component, or vulnerability could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response retrieveAnalysis(@Parameter(description = "The UUID of the project", schema = @Schema(type = "string", format = "uuid"))
                                     @QueryParam("project") String projectUuid,
                                     @Parameter(description = "The UUID of the component", schema = @Schema(type = "string", format = "uuid"), required = true)
                                     @QueryParam("component") String componentUuid,
                                     @Parameter(description = "The UUID of the vulnerability", schema = @Schema(type = "string", format = "uuid"), required = true)
                                     @QueryParam("vulnerability") String vulnerabilityUuid) {
        failOnValidationError(
                new ValidationTask(RegexSequence.Pattern.UUID, projectUuid, "Project is not a valid UUID", false), // this is optional
                new ValidationTask(RegexSequence.Pattern.UUID, componentUuid, "Component is not a valid UUID"),
                new ValidationTask(RegexSequence.Pattern.UUID, vulnerabilityUuid, "Vulnerability is not a valid UUID")
        );
        try (QueryManager qm = new QueryManager()) {
            final Project project;
            if (StringUtils.trimToNull(projectUuid) != null) {
                project = qm.getObjectByUuid(Project.class, projectUuid);
                if (project == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
                }
            }
            final Component component = qm.getObjectByUuid(Component.class, componentUuid);
            if (component == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
            final Vulnerability vulnerability = qm.getObjectByUuid(Vulnerability.class, vulnerabilityUuid);
            if (vulnerability == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The vulnerability could not be found.").build();
            }
            final Analysis analysis = qm.getAnalysis(component, vulnerability);
            if (analysis == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("No analysis exists.").build();
            }
            return Response.ok(analysis).build();
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Records an analysis decision",
            description = "<p>Requires permission <strong>VULNERABILITY_ANALYSIS</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The created analysis",
                    content = @Content(schema = @Schema(implementation = Analysis.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The project, component, or vulnerability could not be found")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS)
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
                validator.validateProperty(request, "comment")
        );
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, request.getProject());
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            final Component component = qm.getObjectByUuid(Component.class, request.getComponent());
            if (component == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
            final Vulnerability vulnerability = qm.getObjectByUuid(Vulnerability.class, request.getVulnerability());
            if (vulnerability == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The vulnerability could not be found.").build();
            }

            String commenter = null;
            if (getPrincipal() instanceof LdapUser || getPrincipal() instanceof ManagedUser || getPrincipal() instanceof OidcUser) {
                commenter = ((UserPrincipal) getPrincipal()).getUsername();
            }

            boolean analysisStateChange = false;
            boolean suppressionChange = false;
            Analysis analysis = qm.getAnalysis(component, vulnerability);
            if (analysis != null) {
                analysisStateChange = AnalysisCommentUtil.makeStateComment(qm, analysis, request.getAnalysisState(), commenter);
                AnalysisCommentUtil.makeJustificationComment(qm, analysis, request.getAnalysisJustification(), commenter);
                AnalysisCommentUtil.makeAnalysisResponseComment(qm, analysis, request.getAnalysisResponse(), commenter);
                AnalysisCommentUtil.makeAnalysisDetailsComment(qm, analysis, request.getAnalysisDetails(), commenter);
                suppressionChange = AnalysisCommentUtil.makeAnalysisSuppressionComment(qm, analysis, request.isSuppressed(), commenter);
                analysis = qm.makeAnalysis(component, vulnerability, request.getAnalysisState(), request.getAnalysisJustification(), request.getAnalysisResponse(), request.getAnalysisDetails(), request.isSuppressed());
            } else {
                analysis = qm.makeAnalysis(component, vulnerability, request.getAnalysisState(), request.getAnalysisJustification(), request.getAnalysisResponse(), request.getAnalysisDetails(), request.isSuppressed());
                analysisStateChange = true; // this is a new analysis - so set to true because it was previously null
                if (AnalysisState.NOT_SET != request.getAnalysisState()) {
                    qm.makeAnalysisComment(analysis, String.format("Analysis: %s → %s", AnalysisState.NOT_SET, request.getAnalysisState()), commenter);
                }
            }

            final String comment = StringUtils.trimToNull(request.getComment());
            qm.makeAnalysisComment(analysis, comment, commenter);
            analysis = qm.getAnalysis(component, vulnerability);
            NotificationUtil.analyzeNotificationCriteria(qm, analysis, analysisStateChange, suppressionChange);
            return Response.ok(analysis).build();
        }
    }

}
