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

import alpine.common.validation.RegexSequence;
import alpine.common.validation.ValidationTask;
import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.UserPrincipal;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
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

import javax.validation.Validator;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * JAX-RS resources for processing analysis decisions.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
@Path("/v1/analysis")
@Api(value = "analysis", authorizations = @Authorization(value = "X-Api-Key"))
public class AnalysisResource extends AlpineResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Retrieves an analysis trail",
            response = Analysis.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project, component, or vulnerability could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response retrieveAnalysis(@ApiParam(value = "The UUID of the project")
                                     @QueryParam("project") String projectUuid,
                                     @ApiParam(value = "The UUID of the component", required = true)
                                     @QueryParam("component") String componentUuid,
                                     @ApiParam(value = "The UUID of the vulnerability", required = true)
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
    @ApiOperation(
            value = "Records an analysis decision",
            response = Analysis.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project, component, or vulnerability could not be found")
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
