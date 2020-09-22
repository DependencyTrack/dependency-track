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

import alpine.auth.PermissionRequired;
import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.UserPrincipal;
import alpine.resources.AlpineResource;
import alpine.validation.RegexSequence;
import alpine.validation.ValidationTask;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.vo.ViolationAnalysisRequest;
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
 * JAX-RS resources for processing violation analysis decisions.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
@Path("/v1/violation/analysis")
@Api(value = "violationanalysis", authorizations = @Authorization(value = "X-Api-Key"))
public class ViolationAnalysisResource extends AlpineResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Retrieves a violation analysis trail",
            response = ViolationAnalysis.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The component or policy violation could not be found")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS)
    public Response retrieveAnalysis(@ApiParam(value = "The UUID of the component", required = true)
                                     @QueryParam("component") String componentUuid,
                                     @ApiParam(value = "The UUID of the policy violation", required = true)
                                     @QueryParam("policyViolation") String violationUuid) {
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
    @ApiOperation(
            value = "Records a violation analysis decision",
            response = ViolationAnalysis.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The component or policy violation could not be found")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS)
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
                    // The analysis state has changed. Add an additional comment to the trail.
                    analysisStateChange = true;
                    final String message = analysis.getAnalysisState().name() + " → " + request.getAnalysisState().name();
                    qm.makeViolationAnalysisComment(analysis, message, commenter);
                    analysis = qm.makeViolationAnalysis(component, violation, request.getAnalysisState(), request.isSuppressed());
                } else if (request.isSuppressed() != null && analysis.isSuppressed() != request.isSuppressed()) {
                    suppressionChange = true;
                    final String message = (request.isSuppressed()) ? "Suppressed" : "Unsuppressed";
                    qm.makeViolationAnalysisComment(analysis, message, commenter);
                    analysis = qm.makeViolationAnalysis(component, violation, analysis.getAnalysisState(), request.isSuppressed());
                }
            } else {
                analysis = qm.makeViolationAnalysis(component, violation, request.getAnalysisState(), request.isSuppressed());
                analysisStateChange = true; // this is a new analysis - so set to true because it was previously null
                if (ViolationAnalysisState.NOT_SET != request.getAnalysisState()) {
                    final String message = ViolationAnalysisState.NOT_SET.name() + " → " + request.getAnalysisState().name();
                    qm.makeViolationAnalysisComment(analysis, message, commenter);
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
