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

import alpine.persistence.PaginatedResult;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.ResponseHeader;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.FetchPlan;
import javax.jdo.PersistenceManager;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Collection;

/**
 * JAX-RS resources for processing policy violations.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
@Path("/v1/violation")
@Api(value = "violation", authorizations = @Authorization(value = "X-Api-Key"))
public class PolicyViolationResource extends AlpineResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all policy violations for the entire portfolio",
            response = PolicyViolation.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of policy violations")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_POLICY_VIOLATION)
    public Response getViolations(@ApiParam(value = "Optionally includes suppressed violations")
                                  @QueryParam("suppressed") boolean suppressed) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getPolicyViolations(suppressed);
            return Response.ok(detachViolations(qm, result.getList(PolicyViolation.class)))
                    .header(TOTAL_COUNT_HEADER, result.getTotal())
                    .build();
        }
    }

    @GET
    @Path("/project/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all policy violations for a specific project",
            response = PolicyViolation.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of policy violations")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_POLICY_VIOLATION)
    public Response getViolationsByProject(@PathParam("uuid") String uuid,
                                           @ApiParam(value = "Optionally includes suppressed violations")
                                           @QueryParam("suppressed") boolean suppressed) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    final PaginatedResult result = qm.getPolicyViolations(project, suppressed);
                    return Response.ok(detachViolations(qm, result.getList(PolicyViolation.class)))
                            .header(TOTAL_COUNT_HEADER, result.getTotal())
                            .build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/component/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all policy violations for a specific component",
            response = PolicyViolation.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of policy violations")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified component is forbidden"),
            @ApiResponse(code = 404, message = "The component could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_POLICY_VIOLATION)
    public Response getViolationsByComponent(@PathParam("uuid") String uuid,
                                             @ApiParam(value = "Optionally includes suppressed violations")
                                             @QueryParam("suppressed") boolean suppressed) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component != null) {
                if (qm.hasAccess(super.getPrincipal(), component.getProject())) {
                    final PaginatedResult result = qm.getPolicyViolations(component, suppressed);
                    return Response.ok(detachViolations(qm, result.getList(PolicyViolation.class)))
                            .header(TOTAL_COUNT_HEADER, result.getTotal())
                            .build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified component is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
        }
    }

    /**
     * Detach a given {@link Collection} of {@link PolicyViolation} suitable for use in API responses.
     * <p>
     * This ensures that responses include not only the violations themselves, but also the associated
     * {@link org.dependencytrack.model.Policy}, which is required to tell the policy name and violation state.
     *
     * @param qm         The {@link QueryManager} to use
     * @param violations The {@link PolicyViolation}s to detach
     * @return A detached {@link Collection} of {@link PolicyViolation}s
     * @see <a href="https://github.com/DependencyTrack/dependency-track/issues/2043">GitHub issue</a>
     */
    private Collection<PolicyViolation> detachViolations(final QueryManager qm, final Collection<PolicyViolation> violations) {
        final PersistenceManager pm = qm.getPersistenceManager();
        pm.getFetchPlan().setMaxFetchDepth(2); // Ensure policy is included
        pm.getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
        return qm.getPersistenceManager().detachCopyAll(violations);
    }

}
