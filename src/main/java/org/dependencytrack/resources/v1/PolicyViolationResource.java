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

import alpine.persistence.PaginatedResult;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import javax.jdo.FetchPlan;
import javax.jdo.PersistenceManager;
import java.util.Collection;

/**
 * JAX-RS resources for processing policy violations.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
@Path("/v1/violation")
@Tag(name = "violation")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class PolicyViolationResource extends AlpineResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all policy violations for the entire portfolio",
            description = "<p>Requires permission <strong>VIEW_POLICY_VIOLATION</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all policy violations for the entire portfolio",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of policy violations", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = PolicyViolation.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_POLICY_VIOLATION)
    public Response getViolations(@Parameter(description = "Optionally includes suppressed violations")
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
    @Operation(
            summary = "Returns a list of all policy violations for a specific project",
            description = "<p>Requires permission <strong>VIEW_POLICY_VIOLATION</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all policy violations for a specific project",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of policy violations", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = PolicyViolation.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_POLICY_VIOLATION)
    public Response getViolationsByProject(@Parameter(description = "The UUID of the project", schema = @Schema(type = "string", format = "uuid"), required = true)
                                           @PathParam("uuid") @ValidUuid String uuid,
                                           @Parameter(description = "Optionally includes suppressed violations")
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
    @Operation(
            summary = "Returns a list of all policy violations for a specific component",
            description = "<p>Requires permission <strong>VIEW_POLICY_VIOLATION</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all policy violations for a specific component",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of policy violations", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = PolicyViolation.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified component is forbidden"),
            @ApiResponse(responseCode = "404", description = "The component could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_POLICY_VIOLATION)
    public Response getViolationsByComponent(@Parameter(description = "The UUID of the component", schema = @Schema(type = "string", format = "uuid"), required = true)
                                             @PathParam("uuid") @ValidUuid String uuid,
                                             @Parameter(description = "Optionally includes suppressed violations")
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
