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

import alpine.common.logging.Logger;
import alpine.model.Team;
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
import org.dependencytrack.model.Project;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;
import org.dependencytrack.resources.v1.vo.AclMappingRequest;

import jakarta.validation.Validator;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;

/**
 * JAX-RS resources for processing LDAP group mapping requests.
 *
 * @author Steve Springett
 * @since 3.3.0
 */
@Path("/v1/acl")
@Tag(name = "acl")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class AccessControlResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(AccessControlResource.class);

    @GET
    @Path("/team/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns the projects assigned to the specified team",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Projects assigned to the specified team",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of projects", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = Project.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the team could not be found"),
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response retrieveProjects (@Parameter(description = "The UUID of the team to retrieve mappings for", schema = @Schema(type = "string", format = "uuid"), required = true)
                                      @PathParam("uuid") @ValidUuid String uuid,
                                      @Parameter(description = "Optionally excludes inactive projects from being returned", required = false)
                                      @QueryParam("excludeInactive") boolean excludeInactive,
                                      @Parameter(description = "Optionally excludes children projects from being returned", required = false)
                                      @QueryParam("onlyRoot") boolean onlyRoot) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Team team = qm.getObjectByUuid(Team.class, uuid);
            if (team != null) {
                final PaginatedResult result = qm.getProjects(team, excludeInactive, true, onlyRoot);
                return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the team could not be found.").build();
            }
        }
    }

    @PUT
    @Path("/mapping")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Adds an ACL mapping",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Mapping created successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the team or project could not be found"),
            @ApiResponse(responseCode = "409", description = "A mapping with the same team and project already exists")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response addMapping(AclMappingRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(request, "team"),
                validator.validateProperty(request, "project")
        );
        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.getObjectByUuid(Team.class, request.getTeam());
            final Project project = qm.getObjectByUuid(Project.class, request.getProject());
            if (team != null && project != null) {
                for (final Team t: project.getAccessTeams()) {
                   if (t.getUuid() == team.getUuid()) {
                       return Response.status(Response.Status.CONFLICT).entity("A mapping with the same team and project already exists.").build();
                   }
                }
                project.addAccessTeam(team);
                qm.persist(project);
                return Response.ok().build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the team could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/mapping/team/{teamUuid}/project/{projectUuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Removes an ACL mapping",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Mapping removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the team or project could not be found"),
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response deleteMapping(
            @Parameter(description = "The UUID of the team to delete the mapping for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("teamUuid") @ValidUuid String teamUuid,
            @Parameter(description = "The UUID of the project to delete the mapping for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("projectUuid") @ValidUuid String projectUuid) {
        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.getObjectByUuid(Team.class, teamUuid);
            final Project project = qm.getObjectByUuid(Project.class, projectUuid);
            if (team != null && project != null) {
                final List<Team> teams = new ArrayList<>();
                for (final Team t: project.getAccessTeams()) {
                    if (t.getUuid() != team.getUuid()) {
                        teams.add(t);
                    }
                }
                project.setAccessTeams(teams);
                qm.persist(project);
                return Response.ok().build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the team or project could not be found.").build();
            }
        }
    }
}
