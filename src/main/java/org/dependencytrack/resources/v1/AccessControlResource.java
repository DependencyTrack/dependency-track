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
import alpine.logging.Logger;
import alpine.model.Team;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.vo.AclMappingRequest;
import javax.validation.Validator;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;

/**
 * JAX-RS resources for processing LDAP group mapping requests.
 *
 * @author Steve Springett
 * @since 3.3.0
 */
@Path("/v1/acl")
@Api(value = "acl", authorizations = @Authorization(value = "X-Api-Key"))
public class AccessControlResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(AccessControlResource.class);

    @GET
    @Path("/team/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns the projects assigned to the specified team",
            response = String.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the team could not be found"),
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response retrieveProjects (@ApiParam(value = "The UUID of the team to retrieve mappings for", required = true)
                                      @PathParam("uuid") String uuid,
                                      @ApiParam(value = "Optionally excludes inactive projects from being returned", required = false)
                                      @QueryParam("excludeInactive") boolean excludeInactive) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Team team = qm.getObjectByUuid(Team.class, uuid);
            if (team != null) {
                final PaginatedResult result = qm.getProjects(team, excludeInactive, true);
                return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the team could not be found.").build();
            }
        }
    }

    @PUT
    @Path("/mapping")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Adds an ACL mapping",
            response = AclMappingRequest.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the team or project could not be found"),
            @ApiResponse(code = 409, message = "A mapping with the same team and project already exists")
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
    @ApiOperation(
            value = "Removes an ACL mapping"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the team or project could not be found"),
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response deleteMapping(
            @ApiParam(value = "The UUID of the team to delete the mapping for", required = true)
            @PathParam("teamUuid") String teamUuid,
            @ApiParam(value = "The UUID of the project to delete the mapping for", required = true)
            @PathParam("projectUuid") String projectUuid) {
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
