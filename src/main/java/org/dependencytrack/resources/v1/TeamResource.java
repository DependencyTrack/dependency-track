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

import alpine.Config;
import alpine.auth.PermissionRequired;
import alpine.logging.Logger;
import alpine.model.ApiKey;
import alpine.model.Team;
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.ResponseHeader;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.vo.TeamSelfResponse;
import org.owasp.security.logging.SecurityMarkers;
import javax.validation.Validator;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.List;

/**
 * JAX-RS resources for processing teams.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/team")
@Api(value = "team", authorizations = @Authorization(value = "X-Api-Key"))
public class TeamResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(TeamResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all teams",
            response = Team.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of teams")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response getTeams() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final long totalCount = qm.getCount(Team.class);
            final List<Team> teams = qm.getTeams();
            return Response.ok(teams).header(TOTAL_COUNT_HEADER, totalCount).build();
        }
    }

    @GET
    @Path("/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a specific team",
            response = Team.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The team could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response getTeam(
            @ApiParam(value = "The UUID of the team to retrieve", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.getObjectByUuid(Team.class, uuid);
            if (team != null) {
                return Response.ok(team).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The team could not be found.").build();
            }
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Creates a new team along with an associated API key",
            response = Team.class,
            code = 201
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    //public Response createTeam(String jsonRequest) {
    public Response createTeam(Team jsonTeam) {
        //Team team = MapperUtil.readAsObjectOf(Team.class, jsonRequest);
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonTeam, "name")
        );

        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.createTeam(jsonTeam.getName(), true);
            super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Team created: " + team.getName());
            return Response.status(Response.Status.CREATED).entity(team).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Updates a team's fields including",
            response = Team.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The team could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response updateTeam(Team jsonTeam) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonTeam, "name")
        );
        try (QueryManager qm = new QueryManager()) {
            Team team = qm.getObjectByUuid(Team.class, jsonTeam.getUuid());
            if (team != null) {
                team.setName(jsonTeam.getName());
                //todo: set permissions
                team = qm.updateTeam(jsonTeam);
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Team updated: " + team.getName());
                return Response.ok(team).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The team could not be found.").build();
            }
        }
    }

    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Deletes a team",
            code = 204
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The team could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response deleteTeam(Team jsonTeam) {
        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.getObjectByUuid(Team.class, jsonTeam.getUuid(), Team.FetchGroup.ALL.name());
            if (team != null) {
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Team deleted: " + team.getName());
                qm.delete(team.getApiKeys());
                qm.delete(team);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The team could not be found.").build();
            }
        }
    }

    @PUT
    @Path("/{uuid}/key")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Generates an API key and returns its value",
            response = ApiKey.class,
            code = 201
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The team could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response generateApiKey(
            @ApiParam(value = "The UUID of the team to generate a key for", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.getObjectByUuid(Team.class, uuid);
            if (team != null) {
                final ApiKey apiKey = qm.createApiKey(team);
                return Response.status(Response.Status.CREATED).entity(apiKey).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The team could not be found.").build();
            }
        }
    }

    @POST
    @Path("/key/{apikey}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Regenerates an API key by removing the specified key, generating a new one and returning its value",
            response = ApiKey.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The API key could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response regenerateApiKey(
            @ApiParam(value = "The API key to regenerate", required = true)
            @PathParam("apikey") String apikey) {
        try (QueryManager qm = new QueryManager()) {
            ApiKey apiKey = qm.getApiKey(apikey);
            if (apiKey != null) {
                apiKey = qm.regenerateApiKey(apiKey);
                return Response.ok(apiKey).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The API key could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/key/{apikey}")
    @ApiOperation(
            value = "Deletes the specified API key",
            code = 204
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The API key could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response deleteApiKey(
            @ApiParam(value = "The API key to delete", required = true)
            @PathParam("apikey") String apikey) {
        try (QueryManager qm = new QueryManager()) {
            final ApiKey apiKey = qm.getApiKey(apikey);
            if (apiKey != null) {
                qm.delete(apiKey);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The API key could not be found.").build();
            }
        }
    }

    @GET
    @Path("self")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns information about the current team.",
            response = TeamSelfResponse.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 400, message = "Invalid API key supplied"),
            @ApiResponse(code = 404, message = "No Team for the given API key found")
    })
    public Response getSelf() {
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.ENFORCE_AUTHENTICATION)) {
            try (var qm = new QueryManager()) {
                if (isApiKey()) {
                    final var apiKey = qm.getApiKey(((ApiKey)getPrincipal()).getKey());
                    final var team = apiKey.getTeams().stream().findFirst();
                    if (team.isPresent()) {
                        return Response.ok(new TeamSelfResponse(team.get())).build();
                    } else {
                        return Response.status(Response.Status.NOT_FOUND).entity("No Team for the given API key found.").build();
                    }
                } else {
                    return Response.status(Response.Status.BAD_REQUEST).entity("Invalid API key supplied.").build();
                }
            }
        }
        // Authentication is not enabled, but we need to return a positive response without any principal data.
        return Response.ok().build();
    }
}
