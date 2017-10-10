/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
 */
package org.owasp.dependencytrack.resources.v1;

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
import org.owasp.dependencytrack.auth.Permission;
import org.owasp.dependencytrack.persistence.QueryManager;
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
            notes = "Requires 'manage teams' permission.",
            response = Team.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of teams")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permission.MANAGE_TEAMS)
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
            notes = "Requires 'manage teams' permission.",
            response = Team.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The user could not be found")
    })
    @PermissionRequired(Permission.MANAGE_TEAMS)
    public Response getTeam(
            @ApiParam(value = "The UUID of the team to retrieve", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.getObjectByUuid(Team.class, uuid);
            if (team != null) {
                return Response.ok(team).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The user could not be found.").build();
            }
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Creates a new team along with an associated API key",
            notes = "Requires 'manage teams' permission.",
            response = Team.class,
            code = 201
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permission.MANAGE_TEAMS)
    //public Response createTeam(String jsonRequest) {
    public Response createTeam(Team jsonTeam) {
        //Team team = MapperUtil.readAsObjectOf(Team.class, jsonRequest);
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonTeam, "name")
        );

        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.createTeam(jsonTeam.getName(), true);
            super.addAuditableEvent(LOGGER, "Team created: " + team.getName());
            return Response.status(Response.Status.CREATED).entity(team).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Updates a team's fields including name and hakmaster",
            notes = "Requires 'manage teams' permission.",
            response = Team.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the team could not be found")
    })
    @PermissionRequired(Permission.MANAGE_TEAMS)
    public Response updateTeam(Team jsonTeam) {
        try (QueryManager qm = new QueryManager()) {
            Team team = qm.getObjectByUuid(Team.class, jsonTeam.getUuid());
            if (team != null) {
                team.setName(jsonTeam.getName());
                //todo: set permissions
                team = qm.updateTeam(jsonTeam);
                super.addAuditableEvent(LOGGER, "Team updated: " + team.getName());
                return Response.ok(team).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the team could not be found.").build();
            }
        }
    }

    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Deletes a team",
            notes = "Requires 'manage teams' permission.",
            code = 204
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the team could not be found")
    })
    @PermissionRequired(Permission.MANAGE_TEAMS)
    public Response deleteTeam(Team jsonTeam) {
        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.getObjectByUuid(Team.class, jsonTeam.getUuid(), Team.FetchGroup.ALL.name());
            if (team != null) {
                super.addAuditableEvent(LOGGER, "Team deleted: " + team.getName());
                qm.delete(team.getApiKeys());
                qm.delete(team);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the team could not be found.").build();
            }
        }
    }

    @PUT
    @Path("/{uuid}/key")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Generates an API key and returns its value",
            notes = "Requires 'manage api keys' permission.",
            response = ApiKey.class,
            code = 201
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the team could not be found")
    })
    @PermissionRequired(Permission.MANAGE_API_KEYS)
    public Response generateApiKey(
            @ApiParam(value = "The UUID of the team to generate a key for", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.getObjectByUuid(Team.class, uuid);
            if (team != null) {
                final ApiKey apiKey = qm.createApiKey(team);
                return Response.status(Response.Status.CREATED).entity(apiKey).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the team could not be found.").build();
            }
        }
    }

    @POST
    @Path("/key/{apikey}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Regenerates an API key by removing the specified key, generating a new one and returning its value",
            notes = "Requires 'manage api keys' permission.",
            response = ApiKey.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The API key could not be found")
    })
    @PermissionRequired(Permission.MANAGE_API_KEYS)
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
            notes = "Requires 'manage api keys' permission.",
            code = 204
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The API key could not be found")
    })
    @PermissionRequired(Permission.MANAGE_API_KEYS)
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

}
