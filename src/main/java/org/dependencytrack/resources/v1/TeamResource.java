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

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.model.ApiKey;
import alpine.model.Team;
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
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.vo.TeamSelfResponse;
import org.owasp.security.logging.SecurityMarkers;

import jakarta.validation.Validator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;

import static org.datanucleus.PropertyNames.PROPERTY_RETAIN_VALUES;

/**
 * JAX-RS resources for processing teams.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/team")
@Tag(name = "team")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class TeamResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(TeamResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all teams",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all teams",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of teams", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = Team.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
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
    @Operation(
            summary = "Returns a specific team",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A specific team",
                    content = @Content(schema = @Schema(implementation = Team.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The team could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response getTeam(
            @Parameter(description = "The UUID of the team to retrieve", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
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
    @Operation(
            summary = "Creates a new team",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created team",
                    content = @Content(schema = @Schema(implementation = Team.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
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
            final Team team = qm.createTeam(jsonTeam.getName(), false);
            super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Team created: " + team.getName());
            return Response.status(Response.Status.CREATED).entity(team).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates a team's fields",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated team",
                    content = @Content(schema = @Schema(implementation = Team.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The team could not be found")
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
    @Operation(
            summary = "Deletes a team",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Team removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The team could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response deleteTeam(Team jsonTeam) {
        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.getObjectByUuid(Team.class, jsonTeam.getUuid(), Team.FetchGroup.ALL.name());
            if (team != null) {
                String teamName = team.getName();
                qm.recursivelyDeleteTeam(team);
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Team deleted: " + teamName);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The team could not be found.").build();
            }
        }
    }

    @PUT
    @Path("/{uuid}/key")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Generates an API key and returns its value",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created API key",
                    content = @Content(schema = @Schema(implementation = ApiKey.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The team could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response generateApiKey(
            @Parameter(description = "The UUID of the team to generate a key for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
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
    @Operation(
            summary = "Regenerates an API key by removing the specified key, generating a new one and returning its value",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The re-generated API key",
                    content = @Content(schema = @Schema(implementation = ApiKey.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The API key could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response regenerateApiKey(
            @Parameter(description = "The API key to regenerate", required = true)
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

    @POST
    @Path("/key/{key}/comment")
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates an API key's comment",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated API key",
                    content = @Content(schema = @Schema(implementation = ApiKey.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The API key could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response updateApiKeyComment(@PathParam("key") final String key,
                                        final String comment) {
        try (final var qm = new QueryManager()) {
            qm.getPersistenceManager().setProperty(PROPERTY_RETAIN_VALUES, "true");

            return qm.callInTransaction(() -> {
                final ApiKey apiKey = qm.getApiKey(key);
                if (apiKey == null) {
                    return Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The API key could not be found.")
                            .build();
                }

                apiKey.setComment(comment);
                return Response.ok(apiKey).build();
            });
        }
    }

    @DELETE
    @Path("/key/{apikey}")
    @Operation(
            summary = "Deletes the specified API key",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "API key removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The API key could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response deleteApiKey(
            @Parameter(description = "The API key to delete", required = true)
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
    @Operation(
            summary = "Returns information about the current team.")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Information about the current team",
                    content = @Content(schema = @Schema(implementation = TeamSelfResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "400", description = "Invalid API key supplied"),
            @ApiResponse(responseCode = "404", description = "No Team for the given API key found")
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
