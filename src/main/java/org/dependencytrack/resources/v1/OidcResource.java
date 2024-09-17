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
import alpine.model.MappedOidcGroup;
import alpine.model.OidcGroup;
import alpine.model.Team;
import alpine.server.auth.AuthenticationNotRequired;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import alpine.server.util.OidcUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
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
import org.dependencytrack.resources.v1.vo.MappedOidcGroupRequest;
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
import java.util.stream.Collectors;

/**
 * JAX-RS resources for processing OpenID Connect group mapping requests.
 *
 * @since 4.0.0
 */
@Path("/v1/oidc")
@Tag(name = "oidc")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class OidcResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(OidcResource.class);

    @GET
    @Path("/available")
    @Produces(MediaType.TEXT_PLAIN)
    @Operation(summary = "Indicates if OpenID Connect is available for this application")
    @ApiResponse(
            responseCode = "200",
            description = "Whether OpenID Connect is available",
            content = @Content(schema = @Schema(type = "boolean"))
    )
    @AuthenticationNotRequired
    public Response isAvailable() {
        return Response.ok(OidcUtil.isOidcAvailable()).build();
    }

    @GET
    @Path("/group")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all groups",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all groups",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = OidcGroup.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response retrieveGroups() {
        try (QueryManager qm = new QueryManager()) {
            final List<OidcGroup> oidcGroups = qm.getOidcGroups();
            return Response.ok(oidcGroups).build();
        }
    }

    @PUT
    @Path("/group")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates group",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created group",
                    content = @Content(schema = @Schema(implementation = OidcGroup.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response createGroup(final OidcGroup jsonGroup) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonGroup, "name")
        );

        try (QueryManager qm = new QueryManager()) {
            if (qm.getOidcGroup(jsonGroup.getName()) == null) {
                final OidcGroup group = qm.createOidcGroup(jsonGroup.getName());
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Group created: " + group.getName());
                return Response.status(Response.Status.CREATED).entity(group).build();
            } else {
                return Response.status(Response.Status.CONFLICT).entity("A group with the same name already exists. Cannot create new group").build();
            }
        }
    }

    @POST
    @Path("/group")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates group",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated group",
                    content = @Content(schema = @Schema(implementation = OidcGroup.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response updateGroup(final OidcGroup jsonGroup) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonGroup, "uuid"),
                validator.validateProperty(jsonGroup, "name")
        );

        try (QueryManager qm = new QueryManager()) {
            OidcGroup oidcGroup = qm.getObjectByUuid(OidcGroup.class, jsonGroup.getUuid());
            if (oidcGroup != null) {
                oidcGroup.setName(jsonGroup.getName());
                oidcGroup = qm.updateOidcGroup(oidcGroup);
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Group updated: " + oidcGroup.getName());
                return Response.ok(oidcGroup).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("An OpenID Connect group with the specified UUID does not exists.").build();
            }
        }
    }

    @DELETE
    @Path("/group/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a group",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Group removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The group could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response deleteGroup(@Parameter(description = "The UUID of the group to delete", schema = @Schema(type = "string", format = "uuid"), required = true)
                                @PathParam("uuid") @ValidUuid final String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final OidcGroup group = qm.getObjectByUuid(OidcGroup.class, uuid);
            if (group != null) {
                qm.delete(qm.getMappedOidcGroups(group));
                qm.delete(group);
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Group deleted: " + group.getName());
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("An OpenID Connect group with the specified UUID could not be found.").build();
            }
        }
    }

    @GET
    @Path("/group/{uuid}/team")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of teams associated with the specified group",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of teams associated with the specified group",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = Team.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the mapping could not be found"),
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response retrieveTeamsMappedToGroup(@Parameter(description = "The UUID of the mapping to retrieve the team for", schema = @Schema(type = "string", format = "uuid"), required = true)
                                               @PathParam("uuid") @ValidUuid final String uuid) {
        try (final QueryManager qm = new QueryManager()) {
            final OidcGroup oidcGroup = qm.getObjectByUuid(OidcGroup.class, uuid);
            if (oidcGroup != null) {
                final List<Team> teams = qm.getMappedOidcGroups(oidcGroup).stream()
                        .map(MappedOidcGroup::getTeam)
                        .map(team -> qm.detach(Team.class, team.getId()))
                        .collect(Collectors.toList());
                return Response.ok(teams).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("A mapping with the specified UUID could not be found.").build();
            }
        }
    }

    @PUT
    @Path("/mapping")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Adds a mapping",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The created mapping",
                    content = @Content(schema = @Schema(implementation = MappedOidcGroup.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the team or group could not be found"),
            @ApiResponse(responseCode = "409", description = "A mapping with the same team and group name already exists")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response addMapping(final MappedOidcGroupRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(request, "team"),
                validator.validateProperty(request, "group")
        );

        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.getObjectByUuid(Team.class, request.getTeam());
            if (team == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("A team with the specified UUID could not be found.").build();
            }

            final OidcGroup group = qm.getObjectByUuid(OidcGroup.class, request.getGroup());
            if (group == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("A group with the specified UUID could not be found.").build();
            }

            if (!qm.isOidcGroupMapped(team, group)) {
                final MappedOidcGroup mappedOidcGroup = qm.createMappedOidcGroup(team, group);
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Mapping created for group " + group.getName() + " and team " + team.getName());
                return Response.ok(mappedOidcGroup).build();
            } else {
                return Response.status(Response.Status.CONFLICT).entity("A mapping for the same team and group already exists.").build();
            }
        }
    }

    @DELETE
    @Path("/mapping/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a mapping",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Mapping removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the mapping could not be found"),
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response deleteMappingByUuid(@Parameter(description = "The UUID of the mapping to delete", schema = @Schema(type = "string", format = "uuid"), required = true)
                                        @PathParam("uuid") @ValidUuid final String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final MappedOidcGroup mapping = qm.getObjectByUuid(MappedOidcGroup.class, uuid);
            if (mapping != null) {
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Mapping for group " + mapping.getGroup().getName() + " and team " + mapping.getTeam().getName() + " deleted");
                qm.delete(mapping);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the mapping could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/group/{groupUuid}/team/{teamUuid}/mapping")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a mapping",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Mapping removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the mapping could not be found"),
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response deleteMapping(@Parameter(description = "The UUID of the group to delete a mapping for", schema = @Schema(type = "string", format = "uuid"), required = true)
                                  @PathParam("groupUuid") @ValidUuid final String groupUuid,
                                  @Parameter(description = "The UUID of the team to delete a mapping for", schema = @Schema(type = "string", format = "uuid"), required = true)
                                  @PathParam("teamUuid") @ValidUuid final String teamUuid) {
        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.getObjectByUuid(Team.class, teamUuid);
            if (team == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the team could not be found.").build();
            }

            final OidcGroup group = qm.getObjectByUuid(OidcGroup.class, groupUuid);
            if (group == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the group could not be found.").build();
            }

            final MappedOidcGroup mapping = qm.getMappedOidcGroup(team, group);
            if (mapping != null) {
                qm.delete(mapping);
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Mapping for group " + group.getName() + " and team " + team.getName() + " deleted");
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("A mapping for the group " + group.getName() + " and team " + team.getName() + " does not exist.").build();
            }
        }
    }

}
