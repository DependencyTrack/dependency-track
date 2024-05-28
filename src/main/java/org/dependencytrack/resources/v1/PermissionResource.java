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
import alpine.model.Permission;
import alpine.model.Team;
import alpine.model.UserPrincipal;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
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
import org.owasp.security.logging.SecurityMarkers;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;

/**
 * JAX-RS resources for processing permissions.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/permission")
@Tag(name = "permission")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class PermissionResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(PermissionResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all permissions",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all permissions",
                    content = @Content(schema = @Schema(implementation = Permissions.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response getAllPermissions() {
        try (QueryManager qm = new QueryManager()) {
            final List<Permission> permissions = qm.getPermissions();
            return Response.ok(permissions).build();
        }
    }

    @POST
    @Path("/{permission}/user/{username}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Adds the permission to the specified username.",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated user",
                    content = @Content(schema = @Schema(implementation = UserPrincipal.class))
            ),
            @ApiResponse(responseCode = "304", description = "The user already has the specified permission assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The user could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response addPermissionToUser(
            @Parameter(description = "A valid username", required = true)
            @PathParam("username") String username,
            @Parameter(description = "A valid permission", required = true)
            @PathParam("permission") String permissionName) {
        try (QueryManager qm = new QueryManager()) {
            UserPrincipal principal = qm.getUserPrincipal(username);
            if (principal == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The user could not be found.").build();
            }
            final Permission permission = qm.getPermission(permissionName);
            if (permission == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The permission could not be found.").build();
            }
            final List<Permission> permissions = principal.getPermissions();
            if (permissions != null && !permissions.contains(permission)) {
                permissions.add(permission);
                principal.setPermissions(permissions);
                principal = qm.persist(principal);
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Added permission for user: " + principal.getName() + " / permission: " + permission.getName());
                return Response.ok(principal).build();
            }
            return Response.status(Response.Status.NOT_MODIFIED).build();
        }
    }

    @DELETE
    @Path("/{permission}/user/{username}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Removes the permission from the user.",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated user",
                    content = @Content(schema = @Schema(implementation = UserPrincipal.class))
            ),
            @ApiResponse(responseCode = "304", description = "The user already has the specified permission assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The user could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response removePermissionFromUser(
            @Parameter(description = "A valid username", required = true)
            @PathParam("username") String username,
            @Parameter(description = "A valid permission", required = true)
            @PathParam("permission") String permissionName) {
        try (QueryManager qm = new QueryManager()) {
            UserPrincipal principal = qm.getUserPrincipal(username);
            if (principal == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The user could not be found.").build();
            }
            final Permission permission = qm.getPermission(permissionName);
            if (permission == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The permission could not be found.").build();
            }
            final List<Permission> permissions = principal.getPermissions();
            if (permissions != null && permissions.contains(permission)) {
                permissions.remove(permission);
                principal.setPermissions(permissions);
                principal = qm.persist(principal);
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Removed permission for user: " + principal.getName() + " / permission: " + permission.getName());
                return Response.ok(principal).build();
            }
            return Response.status(Response.Status.NOT_MODIFIED).build();
        }
    }

    @POST
    @Path("/{permission}/team/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Adds the permission to the specified team.",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated team",
                    content = @Content(schema = @Schema(implementation = Team.class))
            ),
            @ApiResponse(responseCode = "304", description = "The team already has the specified permission assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The team could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response addPermissionToTeam(
            @Parameter(description = "A valid team uuid", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "A valid permission", required = true)
            @PathParam("permission") String permissionName) {
        try (QueryManager qm = new QueryManager()) {
            Team team = qm.getObjectByUuid(Team.class, uuid);
            if (team == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The team could not be found.").build();
            }
            final Permission permission = qm.getPermission(permissionName);
            if (permission == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The permission could not be found.").build();
            }
            final List<Permission> permissions = team.getPermissions();
            if (permissions != null && !permissions.contains(permission)) {
                permissions.add(permission);
                team.setPermissions(permissions);
                team = qm.persist(team);
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Added permission for team: " + team.getName() + " / permission: " + permission.getName());
                return Response.ok(team).build();
            }
            return Response.status(Response.Status.NOT_MODIFIED).build();
        }
    }

    @DELETE
    @Path("/{permission}/team/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Removes the permission from the team.",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated team",
                    content = @Content(schema = @Schema(implementation = Team.class))
            ),
            @ApiResponse(responseCode = "304", description = "The team already has the specified permission assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The team could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response removePermissionFromTeam(
            @Parameter(description = "A valid team uuid", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "A valid permission", required = true)
            @PathParam("permission") String permissionName) {
        try (QueryManager qm = new QueryManager()) {
            Team team = qm.getObjectByUuid(Team.class, uuid);
            if (team == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The team could not be found.").build();
            }
            final Permission permission = qm.getPermission(permissionName);
            if (permission == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The permission could not be found.").build();
            }
            final List<Permission> permissions = team.getPermissions();
            if (permissions != null && permissions.contains(permission)) {
                permissions.remove(permission);
                team.setPermissions(permissions);
                team = qm.persist(team);
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Removed permission for team: " + team.getName() + " / permission: " + permission.getName());
                return Response.ok(team).build();
            }
            return Response.status(Response.Status.NOT_MODIFIED).build();
        }
    }
}
