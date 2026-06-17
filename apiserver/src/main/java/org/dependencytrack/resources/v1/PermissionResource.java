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

import alpine.model.Permission;
import alpine.model.Team;
import alpine.model.User;
import alpine.server.auth.PermissionRequired;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
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
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.vo.TeamPermissionsSetRequest;
import org.dependencytrack.resources.v1.vo.UserPermissionsSetRequest;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jdo.Query;
import java.util.List;
import java.util.Map;

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
public class PermissionResource extends AbstractApiResource {

    private static final Logger LOGGER = LoggerFactory.getLogger(PermissionResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all permissions",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_READ</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all permissions",
                    content = @Content(schema = @Schema(implementation = Permissions.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_READ})
    public Response getAllPermissions() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
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
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated user",
                    content = @Content(schema = @Schema(implementation = User.class))
            ),
            @ApiResponse(responseCode = "304", description = "The user already has the specified permission assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The user could not be found")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE})
    public Response addPermissionToUser(
            @Parameter(description = "A valid username", required = true)
            @PathParam("username") String username,
            @Parameter(description = "A valid permission", required = true)
            @PathParam("permission") String permissionName) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                User principal = qm.getUser(username);
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
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Added permission for user: " + principal.getUsername() + " / permission: " + permission.getName());
                    return Response.ok(principal).build();
                }
                return Response.status(Response.Status.NOT_MODIFIED).build();
            });
        }
    }

    @DELETE
    @Path("/{permission}/user/{username}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Removes the permission from the user.",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated user",
                    content = @Content(schema = @Schema(implementation = User.class))
            ),
            @ApiResponse(responseCode = "304", description = "The user already has the specified permission assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The user could not be found")
    })
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_DELETE})
    public Response removePermissionFromUser(
            @Parameter(description = "A valid username", required = true)
            @PathParam("username") String username,
            @Parameter(description = "A valid permission", required = true)
            @PathParam("permission") String permissionName) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                User principal = qm.getUser(username);
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
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Removed permission for user: " + principal.getUsername() + " / permission: " + permission.getName());
                    return Response.ok(principal).build();
                }
                return Response.status(Response.Status.NOT_MODIFIED).build();
            });
        }
    }

    @POST
    @Path("/{permission}/team/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_UPDATE</strong></p>"
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
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE})
    public Response addPermissionToTeam(
            @Parameter(description = "A valid team uuid", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "A valid permission", required = true)
            @PathParam("permission") String permissionName) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
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
            });
        }
    }

    @DELETE
    @Path("/{permission}/team/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_DELETE</strong></p>"
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
    @PermissionRequired({Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_DELETE})
    public Response removePermissionFromTeam(
            @Parameter(description = "A valid team uuid", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "A valid permission", required = true)
            @PathParam("permission") String permissionName) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                Team team = qm.getObjectByUuid(Team.class, uuid, Team.FetchGroup.ALL.name());
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
            });
        }
    }

    @PUT
    @Path("/user")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
        summary = "Replaces a users's permissions with the specified list",
        description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The updated user", content = @Content(schema = @Schema(implementation = User.class))),
            @ApiResponse(responseCode = "304", description = "The user is already has the specified permission(s)"),
            @ApiResponse(responseCode = "400", description = "Bad request"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The user could not be found")
    })
    @PermissionRequired({ Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE })
    public Response setUserPermissions(
            @Parameter(description = "A username and valid list permission") @Valid UserPermissionsSetRequest request) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                User user = qm.getUser(request.username());
                if (user == null)
                    return Response.status(Response.Status.NOT_FOUND).entity("The user could not be found.").build();

                List<String> permissionNames = request.permissions()
                        .stream()
                        .map(Permissions::name)
                        .toList();

                final Query<Permission> query = qm.getPersistenceManager().newQuery(Permission.class)
                        .filter(":permissions.contains(name)")
                        .setNamedParameters(Map.of("permissions", permissionNames))
                        .orderBy("name asc");

                final List<Permission> requestedPermissions;
                try {
                    requestedPermissions = List.copyOf(query.executeList());
                } finally {
                    query.closeAll();
                }

                if (user.getPermissions().equals(requestedPermissions))
                    return Response.notModified()
                            .entity("User already has selected permission(s).")
                            .build();

                user.setPermissions(requestedPermissions);
                user = qm.persist(user);
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT,
                        "Set permissions for user: %s / permissions: %s"
                                .formatted(user.getUsername(), permissionNames));

                return Response.ok(user).build();
            });
        }
    }

    @PUT
    @Path("/team")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
        summary = "Replaces a team's permissions with the specified list",
        description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong> or <strong>ACCESS_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The updated team", content = @Content(schema = @Schema(implementation = Team.class))),
            @ApiResponse(responseCode = "304", description = "The team already has the specified permission(s)"),
            @ApiResponse(responseCode = "400", description = "Bad request"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The team could not be found")
    })
    @PermissionRequired({ Permissions.Constants.ACCESS_MANAGEMENT, Permissions.Constants.ACCESS_MANAGEMENT_UPDATE })
    public Response setTeamPermissions(@Parameter(description = "Team UUID and requested permissions") @Valid TeamPermissionsSetRequest request) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                Team team = qm.getObjectByUuid(Team.class, request.team(), Team.FetchGroup.ALL.name());
                if (team == null)
                    return Response.status(Response.Status.NOT_FOUND).entity("The team could not be found.").build();

                List<String> permissionNames = request.permissions()
                        .stream()
                        .map(Permissions::name)
                        .toList();

                final Query<Permission> query = qm.getPersistenceManager().newQuery(Permission.class)
                        .filter(":permissions.contains(name)")
                        .setNamedParameters(Map.of("permissions", permissionNames))
                        .orderBy("name asc");

                final List<Permission> requestedPermissions;
                try {
                    requestedPermissions = List.copyOf(query.executeList());
                } finally {
                    query.closeAll();
                }

                if (team.getPermissions().equals(requestedPermissions))
                    return Response.notModified().entity("Team already has selected permission(s).").build();

                team.setPermissions(requestedPermissions);
                team = qm.persist(team);

                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT,
                        "Set permissions for team: %s / permissions: %s"
                                .formatted(team.getName(), permissionNames));
                return Response.ok(team).build();
            });
        }
    }
}
