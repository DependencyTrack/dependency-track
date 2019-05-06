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
import alpine.model.Permission;
import alpine.model.Team;
import alpine.model.UserPrincipal;
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.QueryManager;
import org.owasp.security.logging.SecurityMarkers;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.List;

/**
 * JAX-RS resources for processing permissions.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/permission")
@Api(value = "permission", authorizations = @Authorization(value = "X-Api-Key"))
public class PermissionResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(PermissionResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all permissions",
            response = alpine.model.Permission.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
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
    @ApiOperation(
            value = "Adds the permission to the specified username.",
            response = UserPrincipal.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 304, message = "The user already has the specified permission assigned"),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The user could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response addPermissionToUser(
            @ApiParam(value = "A valid username", required = true)
            @PathParam("username") String username,
            @ApiParam(value = "A valid permission", required = true)
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
    @ApiOperation(
            value = "Removes the permission from the user.",
            response = UserPrincipal.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 304, message = "The user already has the specified permission assigned"),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The user could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response removePermissionFromUser(
            @ApiParam(value = "A valid username", required = true)
            @PathParam("username") String username,
            @ApiParam(value = "A valid permission", required = true)
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
    @ApiOperation(
            value = "Adds the permission to the specified username.",
            notes = "Requires 'manage users' permission.",
            response = Team.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 304, message = "The team already has the specified permission assigned"),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The team could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response addPermissionToTeam(
            @ApiParam(value = "A valid team uuid", required = true)
            @PathParam("uuid") String uuid,
            @ApiParam(value = "A valid permission", required = true)
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
    @ApiOperation(
            value = "Removes the permission from the team.",
            response = Team.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 304, message = "The team already has the specified permission assigned"),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The team could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response removePermissionFromTeam(
            @ApiParam(value = "A valid team uuid", required = true)
            @PathParam("uuid") String uuid,
            @ApiParam(value = "A valid permission", required = true)
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
