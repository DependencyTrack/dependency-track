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

import alpine.auth.AuthenticationNotRequired;
import alpine.auth.Authenticator;
import alpine.auth.JsonWebToken;
import alpine.auth.KeyManager;
import alpine.auth.PermissionRequired;
import alpine.logging.Logger;
import alpine.model.LdapUser;
import alpine.model.Team;
import alpine.resources.AlpineResource;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencytrack.auth.Permission;
import org.owasp.dependencytrack.model.IdentifiableObject;
import org.owasp.dependencytrack.persistence.QueryManager;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.owasp.security.logging.SecurityMarkers;
import javax.naming.AuthenticationException;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.Principal;
import java.util.List;

@Path("/v1/user")
@Api(value = "user")
public class UserResource extends AlpineResource {

    private static final Logger logger = Logger.getLogger(UserResource.class);

    @POST
    @Path("login")
    @Produces(MediaType.TEXT_PLAIN)
    @ApiOperation(
            value = "Assert login credentials",
            notes = "Upon a successful login, a JSON Web Token will be returned in the response body. This functionality requires authentication to be enabled.",
            response = String.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Success"),
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @AuthenticationNotRequired
    public Response validateCredentials(@FormParam("username") String username, @FormParam("password") String password) {
        Authenticator auth = new Authenticator(username, password);
        try {
            Principal principal = auth.authenticate();
            if (principal != null) {
                KeyManager km = KeyManager.getInstance();
                JsonWebToken jwt = new JsonWebToken(km.getSecretKey());
                String token = jwt.createToken(principal);
                return Response.ok(token).build();
            }
        } catch (AuthenticationException e) {
        }
        logger.warn(SecurityMarkers.SECURITY_AUDIT, "Unauthorized login attempt (username: " + username +
                " / ip address: " + super.getRemoteAddress() + " / agent: " + super.getUserAgent() + ")");
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all users",
            notes = "Requires 'manage users' permission.",
            response = LdapUser.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Success"),
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permission.MANAGE_USERS)
    public Response getUsers() {
        try (QueryManager qm = new QueryManager()) {
            List<LdapUser> users = qm.getLdapUsers();
            return Response.ok(users).build();
        }
    }

    @GET
    @Path("/self")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns information about the current logged in user.",
            response = LdapUser.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Success"),
    })
    public Response getSelf() {
        try (QueryManager qm = new QueryManager()) {
            LdapUser user = qm.getLdapUser(getPrincipal().getName());
            return Response.ok(user).build();
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Creates a new user that references an existing LDAP object.",
            notes = "Requires 'manage users' permission.",
            response = LdapUser.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 201, message = "Success"),
            @ApiResponse(code = 400, message = "Username cannot be null or blank."),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 409, message = "A user with the same username already exists. Cannot create new user")
    })
    @PermissionRequired(Permission.MANAGE_USERS)
    public Response createLdapUser(LdapUser jsonUser) {
        try (QueryManager qm = new QueryManager()) {
            if (StringUtils.isBlank(jsonUser.getUsername())) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Username cannot be null or blank.").build();
            }
            LdapUser user = qm.getLdapUser(jsonUser.getUsername());
            if (user == null) {
                user = qm.createLdapUser(jsonUser.getUsername());
                return Response.status(Response.Status.CREATED).entity(user).build();
            } else {
                return Response.status(Response.Status.CONFLICT).entity("A user with the same username already exists. Cannot create new user.").build();
            }
        }
    }

    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Deletes a user.",
            notes = "Requires 'manage users' permission."
    )
    @ApiResponses(value = {
            @ApiResponse(code = 204, message = "Success"),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The user could not be found")
    })
    @PermissionRequired(Permission.MANAGE_USERS)
    public Response deleteLdapUser(LdapUser jsonUser) {
        try (QueryManager qm = new QueryManager()) {
            LdapUser user = qm.getLdapUser(jsonUser.getUsername());
            if (user != null) {
                qm.delete(user);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The user could not be found.").build();
            }
        }
    }

    @POST
    @Path("/{username}/membership")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Adds the username to the specified team.",
            notes = "Requires 'manage users' and 'manage teams' permission.",
            response = LdapUser.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Success"),
            @ApiResponse(code = 304, message = "The user is already a member of the specified team"),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The user or team could not be found")
    })
    @PermissionRequired({Permission.MANAGE_USERS, Permission.MANAGE_TEAMS})
    public Response addTeamToUser(
            @ApiParam(value = "A valid username", required = true)
            @PathParam("username") String username,
            @ApiParam(value = "The UUID of the team to associate username with", required = true)
                    IdentifiableObject identifiableObject) {
        try (QueryManager qm = new QueryManager()) {
            LdapUser user = qm.getLdapUser(username);
            Team team = qm.getObjectByUuid(Team.class, identifiableObject.getUuid());
            if (user == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The user could not be found.").build();
            }
            if (team == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The team could not be found.").build();
            }
            boolean modified = qm.addUserToTeam(user, team);
            user = qm.getObjectById(LdapUser.class, user.getId());
            if (modified) {
                return Response.ok(user).build();
            } else {
                return Response.status(Response.Status.NOT_MODIFIED).entity("The user is already a member of the specified team.").build();
            }
        }
    }

    @DELETE
    @Path("/{username}/membership")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Removes the username from the specified team.",
            notes = "Requires 'manage users' and 'manage teams' permission.",
            response = LdapUser.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Success"),
            @ApiResponse(code = 304, message = "The user was not a member of the specified team"),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The user or team could not be found")
    })
    @PermissionRequired({Permission.MANAGE_USERS, Permission.MANAGE_TEAMS})
    public Response removeTeamFromUser(
            @ApiParam(value = "A valid username", required = true)
            @PathParam("username") String username,
            @ApiParam(value = "The UUID of the team to un-associate username from", required = true)
                    IdentifiableObject identifiableObject) {
        try (QueryManager qm = new QueryManager()) {
            LdapUser user = qm.getLdapUser(username);
            Team team = qm.getObjectByUuid(Team.class, identifiableObject.getUuid());
            if (user == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The user could not be found.").build();
            }
            if (team == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The team could not be found.").build();
            }
            boolean modified = qm.removeUserFromTeam(user, team);
            user = qm.getObjectById(LdapUser.class, user.getId());
            if (modified) {
                return Response.ok(user).build();
            } else {
                return Response.status(Response.Status.NOT_MODIFIED).entity("The user was not a member of the specified team.").build();
            }
        }
    }

}
