package org.dependencytrack.resources.v1;

import alpine.auth.AuthenticationNotRequired;
import alpine.auth.PermissionRequired;
import alpine.logging.Logger;
import alpine.model.MappedOidcGroup;
import alpine.model.OidcGroup;
import alpine.model.Team;
import alpine.resources.AlpineResource;
import alpine.util.OidcUtil;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.vo.MappedOidcGroupRequest;
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
import java.util.ArrayList;
import java.util.List;

/**
 * JAX-RS resources for processing OpenID Connect group mapping requests.
 *
 * @since 3.9.0
 */
@Path("/v1/oidc")
@Api(value = "oidc", authorizations = @Authorization(value = "X-Api-Key"))
public class OidcResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(OidcResource.class);

    @GET
    @Path("/available")
    @Produces(MediaType.TEXT_PLAIN)
    @ApiOperation(
            value = "Indicates if OpenID Connect is available for this application",
            response = Boolean.class
    )
    @AuthenticationNotRequired
    public Response isAvailable() {
        return Response.ok(OidcUtil.isOidcAvailable()).build();
    }

    @GET
    @Path("/group")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all OpenID Connect groups",
            response = OidcGroup.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response retrieveOidcGroups() {
        try (QueryManager qm = new QueryManager()) {
            final List<OidcGroup> oidcGroups = qm.getOidcGroups();
            return Response.ok(oidcGroups).build();
        }
    }

    @PUT
    @Path("/group")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Creates an OpenID Connect group",
            response = OidcGroup.class,
            code = 201
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response createOidcGroup(final OidcGroup oidcGroupRequest) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(oidcGroupRequest, "name")
        );

        try (QueryManager qm = new QueryManager()) {
            if (qm.getOidcGroup(oidcGroupRequest.getName()) == null) {
                final OidcGroup group = qm.createOidcGroup(oidcGroupRequest.getName());
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "OpenID Connect group created: " + group.getName());
                return Response.status(Response.Status.CREATED).entity(group).build();
            } else {
                return Response.status(Response.Status.CONFLICT).entity("An OpenID Connect group with the same name already exists. Cannot create new group").build();
            }
        }
    }

    @POST
    @Path("/group")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Updates an OpenID Connect group",
            response = OidcGroup.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response updateOidcGroup(final OidcGroup oidcGroupRequest) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(oidcGroupRequest, "uuid"),
                validator.validateProperty(oidcGroupRequest, "name")
        );

        try (QueryManager qm = new QueryManager()) {
            OidcGroup oidcGroup = qm.getObjectByUuid(OidcGroup.class, oidcGroupRequest.getUuid());
            if (oidcGroup != null) {
                oidcGroup.setName(oidcGroupRequest.getName());
                oidcGroup = qm.updateOidcGroup(oidcGroup);
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "OpenID Connect group updated: " + oidcGroup.getName());
                return Response.ok(oidcGroup).build();
            } else {
                return Response.status(Response.Status.CONFLICT).entity("An OpenID Connect group with the specified UUID does not exists.").build();
            }
        }
    }

    @DELETE
    @Path("/group/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Deletes an OpenID Connect group",
            code = 204
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The group could not be found")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response deleteOidcGroup(@ApiParam(value = "The UUID of the group to delete", required = true)
                                    @PathParam("uuid") final String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final OidcGroup group = qm.getObjectByUuid(OidcGroup.class, uuid);
            if (group != null) {
                qm.delete(qm.getMappedOidcGroups(group));
                qm.delete(group);
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "OpenID Connect group deleted: " + group.getName());
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The OpenID Connect group could not be found.").build();
            }
        }
    }

    @GET
    @Path("/team/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of mappings associated to the specified team",
            response = MappedOidcGroup.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the team could not be found"),
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response retrieveOidcGroupMappings(@ApiParam(value = "The UUID of the team to retrieve mappings for", required = true)
                                              @PathParam("uuid") final String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.getObjectByUuid(Team.class, uuid);
            if (team != null) {
                final List<MappedOidcGroup> mappings = qm.getMappedOidcGroups(team);
                return Response.ok(mappings).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the team could not be found.").build();
            }
        }
    }

    @GET
    @Path("/group/{uuid}/team")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of teams associated with the specified group",
            response = Team.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the mapping could not be found"),
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response retrieveTeamMappedByOidcGroupMapping(@ApiParam(value = "The UUID of the mapping to retrieve the team for", required = true)
                                                         @PathParam("uuid") final String uuid) {
        try (final QueryManager qm = new QueryManager()) {
            final OidcGroup oidcGroup = qm.getObjectByUuid(OidcGroup.class, uuid);
            if (oidcGroup != null) {
                final List<MappedOidcGroup> mappedOidcGroups = qm.getMappedOidcGroups(oidcGroup);
                final List<Team> teams = new ArrayList<>();
                for (final MappedOidcGroup mappedOidcGroup : mappedOidcGroups) {
                    // FIXME: This is a hack to force JDO to load the given fields as they're not part of the default fetch group
                    mappedOidcGroup.getTeam().getUuid();
                    mappedOidcGroup.getTeam().getName();

                    teams.add(mappedOidcGroup.getTeam());
                }
                return Response.ok(teams).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the mapping could not be found.").build();
            }
        }
    }

    @PUT
    @Path("/mapping")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Adds a mapping",
            response = MappedOidcGroup.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the team or group could not be found"),
            @ApiResponse(code = 409, message = "A mapping with the same team and group name already exists")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response addOidcGroupMapping(final MappedOidcGroupRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(request, "team"),
                validator.validateProperty(request, "group")
        );

        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.getObjectByUuid(Team.class, request.getTeam());
            if (team == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the team could not be found.").build();
            }

            final OidcGroup group = qm.getObjectByUuid(OidcGroup.class, request.getGroup());
            if (group == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the group could not be found.").build();
            }

            if (!qm.isOidcGroupMapped(team, group)) {
                return Response.ok(qm.createMappedOidcGroup(team, group)).build();
            } else {
                return Response.status(Response.Status.CONFLICT).entity("A mapping with the same team and groupName already exists.").build();
            }
        }
    }

    @DELETE
    @Path("/mapping/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Removes a mapping")
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the mapping could not be found"),
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response deleteOidcGroupMapping(@ApiParam(value = "The UUID of the mapping to delete", required = true)
                                           @PathParam("uuid") final String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final MappedOidcGroup mapping = qm.getObjectByUuid(MappedOidcGroup.class, uuid);
            if (mapping != null) {
                qm.delete(mapping);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the mapping could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/mapping")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Removes a mapping")
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the mapping could not be found"),
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response deleteOidcGroupMapping(final MappedOidcGroupRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(request, "team"),
                validator.validateProperty(request, "group")
        );

        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.getObjectByUuid(Team.class, request.getTeam());
            if (team == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the team could not be found.").build();
            }

            final OidcGroup group = qm.getObjectByUuid(OidcGroup.class, request.getGroup());
            if (group == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the group could not be found.").build();
            }

            final MappedOidcGroup mapping = qm.getMappedOidcGroup(team, group);
            if (mapping != null) {
                qm.delete(mapping);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the mapping could not be found.").build();
            }
        }
    }

}
