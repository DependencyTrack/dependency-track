package org.dependencytrack.resources.v1;

import alpine.auth.AuthenticationNotRequired;
import alpine.auth.PermissionRequired;
import alpine.model.MappedOidcGroup;
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

import javax.validation.Validator;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.List;

/**
 * JAX-RS resources for processing OpenID Connect group mapping requests.
 *
 * @since 3.9.0
 */
@Path("/v1/oidc")
@Api(value = "oidc", authorizations = @Authorization(value = "X-Api-Key"))
public class OidcResource extends AlpineResource {

    @GET
    @Path("/available")
    @Produces(MediaType.APPLICATION_JSON)
    @AuthenticationNotRequired
    public Response isAvailable() {
        return Response.ok(OidcUtil.isOidcAvailable()).build();
    }

    @GET
    @Path("/team/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns the group names of all groups mapped to the specified team",
            response = String.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the team could not be found"),
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response retrieveOidcGroups(@ApiParam(value = "The UUID of the team to retrieve mappings for", required = true)
                                       @PathParam("uuid") String uuid) {
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

    @PUT
    @Path("/mapping")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Adds a mapping",
            response = MappedOidcGroup.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the team could not be found"),
            @ApiResponse(code = 409, message = "A mapping with the same team and group name already exists")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response addMapping(MappedOidcGroupRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(request, "team"),
                validator.validateProperty(request, "groupName")
        );

        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.getObjectByUuid(Team.class, request.getTeam());

            if (team != null) {
                if (!qm.isOidcGroupMapped(team, request.getGroup())) {
                    return Response.ok(qm.createMappedOidcGroup(team, request.getGroup())).build();
                } else {
                    return Response.status(Response.Status.CONFLICT).entity("A mapping with the same team and groupName already exists.").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the team could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/mapping/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Removes a mapping",
            response = MappedOidcGroup.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the mapping could not be found"),
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response deleteMapping(@ApiParam(value = "The UUID of the mapping to delete", required = true)
                                  @PathParam("uuid") String uuid) {
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

}
