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
import alpine.model.MappedLdapGroup;
import alpine.model.Team;
import alpine.server.auth.LdapConnectionWrapper;
import alpine.server.auth.PermissionRequired;
import alpine.server.cache.CacheManager;
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
import org.dependencytrack.resources.v1.vo.MappedLdapGroupRequest;

import jakarta.validation.Validator;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import javax.naming.NamingException;
import javax.naming.SizeLimitExceededException;
import javax.naming.directory.DirContext;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JAX-RS resources for processing LDAP group mapping requests.
 *
 * @author Steve Springett
 * @since 3.3.0
 */
@Path("/v1/ldap")
@Tag(name = "ldap")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class LdapResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(LdapResource.class);

    @GET
    @Path("/groups")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns the DNs of all accessible groups within the directory",
            description = """
                    <p>
                      This API performs a pass-through query to the configured LDAP server.
                      Search criteria results are cached using default Alpine CacheManager policy.
                    <p>
                    <p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"""
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "DNs of all accessible groups within the directory",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of ldap groups that match the specified search criteria", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(type = "string")))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response retrieveLdapGroups () {
        if (!LdapConnectionWrapper.LDAP_CONFIGURED) {
            return Response.ok().build();
        }
        if (getAlpineRequest().getFilter() == null) {
            return Response.status(Response.Status.NO_CONTENT).build();
        }
        List<String> groups = CacheManager.getInstance().get(ArrayList.class, "ldap-group-search:" + getAlpineRequest().getFilter());
        if (groups == null) {
            final LdapConnectionWrapper ldap = new LdapConnectionWrapper();
            DirContext dirContext = null;
            try {
                dirContext = ldap.createDirContext();
                groups = ldap.searchForGroupName(dirContext, getAlpineRequest().getFilter());
                CacheManager.getInstance().put("ldap-group-search:" + getAlpineRequest().getFilter(), groups);
            } catch (SizeLimitExceededException e) {
                LOGGER.warn("The LDAP server did not return results from the specified search criteria as the result list would have exceeded the size limit specified by the LDAP server");
                return Response.status(Response.Status.NO_CONTENT).build();
            } catch (NamingException e) {
                LOGGER.error("An error occurred attempting to retrieve a list of groups from the configured LDAP server", e);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
            } finally {
                ldap.closeQuietly(dirContext);
            }
        }
        final List<String> result = groups.stream()
                .skip(getAlpineRequest().getPagination().getOffset())
                .limit(getAlpineRequest().getPagination().getLimit())
                .collect(Collectors.toList());
        return Response.ok(result).header(TOTAL_COUNT_HEADER, groups.size()).build();
    }

    @GET
    @Path("/team/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns the DNs of all groups mapped to the specified team",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "DNs of all groups mapped to the specified team",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = MappedLdapGroup.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the team could not be found"),
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response retrieveLdapGroups (@Parameter(description = "The UUID of the team to retrieve mappings for", schema = @Schema(type = "string", format = "uuid"), required = true)
                                        @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.getObjectByUuid(Team.class, uuid);
            if (team != null) {
                final List<MappedLdapGroup> mappings = qm.getMappedLdapGroups(team);
                return Response.ok(mappings).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the team could not be found.").build();
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
                    content = @Content(schema = @Schema(implementation = MappedLdapGroup.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the team could not be found"),
            @ApiResponse(responseCode = "409", description = "A mapping with the same team and dn already exists")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response addMapping(MappedLdapGroupRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(request, "team"),
                validator.validateProperty(request, "dn")
        );
        try (QueryManager qm = new QueryManager()) {
            final Team team = qm.getObjectByUuid(Team.class, request.getTeam());
            if (team != null) {
                if (!qm.isMapped(team, request.getDn())) {
                    final MappedLdapGroup mapping = qm.createMappedLdapGroup(team, request.getDn());
                    return Response.ok(mapping).build();
                } else {
                    return Response.status(Response.Status.CONFLICT).entity("A mapping with the same team and dn already exists.").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the team could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/mapping/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Removes a mapping",
            description = "<p>Requires permission <strong>ACCESS_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Mapping removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the mapping could not be found"),
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response deleteMapping(
            @Parameter(description = "The UUID of the mapping to delete", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final MappedLdapGroup mapping = qm.getObjectByUuid(MappedLdapGroup.class, uuid);
            if (mapping != null) {
                qm.delete(mapping);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the mapping could not be found.").build();
            }
        }
    }
}
