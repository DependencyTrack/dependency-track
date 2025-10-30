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

import alpine.persistence.PaginatedResult;
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
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;

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

/**
 * JAX-RS resources for processing license groups.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
@Path("/v1/licenseGroup")
@Tag(name = "licenseGroup")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class LicenseGroupResource extends AlpineResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all license groups",
            description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all license groups",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of license groups", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = LicenseGroup.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response getLicenseGroups() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getLicenseGroups();
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @GET
    @Path("/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a specific license group",
            description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A specific license group",
                    content = @Content(schema = @Schema(implementation = LicenseGroup.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The license group could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response getLicenseGroup(
            @Parameter(description = "The UUID of the license group to retrieve", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final LicenseGroup licenseGroup = qm.getObjectByUuid(LicenseGroup.class, uuid);
            if (licenseGroup != null) {
                return Response.ok(licenseGroup).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The license group could not be found.").build();
            }
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new license group",
            description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created license group",
                    content = @Content(schema = @Schema(implementation = LicenseGroup.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "A license group with the specified name already exists")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response createLicenseGroup(LicenseGroup jsonLicenseGroup) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonLicenseGroup, "name")
        );

        try (QueryManager qm = new QueryManager()) {
            LicenseGroup licenseGroup = qm.getLicenseGroup(StringUtils.trimToNull(jsonLicenseGroup.getName()));
            if (licenseGroup == null) {
                licenseGroup = qm.createLicenseGroup(StringUtils.trimToNull(jsonLicenseGroup.getName()));
                return Response.status(Response.Status.CREATED).entity(licenseGroup).build();
            } else {
                return Response.status(Response.Status.CONFLICT).entity("A license group with the specified name already exists.").build();
            }
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates a license group",
            description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated license group",
                    content = @Content(schema = @Schema(implementation = LicenseGroup.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The license group could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response updateLicenseGroup(LicenseGroup jsonLicenseGroup) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonLicenseGroup, "name")
        );
        try (QueryManager qm = new QueryManager()) {
            LicenseGroup licenseGroup = qm.getObjectByUuid(LicenseGroup.class, jsonLicenseGroup.getUuid());
            if (licenseGroup != null) {
                licenseGroup.setName(jsonLicenseGroup.getName());
                licenseGroup = qm.persist(licenseGroup);
                return Response.ok(licenseGroup).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The license group could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a license group",
            description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "License group removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the license group could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response deleteLicenseGroup(
            @Parameter(description = "The UUID of the license group to delete", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final LicenseGroup licenseGroup = qm.getObjectByUuid(LicenseGroup.class, uuid);
            if (licenseGroup != null) {
                qm.delete(licenseGroup);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the license group could not be found.").build();
            }
        }
    }

    @POST
    @Path("/{uuid}/license/{licenseUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Adds the license to the specified license group.",
            description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated license group",
                    content = @Content(schema = @Schema(implementation = LicenseGroup.class))
            ),
            @ApiResponse(responseCode = "304", description = "The license group already has the specified license assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The license group or license could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response addLicenseToLicenseGroup(
            @Parameter(description = "A valid license group", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "A valid license", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("licenseUuid") @ValidUuid String licenseUuid) {
        try (QueryManager qm = new QueryManager()) {
            LicenseGroup licenseGroup = qm.getObjectByUuid(LicenseGroup.class, uuid);
            if (licenseGroup == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The license group could not be found.").build();
            }
            final License license = qm.getObjectByUuid(License.class, licenseUuid);
            if (license == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The license could not be found.").build();
            }
            final List<License> licenses = licenseGroup.getLicenses();
            if (licenses != null && !licenses.contains(license)) {
                licenses.add(license);
                licenseGroup.setLicenses(licenses);
                qm.persist(licenseGroup);
                return Response.ok(licenseGroup).build();
            }
            return Response.status(Response.Status.NOT_MODIFIED).build();
        }
    }

    @DELETE
    @Path("/{uuid}/license/{licenseUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Removes the license from the license group.",
            description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated license group",
                    content = @Content(schema = @Schema(implementation = LicenseGroup.class))
            ),
            @ApiResponse(responseCode = "304", description = "The license is not a member with the license group"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The license group or license could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response removeLicenseFromLicenseGroup(
            @Parameter(description = "A valid license group", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "A valid license", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("licenseUuid") @ValidUuid String licenseUuid) {
        try (QueryManager qm = new QueryManager()) {
            LicenseGroup licenseGroup = qm.getObjectByUuid(LicenseGroup.class, uuid);
            if (licenseGroup == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The license group could not be found.").build();
            }
            final License license = qm.getObjectByUuid(License.class, licenseUuid);
            if (license == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The license could not be found.").build();
            }
            final List<License> licenses = licenseGroup.getLicenses();
            if (licenses != null && licenses.contains(license)) {
                licenses.remove(license);
                licenseGroup.setLicenses(licenses);
                licenseGroup = qm.persist(licenseGroup);
                return Response.ok(licenseGroup).build();
            }
            return Response.status(Response.Status.NOT_MODIFIED).build();
        }
    }
}
