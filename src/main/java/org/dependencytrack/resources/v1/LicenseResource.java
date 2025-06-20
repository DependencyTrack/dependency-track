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
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.License;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;

import jakarta.validation.Validator;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;

/**
 * JAX-RS resources for processing licenses.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/license")
@Tag(name = "license")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class LicenseResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(LicenseResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a list of all licenses with complete metadata for each license")
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all licenses with complete metadata for each license",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of licenses", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = License.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public Response getLicenses() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getLicenses();
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @GET
    @Path("/concise")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a concise listing of all licenses")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A concise listing of all licenses",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of licenses", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = License.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public Response getLicenseListing() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final List<License> result = qm.getAllLicensesConcise();
            return Response.ok(result).build();
        }
    }

    @GET
    @Path("/{licenseId}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a specific license")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A specific license",
                    content = @Content(schema = @Schema(implementation = License.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The license could not be found")
    })
    public Response getLicense(
            @Parameter(description = "The SPDX License ID of the license to retrieve", required = true)
            @PathParam("licenseId") String licenseId) {
        try (QueryManager qm = new QueryManager()) {
            final License license = qm.getLicense(licenseId);
            if (license != null) {
                return Response.ok(license).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The license could not be found.").build();
            }
        }
    }

    @PUT
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new custom license",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created license",
                    content = @Content(schema = @Schema(implementation = License.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "A license with the specified ID already exists.")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response createLicense(License jsonLicense) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonLicense, "name"),
                validator.validateProperty(jsonLicense, "licenseId")
        );
        try (QueryManager qm = new QueryManager()) {
            License license = qm.getLicense(jsonLicense.getLicenseId());
            if (license == null){
                license = qm.createCustomLicense(jsonLicense, true);
                LOGGER.info("License " + license.getName() + " created by " + super.getPrincipal().getName());
                return Response.status(Response.Status.CREATED).entity(license).build();
            } else {
                return Response.status(Response.Status.CONFLICT).entity("A license with the specified name already exists.").build();
            }
        }
    }

    @DELETE
    @Path("/{licenseId}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a custom license",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "License removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The license could not be found"),
            @ApiResponse(responseCode = "409", description = "Only custom licenses can be deleted.")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response deleteLicense(
            @Parameter(description = "The SPDX License ID of the license to delete", required = true)
            @PathParam("licenseId") String licenseId) {
        try (QueryManager qm = new QueryManager()) {
            final License license = qm.getLicense(licenseId);
            if (license != null) {
                if (Boolean.TRUE.equals(license.isCustomLicense())) {
                    LOGGER.info("License " + license + " deletion request by " + super.getPrincipal().getName());
                    qm.deleteLicense(license, true);
                    return Response.status(Response.Status.NO_CONTENT).build();
                } else {
                    return Response.status(Response.Status.CONFLICT).entity("Only custom licenses can be deleted.").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The license could not be found.").build();
            }
        }
    }

}
