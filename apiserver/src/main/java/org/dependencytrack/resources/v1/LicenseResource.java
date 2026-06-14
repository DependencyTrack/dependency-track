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
import jakarta.validation.Validator;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.License;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;
import org.dependencytrack.resources.v1.vo.ConciseLicenseResponse;
import org.dependencytrack.resources.v1.vo.CreateLicenseRequest;
import org.dependencytrack.resources.v1.vo.LicenseResponse;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
public class LicenseResource extends AbstractApiResource {

    private static final Logger LOGGER = LoggerFactory.getLogger(LicenseResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all licenses with complete metadata for each license"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all licenses with complete metadata for each license",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of licenses", schema = @Schema(format = "integeger")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = LicenseResponse.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public Response getLicenses() {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getLicenses();
            final List<LicenseResponse> responses =
                    result.getList(License.class).stream()
                            .map(LicenseResponse::of)
                            .toList();

            return Response
                    .ok(responses)
                    .header(TOTAL_COUNT_HEADER, result.getTotal())
                    .build();
        }
    }

    @GET
    @Path("/concise")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a concise listing of all licenses"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A concise listing of all licenses",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of licenses", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ConciseLicenseResponse.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public Response getLicenseListing() {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final List<License> result = qm.getAllLicensesConcise();
            return Response
                    .ok(result.stream().map(ConciseLicenseResponse::of).toList())
                    .build();
        }
    }

    @GET
    @Path("/{licenseId}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a specific license"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A specific license",
                    content = @Content(schema = @Schema(implementation = LicenseResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The license could not be found")
    })
    public Response getLicense(
            @Parameter(description = "The SPDX License ID of the license to retrieve", required = true)
            @PathParam("licenseId") String licenseId) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final License license = qm.getLicense(licenseId);
            if (license != null) {
                return Response
                        .ok(LicenseResponse.of(license))
                        .build();
            } else {
                return Response
                        .status(Response.Status.NOT_FOUND)
                        .entity("The license could not be found.")
                        .build();
            }
        }
    }

    @PUT
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new custom license",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_CREATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created license",
                    content = @Content(schema = @Schema(implementation = LicenseResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "A license with the specified ID already exists.")
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_CREATE
    })
    public Response createLicense(CreateLicenseRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(request, "name"),
                validator.validateProperty(request, "licenseId")
        );

        try (final var qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                final License existing = qm.getLicense(request.licenseId());
                if (existing != null) {
                    return Response
                            .status(Response.Status.CONFLICT)
                            .entity("A license with the specified licenseId already exists.")
                            .build();
                }

                final License license = qm.createCustomLicense(convert(request), true);
                LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Created license {}", license.getName());

                return Response
                        .status(Response.Status.CREATED)
                        .entity(LicenseResponse.of(license))
                        .build();
            });
        }
    }

    @DELETE
    @Path("/{licenseId}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a custom license",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "License removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The license could not be found"),
            @ApiResponse(responseCode = "409", description = "Only custom licenses can be deleted.")
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_DELETE
    })
    public Response deleteLicense(
            @Parameter(description = "The SPDX License ID of the license to delete", required = true)
            @PathParam("licenseId") String licenseId) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                final License license = qm.getLicense(licenseId);
                if (license != null) {
                    if (Boolean.TRUE.equals(license.isCustomLicense())) {
                        final String licenseName = license.getName();
                        qm.deleteLicense(license, true);
                        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Deleted license {}", licenseName);
                        return Response.status(Response.Status.NO_CONTENT).build();
                    } else {
                        return Response
                                .status(Response.Status.CONFLICT)
                                .entity("Only custom licenses can be deleted.")
                                .build();
                    }
                } else {
                    return Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The license could not be found.")
                            .build();
                }
            });
        }
    }

    private static License convert(CreateLicenseRequest request) {
        final License license = new License();
        license.setName(request.name());
        license.setLicenseId(request.licenseId());
        license.setText(request.licenseText());
        license.setHeader(request.standardLicenseHeader());
        license.setTemplate(request.standardLicenseTemplate());
        license.setComment(request.licenseComments());
        if (request.seeAlso() != null) {
            license.setSeeAlso(request.seeAlso().toArray(String[]::new));
        }
        if (request.isOsiApproved() != null) {
            license.setOsiApproved(request.isOsiApproved());
        }
        if (request.isFsfLibre() != null) {
            license.setFsfLibre(request.isFsfLibre());
        }
        if (request.isDeprecatedLicenseId() != null) {
            license.setDeprecatedLicenseId(request.isDeprecatedLicenseId());
        }

        return license;
    }

}
