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

import alpine.persistence.PaginatedResult;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.ResponseHeader;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.License;
import org.dependencytrack.persistence.QueryManager;

import javax.validation.Validator;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.DELETE;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.List;
import alpine.common.logging.Logger;

/**
 * JAX-RS resources for processing licenses.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/license")
@Api(value = "license", authorizations = @Authorization(value = "X-Api-Key"))
public class LicenseResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(LicenseResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all licenses with complete metadata for each license",
            response = License.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of licenses")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
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
    @ApiOperation(
            value = "Returns a concise listing of all licenses",
            response = License.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
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
    @ApiOperation(
            value = "Returns a specific license",
            response = License.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The license could not be found")
    })
    public Response getLicense(
            @ApiParam(value = "The SPDX License ID of the license to retrieve", required = true)
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
    @ApiOperation(
            value = "Creates a new custom license",
            response = License.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 409, message = "A license with the specified ID already exists.")
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
    @ApiOperation(
            value = "Deletes a custom license",
            code = 204
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The license could not be found"),
            @ApiResponse(code = 409, message = "Only custom licenses can be deleted.")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response deleteLicense(
            @ApiParam(value = "The SPDX License ID of the license to delete", required = true)
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
