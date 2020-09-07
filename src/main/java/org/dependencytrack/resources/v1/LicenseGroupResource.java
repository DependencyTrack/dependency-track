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
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.ResponseHeader;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.persistence.QueryManager;
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
import java.util.List;

/**
 * JAX-RS resources for processing license groups.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
@Path("/v1/licenseGroup")
@Api(value = "licenseGroup", authorizations = @Authorization(value = "X-Api-Key"))
public class LicenseGroupResource extends AlpineResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all license groups",
            response = LicenseGroup.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of license groups")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
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
    @ApiOperation(
            value = "Returns a specific license group",
            response = License.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The license group could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response getLicenseGroup(
            @ApiParam(value = "The UUID of the license group to retrieve", required = true)
            @PathParam("uuid") String uuid) {
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
    @ApiOperation(
            value = "Creates a new license group",
            response = LicenseGroup.class,
            code = 201
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 409, message = "A license group with the specified name already exists")
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
    @ApiOperation(
            value = "Updates a license group",
            response = LicenseGroup.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The license group could not be found")
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
    @ApiOperation(
            value = "Deletes a license group",
            code = 204
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the license group could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response deleteLicenseGroup(
            @ApiParam(value = "The UUID of the license group to delete", required = true)
            @PathParam("uuid") String uuid) {
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
    @ApiOperation(
            value = "Adds the license to the specified license group.",
            response = LicenseGroup.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 304, message = "The license group already has the specified license assigned"),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The license group or license could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response addLicenseToLicenseGroup(
            @ApiParam(value = "A valid license group", required = true)
            @PathParam("uuid") String uuid,
            @ApiParam(value = "A valid license", required = true)
            @PathParam("licenseUuid") String licenseUuid) {
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
    @ApiOperation(
            value = "Removes the license from the license group.",
            response = LicenseGroup.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 304, message = "The license is not a member with the license group"),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The license group or license could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response removeLicenseFromLicenseGroup(
            @ApiParam(value = "A valid license group", required = true)
            @PathParam("uuid") String uuid,
            @ApiParam(value = "A valid license", required = true)
            @PathParam("licenseUuid") String licenseUuid) {
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
