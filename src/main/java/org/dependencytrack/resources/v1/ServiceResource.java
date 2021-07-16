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
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
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

/**
 * JAX-RS resources for processing services.
 *
 * @author Steve Springett
 * @since 4.2.0
 */
@Path("/v1/service")
@Api(value = "service", authorizations = @Authorization(value = "X-Api-Key"))
public class ServiceResource extends AlpineResource {

    @GET
    @Path("/project/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all services for a given project",
            response = ServiceComponent.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of services")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getAllServices(@PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    final PaginatedResult result = qm.getServiceComponents(project, true);
                    return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a specific service",
            response = ServiceComponent.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified service is forbidden"),
            @ApiResponse(code = 404, message = "The service could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getServiceByUuid(
            @ApiParam(value = "The UUID of the service to retrieve", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final ServiceComponent service = qm.getObjectByUuid(ServiceComponent.class, uuid);
            if (service != null) {
                final Project project = service.getProject();
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    final ServiceComponent detachedService = qm.detach(ServiceComponent.class, service.getId()); // TODO: Force project to be loaded. It should be anyway, but JDO seems to be having issues here.
                    return Response.ok(detachedService).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified service is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The service could not be found.").build();
            }
        }
    }

    @PUT
    @Path("/project/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Creates a new service",
            response = ServiceComponent.class,
            code = 201
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response createService(@PathParam("uuid") String uuid, ServiceComponent jsonService) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonService, "name"),
                validator.validateProperty(jsonService, "version"),
                validator.validateProperty(jsonService, "group"),
                validator.validateProperty(jsonService, "description")
        );

        try (QueryManager qm = new QueryManager()) {
            ServiceComponent parent = null;
            if (jsonService.getParent() != null && jsonService.getParent().getUuid() != null) {
                parent = qm.getObjectByUuid(ServiceComponent.class, jsonService.getParent().getUuid());
            }
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            if (! qm.hasAccess(super.getPrincipal(), project)) {
                return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
            }
            ServiceComponent service = new ServiceComponent();
            service.setProject(project);
            service.setProvider(jsonService.getProvider());
            service.setGroup(StringUtils.trimToNull(jsonService.getGroup()));
            service.setName(StringUtils.trimToNull(jsonService.getName()));
            service.setVersion(StringUtils.trimToNull(jsonService.getVersion()));
            service.setDescription(StringUtils.trimToNull(jsonService.getDescription()));
            service.setEndpoints(jsonService.getEndpoints().clone());
            service.setAuthenticated(jsonService.getAuthenticated());
            service.setCrossesTrustBoundary(jsonService.getCrossesTrustBoundary());
            service.setData(jsonService.getData());
            service.setExternalReferences(jsonService.getExternalReferences());
            service = qm.createServiceComponent(service, true);
            return Response.status(Response.Status.CREATED).entity(service).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Updates a service",
            response = ServiceComponent.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified service is forbidden"),
            @ApiResponse(code = 404, message = "The UUID of the service could not be found"),
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response updateService(ServiceComponent jsonService) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonService, "name"),
                validator.validateProperty(jsonService, "version"),
                validator.validateProperty(jsonService, "group"),
                validator.validateProperty(jsonService, "description")
        );
        try (QueryManager qm = new QueryManager()) {
            ServiceComponent service = qm.getObjectByUuid(ServiceComponent.class, jsonService.getUuid());
            if (service != null) {
                if (! qm.hasAccess(super.getPrincipal(), service.getProject())) {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified service is forbidden").build();
                }
                // Name cannot be empty or null - prevent it
                final String name = StringUtils.trimToNull(jsonService.getName());
                if (name != null) {
                    service.setName(name);
                }
                service.setProvider(jsonService.getProvider());
                service.setGroup(StringUtils.trimToNull(jsonService.getGroup()));
                service.setVersion(StringUtils.trimToNull(jsonService.getVersion()));
                service.setDescription(StringUtils.trimToNull(jsonService.getDescription()));
                service.setEndpoints(jsonService.getEndpoints().clone());
                service.setAuthenticated(jsonService.getAuthenticated());
                service.setCrossesTrustBoundary(jsonService.getCrossesTrustBoundary());
                service.setData(jsonService.getData());
                service.setExternalReferences(jsonService.getExternalReferences());
                service = qm.updateServiceComponent(service, true);
                return Response.ok(service).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the service could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Deletes a service",
            code = 204
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified service is forbidden"),
            @ApiResponse(code = 404, message = "The UUID of the service could not be found")
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response deleteService(
            @ApiParam(value = "The UUID of the service to delete", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final ServiceComponent service = qm.getObjectByUuid(ServiceComponent.class, uuid, ServiceComponent.FetchGroup.ALL.name());
            if (service != null) {
                if (! qm.hasAccess(super.getPrincipal(), service.getProject())) {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified service is forbidden").build();
                }
                qm.recursivelyDelete(service, false);
                qm.commitSearchIndex(ServiceComponent.class);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the service could not be found.").build();
            }
        }
    }
}
