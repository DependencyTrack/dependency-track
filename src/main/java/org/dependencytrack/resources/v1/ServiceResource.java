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
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
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

/**
 * JAX-RS resources for processing services.
 *
 * @author Steve Springett
 * @since 4.2.0
 */
@Path("/v1/service")
@Tag(name = "service")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class ServiceResource extends AlpineResource {

    @GET
    @Path("/project/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all services for a given project",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all services for a given project",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of services", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ServiceComponent.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getAllServices(@Parameter(description = "The UUID of the project", schema = @Schema(type = "string", format = "uuid"), required = true)
                                   @PathParam("uuid") @ValidUuid String uuid) {
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
    @Operation(
            summary = "Returns a specific service",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A specific service",
                    content = @Content(schema = @Schema(implementation = ServiceComponent.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified service is forbidden"),
            @ApiResponse(responseCode = "404", description = "The service could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getServiceByUuid(
            @Parameter(description = "The UUID of the service to retrieve", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
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
    @Operation(
            summary = "Creates a new service",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created service",
                    content = @Content(schema = @Schema(implementation = ServiceComponent.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response createService(@Parameter(description = "The UUID of the project", schema = @Schema(type = "string", format = "uuid"), required = true)
                                  @PathParam("uuid") @ValidUuid String uuid, ServiceComponent jsonService) {
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
    @Operation(
            summary = "Updates a service",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated service",
                    content = @Content(schema = @Schema(implementation = ServiceComponent.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified service is forbidden"),
            @ApiResponse(responseCode = "404", description = "The UUID of the service could not be found"),
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
    @Operation(
            summary = "Deletes a service",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Service removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified service is forbidden"),
            @ApiResponse(responseCode = "404", description = "The UUID of the service could not be found")
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response deleteService(
            @Parameter(description = "The UUID of the service to delete", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
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
