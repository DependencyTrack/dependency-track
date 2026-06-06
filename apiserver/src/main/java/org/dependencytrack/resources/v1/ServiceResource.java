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
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;
import org.dependencytrack.resources.v1.problems.ProblemDetails;

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
public
class ServiceResource extends AbstractApiResource {

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
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getAllServices(@Parameter(description = "The UUID of the project", schema = @Schema(type = "string", format = "uuid"), required = true)
                                   @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                requireAccess(qm, project);
                final PaginatedResult result = qm.getServiceComponents(project, true);
                return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
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
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The service could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getServiceByUuid(
            @Parameter(description = "The UUID of the service to retrieve", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final ServiceComponent service = qm.getObjectByUuid(ServiceComponent.class, uuid);
            if (service != null) {
                requireAccess(qm, service.getProject());
                final ServiceComponent detachedService = qm.detach(ServiceComponent.class, service.getId()); // TODO: Force project to be loaded. It should be anyway, but JDO seems to be having issues here.
                return Response.ok(detachedService).build();
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
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_CREATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created service",
                    content = @Content(schema = @Schema(implementation = ServiceComponent.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_CREATE})
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
            return qm.callInTransaction(() -> {
                final Project project = qm.getObjectByUuid(Project.class, uuid);
                if (project == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
                }
                requireAccess(qm, project);
                if (project.getCollectionLogic() != null) {
                    return Response.status(Response.Status.BAD_REQUEST)
                            .entity("A collection project cannot contain services.").build();
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
                service = qm.persist(service);
                return Response.status(Response.Status.CREATED).entity(service).build();
            });
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates a service",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated service",
                    content = @Content(schema = @Schema(implementation = ServiceComponent.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The UUID of the service could not be found"),
    })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE})
    public Response updateService(ServiceComponent jsonService) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonService, "name"),
                validator.validateProperty(jsonService, "version"),
                validator.validateProperty(jsonService, "group"),
                validator.validateProperty(jsonService, "description")
        );
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                ServiceComponent service = qm.getObjectByUuid(ServiceComponent.class, jsonService.getUuid());
                if (service != null) {
                    requireAccess(qm, service.getProject());
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
            });
        }
    }

    @DELETE
    @Path("/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a service",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Service removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The UUID of the service could not be found")
    })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_DELETE})
    public Response deleteService(
            @Parameter(description = "The UUID of the service to delete", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                final ServiceComponent service = qm.getObjectByUuid(ServiceComponent.class, uuid, ServiceComponent.FetchGroup.ALL.name());
                if (service != null) {
                    requireAccess(qm, service.getProject());
                    qm.delete(service);
                    return Response.status(Response.Status.NO_CONTENT).build();
                } else {
                    return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the service could not be found.").build();
                }
            });
        }
    }
}
