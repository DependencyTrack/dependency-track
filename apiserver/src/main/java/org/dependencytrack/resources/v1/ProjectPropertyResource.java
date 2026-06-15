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

import alpine.server.auth.PermissionRequired;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.inject.Inject;
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
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.CreateProjectPropertyRequest;
import org.dependencytrack.resources.v1.vo.DeleteProjectPropertyRequest;
import org.dependencytrack.resources.v1.vo.ProjectPropertyResponse;
import org.dependencytrack.resources.v1.vo.UpdateProjectPropertyRequest;
import org.dependencytrack.secret.management.SecretManager;

import java.util.List;

/**
 * JAX-RS resources for processing ProjectProperties
 *
 * @author Steve Springett
 * @since 3.4.0
 */
@Path("/v1/project/{uuid}/property")
@Tag(name = "projectProperty")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class ProjectPropertyResource extends AbstractConfigPropertyResource {

    @Inject
    ProjectPropertyResource(SecretManager secretManager) {
        super(secretManager);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all ProjectProperties for the specified project",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_READ</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all ProjectProperties for the specified project",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ProjectPropertyResponse.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired({
            Permissions.Constants.PORTFOLIO_MANAGEMENT,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_READ
    })
    public Response getProperties(
            @Parameter(description = "The UUID of the project to retrieve properties for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                requireAccess(qm, project);
                final List<ProjectProperty> properties = qm.getProjectProperties(project);
                return Response
                        .ok(properties.stream().map(ProjectPropertyResponse::of).toList())
                        .build();
            } else {
                return Response
                        .status(Response.Status.NOT_FOUND)
                        .entity("The project could not be found.")
                        .build();
            }
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new project property",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_CREATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created project property",
                    content = @Content(schema = @Schema(implementation = ProjectPropertyResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found"),
            @ApiResponse(responseCode = "409", description = "A property with the specified project/group/name combination already exists")
    })
    @PermissionRequired({
            Permissions.Constants.PORTFOLIO_MANAGEMENT,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_CREATE
    })
    public Response createProperty(
            @Parameter(description = "The UUID of the project to create a property for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            CreateProjectPropertyRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(request, "groupName"),
                validator.validateProperty(request, "propertyName"),
                validator.validateProperty(request, "propertyValue"),
                validator.validateProperty(request, "propertyType")
        );
        try (final var qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                final Project project = qm.getObjectByUuid(Project.class, uuid);
                if (project == null) {
                    return Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The project could not be found.")
                            .build();
                }
                requireAccess(qm, project);

                final ProjectProperty existing = qm.getProjectProperty(project, request.groupName(), request.propertyName());
                if (existing != null) {
                    return Response
                            .status(Response.Status.CONFLICT)
                            .entity("A property with the specified project/group/name combination already exists.")
                            .build();
                }

                final ProjectProperty property = qm.createProjectProperty(project,
                        request.groupName(),
                        request.propertyName(),
                        null, // Set value to null - this will be taken care of by applyPropertyValue below
                        request.propertyType(),
                        request.description());

                final Response error = applyPropertyValue(request.propertyValue(), property);
                if (error != null) {
                    return error;
                }

                return Response
                        .status(Response.Status.CREATED)
                        .entity(ProjectPropertyResponse.of(property))
                        .build();
            });
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates a project property",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated project property",
                    content = @Content(schema = @Schema(implementation = ProjectPropertyResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found"),
    })
    @PermissionRequired({
            Permissions.Constants.PORTFOLIO_MANAGEMENT,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE
    })
    public Response updateProperty(
            @Parameter(description = "The UUID of the project to create a property for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            UpdateProjectPropertyRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(request, "groupName"),
                validator.validateProperty(request, "propertyName"),
                validator.validateProperty(request, "propertyValue")
        );
        try (final var qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                final Project project = qm.getObjectByUuid(Project.class, uuid);
                if (project == null) {
                    return Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The project could not be found.")
                            .build();
                }
                requireAccess(qm, project);

                final ProjectProperty property = qm.getProjectProperty(
                        project, request.groupName(), request.propertyName());
                if (property == null) {
                    return Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("A property with the specified project/group/name combination could not be found.")
                            .build();
                }

                final Response error = applyPropertyValue(request.propertyValue(), property);
                if (error != null) {
                    return error;
                }

                return Response
                        .ok(ProjectPropertyResponse.of(property))
                        .build();
            });
        }
    }

    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a config property",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Project property removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project or project property could not be found"),
    })
    @PermissionRequired({
            Permissions.Constants.PORTFOLIO_MANAGEMENT,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_DELETE
    })
    public Response deleteProperty(
            @Parameter(description = "The UUID of the project to delete a property from", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            DeleteProjectPropertyRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(request, "groupName"),
                validator.validateProperty(request, "propertyName")
        );
        try (final var qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                final Project project = qm.getObjectByUuid(Project.class, uuid);
                if (project == null) {
                    return Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The project could not be found.")
                            .build();
                }
                requireAccess(qm, project);

                final ProjectProperty property = qm.getProjectProperty(
                        project, request.groupName(), request.propertyName());
                if (property == null) {
                    return Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The project property could not be found.")
                            .build();
                }

                qm.delete(property);
                return Response
                        .status(Response.Status.NO_CONTENT)
                        .build();
            });
        }
    }

}
