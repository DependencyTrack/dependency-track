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
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;

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

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all ProjectProperties for the specified project",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all ProjectProperties for the specified project",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ProjectProperty.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response getProperties(
            @Parameter(description = "The UUID of the project to retrieve properties for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    final List<ProjectProperty> properties = qm.getProjectProperties(project);
                    // Detaches the objects and closes the persistence manager so that if/when encrypted string
                    // values are replaced by the placeholder, they are not erroneously persisted to the database.
                    qm.getPersistenceManager().detachCopyAll(properties);
                    qm.close();
                    for (final ProjectProperty property: properties) {
                        // Replace the value of encrypted strings with the pre-defined placeholder
                        if (ProjectProperty.PropertyType.ENCRYPTEDSTRING == property.getPropertyType()) {
                            property.setPropertyValue(ENCRYPTED_PLACEHOLDER);
                        }
                    }
                    return Response.ok(properties).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new project property",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created project property",
                    content = @Content(schema = @Schema(implementation = ProjectProperty.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found"),
            @ApiResponse(responseCode = "409", description = "A property with the specified project/group/name combination already exists")
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response createProperty(
            @Parameter(description = "The UUID of the project to create a property for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            ProjectProperty json) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(json, "groupName"),
                validator.validateProperty(json, "propertyName"),
                validator.validateProperty(json, "propertyValue")
        );
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    final ProjectProperty existing = qm.getProjectProperty(project,
                            StringUtils.trimToNull(json.getGroupName()), StringUtils.trimToNull(json.getPropertyName()));
                    if (existing == null) {
                        final ProjectProperty property = qm.createProjectProperty(project,
                                StringUtils.trimToNull(json.getGroupName()),
                                StringUtils.trimToNull(json.getPropertyName()),
                                null, // Set value to null - this will be taken care of by updatePropertyValue below
                                json.getPropertyType(),
                                StringUtils.trimToNull(json.getDescription()));
                        updatePropertyValue(qm, json, property);
                        qm.getPersistenceManager().detachCopy(project);
                        qm.close();
                        if (ProjectProperty.PropertyType.ENCRYPTEDSTRING == property.getPropertyType()) {
                            property.setPropertyValue(ENCRYPTED_PLACEHOLDER);
                        }
                        return Response.status(Response.Status.CREATED).entity(property).build();
                    } else {
                        return Response.status(Response.Status.CONFLICT).entity("A property with the specified project/group/name combination already exists.").build();
                    }
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates a project property",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated project property",
                    content = @Content(schema = @Schema(implementation = ProjectProperty.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found"),
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response updateProperty(
            @Parameter(description = "The UUID of the project to create a property for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            ProjectProperty json) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(json, "groupName"),
                validator.validateProperty(json, "propertyName"),
                validator.validateProperty(json, "propertyValue")
        );
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    final ProjectProperty property = qm.getProjectProperty(project, json.getGroupName(), json.getPropertyName());
                    if (property != null) {
                        return updatePropertyValue(qm, json, property);
                    } else {
                        return Response.status(Response.Status.NOT_FOUND).entity("A property with the specified project/group/name combination could not be found.").build();
                    }
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a config property",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Project property removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project or project property could not be found"),
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response deleteProperty(
            @Parameter(description = "The UUID of the project to delete a property from", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            ProjectProperty json) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(json, "groupName"),
                validator.validateProperty(json, "propertyName")
        );
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    final ProjectProperty property = qm.getProjectProperty(project, json.getGroupName(), json.getPropertyName());
                    if (property != null) {
                        qm.delete(property);
                        return Response.status(Response.Status.NO_CONTENT).build();
                    } else {
                        return Response.status(Response.Status.NOT_FOUND).entity("The project property could not be found.").build();
                    }
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }
}
