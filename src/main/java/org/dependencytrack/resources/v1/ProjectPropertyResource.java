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
import alpine.logging.Logger;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectProperty;
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
 * JAX-RS resources for processing ProjectProperties
 *
 * @author Steve Springett
 * @since 3.4.0
 */
@Path("/v1/project/{uuid}/property")
@Api(value = "projectProperty", authorizations = @Authorization(value = "X-Api-Key"))
public class ProjectPropertyResource extends AbstractConfigPropertyResource {

    private static final Logger LOGGER = Logger.getLogger(ProjectPropertyResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all ProjectProperties for the specified project",
            response = ProjectProperty.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response getProperties(
            @ApiParam(value = "The UUID of the project to retrieve properties for", required = true)
            @PathParam("uuid") String uuid) {
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
    @ApiOperation(
            value = "Creates a new project property",
            response = ProjectProperty.class,
            code = 201
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The project could not be found"),
            @ApiResponse(code = 409, message = "A property with the specified project/group/name combination already exists")
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response createProperty(
            @ApiParam(value = "The UUID of the project to create a property for", required = true)
            @PathParam("uuid") String uuid,
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
    @ApiOperation(
            value = "Updates a project property",
            response = ProjectProperty.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The project could not be found"),
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response updateProperty(
            @ApiParam(value = "The UUID of the project to create a property for", required = true)
            @PathParam("uuid") String uuid,
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
    @ApiOperation(
            value = "Deletes a config property",
            response = ProjectProperty.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The project or project property could not be found"),
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response deleteProperty(
            @ApiParam(value = "The UUID of the project to delete a property from", required = true)
            @PathParam("uuid") String uuid,
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
