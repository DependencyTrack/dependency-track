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
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentProperty;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;

import javax.validation.Validator;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.UUID;

/**
 * @since 4.11.0
 */
@Path("/v1/component/{uuid}/property")
@Api(value = "componentProperty", authorizations = @Authorization(value = "X-Api-Key"))
public class ComponentPropertyResource extends AbstractConfigPropertyResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all ComponentProperties for the specified component",
            response = ComponentProperty.class,
            responseContainer = "List",
            notes = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified project is forbidden"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProperties(
            @ApiParam(value = "The UUID of the component to retrieve properties for", format = "uuid", required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component != null) {
                if (qm.hasAccess(super.getPrincipal(), component.getProject())) {
                    final List<ComponentProperty> properties = qm.getComponentProperties(component);
                    // Detaches the objects and closes the persistence manager so that if/when encrypted string
                    // values are replaced by the placeholder, they are not erroneously persisted to the database.
                    qm.getPersistenceManager().detachCopyAll(properties);
                    qm.close();
                    for (final ComponentProperty property : properties) {
                        // Replace the value of encrypted strings with the pre-defined placeholder
                        if (ComponentProperty.PropertyType.ENCRYPTEDSTRING == property.getPropertyType()) {
                            property.setPropertyValue(ENCRYPTED_PLACEHOLDER);
                        }
                    }
                    return Response.ok(properties).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Creates a new component property",
            response = ComponentProperty.class,
            code = 201,
            notes = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified component is forbidden"),
            @ApiResponse(code = 404, message = "The component could not be found"),
            @ApiResponse(code = 409, message = "A property with the specified component/group/name combination already exists")
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response createProperty(
            @ApiParam(value = "The UUID of the component to create a property for", format = "uuid", required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            ComponentProperty json) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(json, "groupName"),
                validator.validateProperty(json, "propertyName"),
                validator.validateProperty(json, "propertyValue"),
                validator.validateProperty(json, "propertyType")
        );
        try (QueryManager qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component != null) {
                if (qm.hasAccess(super.getPrincipal(), component.getProject())) {
                    final List<ComponentProperty> existingProperties = qm.getComponentProperties(component,
                            StringUtils.trimToNull(json.getGroupName()), StringUtils.trimToNull(json.getPropertyName()));
                    final var jsonPropertyIdentity = new ComponentProperty.Identity(json);
                    final boolean isDuplicate = existingProperties.stream()
                            .map(ComponentProperty.Identity::new)
                            .anyMatch(jsonPropertyIdentity::equals);
                    if (existingProperties.isEmpty() || !isDuplicate) {
                        final ComponentProperty property = qm.createComponentProperty(component,
                                StringUtils.trimToNull(json.getGroupName()),
                                StringUtils.trimToNull(json.getPropertyName()),
                                null, // Set value to null - this will be taken care of by updatePropertyValue below
                                json.getPropertyType(),
                                StringUtils.trimToNull(json.getDescription()));
                        updatePropertyValue(qm, json, property);
                        return Response.status(Response.Status.CREATED).entity(property).build();
                    } else {
                        return Response.status(Response.Status.CONFLICT).entity("A property with the specified component/group/name/value combination already exists.").build();
                    }
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified component is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/{propertyUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Deletes a config property",
            response = ComponentProperty.class,
            notes = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to the specified component is forbidden"),
            @ApiResponse(code = 404, message = "The component or component property could not be found"),
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response deleteProperty(
            @ApiParam(value = "The UUID of the component to delete a property from", format = "uuid", required = true)
            @PathParam("uuid") @ValidUuid final String componentUuid,
            @ApiParam(value = "The UUID of the component property to delete", format = "uuid", required = true)
            @PathParam("propertyUuid") @ValidUuid final String propertyUuid) {
        try (QueryManager qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, componentUuid);
            if (component != null) {
                if (qm.hasAccess(super.getPrincipal(), component.getProject())) {
                    final long propertiesDeleted = qm.deleteComponentPropertyByUuid(component, UUID.fromString(propertyUuid));
                    if (propertiesDeleted > 0) {
                        return Response.status(Response.Status.NO_CONTENT).build();
                    } else {
                        return Response.status(Response.Status.NOT_FOUND).entity("The component property could not be found.").build();
                    }
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified component is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
        }
    }
}