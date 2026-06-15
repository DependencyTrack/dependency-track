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
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentProperty;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.ComponentPropertyResponse;
import org.dependencytrack.resources.v1.vo.CreateComponentPropertyRequest;
import org.dependencytrack.secret.management.SecretManager;

import java.util.List;
import java.util.UUID;

/**
 * @since 4.11.0
 */
@Path("/v1/component/{uuid}/property")
@Tag(name = "componentProperty")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class ComponentPropertyResource extends AbstractConfigPropertyResource {

    @Inject
    ComponentPropertyResource(SecretManager secretManager) {
        super(secretManager);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all properties for the specified component",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all properties for the specified component",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ComponentPropertyResponse.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProperties(
            @Parameter(description = "The UUID of the component to retrieve properties for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component != null) {
                requireAccess(qm, component.getProject());
                final List<ComponentProperty> properties = qm.getComponentProperties(component);
                return Response
                        .ok(properties.stream().map(ComponentPropertyResponse::of).toList())
                        .build();
            } else {
                return Response
                        .status(Response.Status.NOT_FOUND)
                        .entity("The component could not be found.")
                        .build();
            }
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new component property",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_CREATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created component",
                    content = @Content(schema = @Schema(implementation = ComponentPropertyResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The component could not be found"),
            @ApiResponse(responseCode = "409", description = "A property with the specified component/group/name combination already exists")
    })
    @PermissionRequired({
            Permissions.Constants.PORTFOLIO_MANAGEMENT,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_CREATE
    })
    public Response createProperty(
            @Parameter(description = "The UUID of the component to create a property for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            CreateComponentPropertyRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(request, "groupName"),
                validator.validateProperty(request, "propertyName"),
                validator.validateProperty(request, "propertyValue"),
                validator.validateProperty(request, "propertyType")
        );
        try (final var qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                final Component component = qm.getObjectByUuid(Component.class, uuid);
                if (component == null) {
                    return Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The component could not be found.")
                            .build();
                }
                requireAccess(qm, component.getProject());

                final List<ComponentProperty> existingProperties = qm.getComponentProperties(
                        component, request.groupName(), request.propertyName());
                final var requestedIdentity = new ComponentProperty.Identity(
                        request.groupName(), request.propertyName(), request.propertyValue());
                final boolean isDuplicate = existingProperties.stream()
                        .map(ComponentProperty.Identity::new)
                        .anyMatch(requestedIdentity::equals);
                if (!existingProperties.isEmpty() && isDuplicate) {
                    return Response
                            .status(Response.Status.CONFLICT)
                            .entity("A property with the specified component/group/name/value combination already exists.")
                            .build();
                }

                final ComponentProperty property = qm.createComponentProperty(
                        component,
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
                        .entity(ComponentPropertyResponse.of(property))
                        .build();
            });
        }
    }

    @DELETE
    @Path("/{propertyUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a config property",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Property removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The component or component property could not be found"),
    })
    @PermissionRequired({
            Permissions.Constants.PORTFOLIO_MANAGEMENT,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_DELETE
    })
    public Response deleteProperty(
            @Parameter(description = "The UUID of the component to delete a property from", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid final String componentUuid,
            @Parameter(description = "The UUID of the component property to delete", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("propertyUuid") @ValidUuid final String propertyUuid) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                final Component component = qm.getObjectByUuid(Component.class, componentUuid);
                if (component != null) {
                    requireAccess(qm, component.getProject());
                    final long propertiesDeleted = qm.deleteComponentPropertyByUuid(
                            component, UUID.fromString(propertyUuid));
                    if (propertiesDeleted > 0) {
                        return Response
                                .status(Response.Status.NO_CONTENT)
                                .build();
                    } else {
                        return Response
                                .status(Response.Status.NOT_FOUND)
                                .entity("The component property could not be found.")
                                .build();
                    }
                } else {
                    return Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The component could not be found.")
                            .build();
                }
            });
        }
    }

}
