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
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.jdbi.ComponentPropertyDao;
import org.dependencytrack.persistence.jdbi.ComponentPropertyDao.ComponentPropertyRow;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.ComponentPropertyResponse;
import org.dependencytrack.resources.v1.vo.CreateComponentPropertyRequest;
import org.dependencytrack.secret.management.SecretManager;

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

import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 4.11.0
 */
@Path("/v1/component/{uuid}/property")
@Tag(name = "componentProperty")
@SecurityRequirements({@SecurityRequirement(name = "ApiKeyAuth"), @SecurityRequirement(name = "BearerAuth")})
public class ComponentPropertyResource extends AbstractConfigPropertyResource {

    @Inject
    ComponentPropertyResource(SecretManager secretManager) {
        super(secretManager);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all properties for the specified component",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "A list of all properties for the specified component",
                        content =
                                @Content(
                                        array =
                                                @ArraySchema(
                                                        schema =
                                                                @Schema(
                                                                        implementation =
                                                                                ComponentPropertyResponse.class)))),
                @ApiResponse(responseCode = "401", description = "Unauthorized"),
                @ApiResponse(
                        responseCode = "403",
                        description = "Access to the requested project is forbidden",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
                @ApiResponse(
                        responseCode = "404",
                        description = "The component could not be found",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON))
            })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProperties(
            @Parameter(
                            description = "The UUID of the component to retrieve properties for",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @PathParam("uuid")
                    @ValidUuid
                    String uuid) {
        final UUID componentUuid = UUID.fromString(uuid);
        final List<ComponentPropertyRow> properties = withJdbiHandle(getAlpineRequest(), handle -> {
            requireComponentAccess(handle, componentUuid);
            return handle.attach(ComponentPropertyDao.class).getProperties(componentUuid);
        });
        return Response.ok(
                        properties.stream().map(ComponentPropertyResponse::of).toList())
                .build();
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new component property",
            description =
                    "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_CREATE</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "201",
                        description = "The created component",
                        content = @Content(schema = @Schema(implementation = ComponentPropertyResponse.class))),
                @ApiResponse(responseCode = "401", description = "Unauthorized"),
                @ApiResponse(
                        responseCode = "403",
                        description = "Access to the requested project is forbidden",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
                @ApiResponse(
                        responseCode = "404",
                        description = "The component could not be found",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
                @ApiResponse(
                        responseCode = "409",
                        description = "A property with the specified component/group/name combination already exists")
            })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_CREATE})
    public Response createProperty(
            @Parameter(
                            description = "The UUID of the component to create a property for",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @PathParam("uuid")
                    @ValidUuid
                    String uuid,
            CreateComponentPropertyRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(request, "groupName"),
                validator.validateProperty(request, "propertyName"),
                validator.validateProperty(request, "propertyValue"),
                validator.validateProperty(request, "propertyType"));
        final UUID componentUuid = UUID.fromString(uuid);
        return inJdbiTransaction(getAlpineRequest(), handle -> {
            requireComponentAccess(handle, componentUuid);

            final var property = new ComponentPropertyRow(
                    request.groupName(),
                    request.propertyName(),
                    normalizePropertyValue(
                            request.groupName(),
                            request.propertyName(),
                            request.propertyType(),
                            request.propertyValue()),
                    request.propertyType(),
                    request.description(),
                    UUID.randomUUID());
            if (!handle.attach(ComponentPropertyDao.class).createProperty(componentUuid, property)) {
                return Response.status(Response.Status.CONFLICT)
                        .entity("A property with the specified component/group/name/value combination already exists.")
                        .build();
            }

            return Response.status(Response.Status.CREATED)
                    .entity(ComponentPropertyResponse.of(property))
                    .build();
        });
    }

    @DELETE
    @Path("/{propertyUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a config property",
            description =
                    "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_DELETE</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(responseCode = "204", description = "Property removed successfully"),
                @ApiResponse(responseCode = "401", description = "Unauthorized"),
                @ApiResponse(
                        responseCode = "403",
                        description = "Access to the requested project is forbidden",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
                @ApiResponse(
                        responseCode = "404",
                        description = "The component or component property could not be found",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_DELETE})
    public Response deleteProperty(
            @Parameter(
                            description = "The UUID of the component to delete a property from",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @PathParam("uuid")
                    @ValidUuid
                    final String componentUuid,
            @Parameter(
                            description = "The UUID of the component property to delete",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @PathParam("propertyUuid")
                    @ValidUuid
                    final String propertyUuid) {
        final UUID parsedComponentUuid = UUID.fromString(componentUuid);
        return inJdbiTransaction(getAlpineRequest(), handle -> {
            requireComponentAccess(handle, parsedComponentUuid);

            final boolean deleted = handle.attach(ComponentPropertyDao.class)
                    .deleteProperty(parsedComponentUuid, UUID.fromString(propertyUuid));
            if (!deleted) {
                throw new NoSuchElementException("Component property could not be found");
            }

            return Response.status(Response.Status.NO_CONTENT).build();
        });
    }
}
