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

import alpine.model.ConfigProperty;
import alpine.server.auth.AuthenticationNotRequired;
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
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.ConfigPropertyVisibility;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.vo.ConfigPropertyResponse;
import org.dependencytrack.resources.v1.vo.UpdateConfigPropertyRequest;
import org.dependencytrack.secret.management.SecretManager;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * JAX-RS resources for processing ConfigProperties
 *
 * @author Steve Springett
 * @since 3.2.0
 */
@Path("/v1/configProperty")
@Tag(name = "configProperty")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class ConfigPropertyResource extends AbstractConfigPropertyResource {

    @Inject
    ConfigPropertyResource(SecretManager secretManager) {
        super(secretManager);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all ConfigProperties for the specified groupName",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_READ</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all ConfigProperties for the specified groupName",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ConfigPropertyResponse.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getConfigProperties() {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final List<ConfigProperty> configProperties = qm.getConfigProperties();
            final List<ConfigPropertyResponse> response =
                    configProperties.stream()
                            .map(ConfigPropertyResponse::of)
                            .toList();
            return Response.ok(response).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Updates a config property",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated config property",
                    content = @Content(schema = @Schema(implementation = ConfigPropertyResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The config property could not be found"),
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE
    })
    public Response updateConfigProperty(UpdateConfigPropertyRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(request, "groupName"),
                validator.validateProperty(request, "propertyName"),
                validator.validateProperty(request, "propertyValue")
        );

        try (final var qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> applyUpdate(qm, request));
        }
    }

    @POST
    @Path("aggregate")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates an array of config properties",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = """
                            The updated config properties. \
                            Each array element is either a successfully updated `ConfigPropertyResponse`, \
                            or an error message string if the entry's property could not be found, \
                            is read-only, or its requested value is invalid.\
                            """,
                    content = @Content(array = @ArraySchema(schema = @Schema(anyOf = {ConfigPropertyResponse.class, String.class})))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE
    })
    public Response updateConfigProperty(List<UpdateConfigPropertyRequest> requests) {
        final Validator validator = super.getValidator();
        for (final UpdateConfigPropertyRequest item : requests) {
            failOnValidationError(
                    validator.validateProperty(item, "groupName"),
                    validator.validateProperty(item, "propertyName"),
                    validator.validateProperty(item, "propertyValue")
            );
        }

        final var returnList = new ArrayList<>();
        try (final var qm = new QueryManager(getAlpineRequest())) {
            qm.runInTransaction(() -> {
                for (final UpdateConfigPropertyRequest request : requests) {
                    final Response itemResponse = applyUpdate(qm, request);
                    returnList.add(itemResponse.getEntity());
                }
            });
        }

        return Response.ok(returnList).build();
    }

    @GET
    @Path("/public/{groupName}/{propertyName}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns a public ConfigProperty", description = "<p></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Public ConfigProperty returned", content = @Content(schema = @Schema(implementation = ConfigPropertyResponse.class))),
            @ApiResponse(responseCode = "403", description = "This is not a public visible ConfigProperty"),
            @ApiResponse(responseCode = "404", description = "The config property could not be found")
    })
    @AuthenticationNotRequired
    public Response getPublicConfigProperty(
            @Parameter(description = "The group name of the value to retrieve", required = true)
            @PathParam("groupName") String groupName,
            @Parameter(description = "The property name of the value to retrieve", required = true)
            @PathParam("propertyName") String propertyName) {
        return getClassifiedConfigProperty(
                groupName,
                propertyName,
                EnumSet.of(ConfigPropertyVisibility.PUBLIC));
    }

    @GET
    @Path("/internal/{groupName}/{propertyName}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns an internal ConfigProperty",
            description = """
                    <p>
                      Requires authentication, but no permission.
                      Returns both internal and public properties
                    </p>"""
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The internal config property",
                    content = @Content(schema = @Schema(implementation = ConfigPropertyResponse.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Not an internal- or public-readable config property"),
            @ApiResponse(responseCode = "404", description = "The config property could not be found")
    })
    public Response getInternalConfigProperty(
            @Parameter(description = "The group name of the value to retrieve", required = true)
            @PathParam("groupName") String groupName,
            @Parameter(description = "The property name of the value to retrieve", required = true)
            @PathParam("propertyName") String propertyName) {
        return getClassifiedConfigProperty(
                groupName,
                propertyName,
                EnumSet.of(
                        ConfigPropertyVisibility.PUBLIC,
                        ConfigPropertyVisibility.INTERNAL));
    }

    private Response getClassifiedConfigProperty(
            String groupName,
            String propertyName,
            Set<ConfigPropertyVisibility> allowedVisibilities) {
        final var lookup = new ConfigProperty();
        lookup.setGroupName(groupName);
        lookup.setPropertyName(propertyName);

        final var wellKnownProperty = ConfigPropertyConstants.ofProperty(lookup);
        if (wellKnownProperty == null || !allowedVisibilities.contains(wellKnownProperty.getVisibility())) {
            return Response.status(Response.Status.FORBIDDEN).build();
        }

        try (final var qm = new QueryManager(getAlpineRequest())) {
            final ConfigProperty property = qm.getConfigProperty(groupName, propertyName);
            if (property == null) {
                return Response
                        .status(Response.Status.NOT_FOUND)
                        .entity("The config property could not be found.")
                        .build();
            }

            return Response.ok(ConfigPropertyResponse.of(property)).build();
        }
    }

    private Response applyUpdate(QueryManager qm, UpdateConfigPropertyRequest request) {
        final ConfigProperty property = qm.getConfigProperty(request.groupName(), request.propertyName());
        if (property == null) {
            return Response
                    .status(Response.Status.NOT_FOUND)
                    .entity("The config property could not be found.")
                    .build();
        }

        final Response validationError = applyPropertyValue(request.propertyValue(), property);
        if (validationError != null) {
            return validationError;
        }

        return Response.ok(ConfigPropertyResponse.of(property)).build();
    }

}
