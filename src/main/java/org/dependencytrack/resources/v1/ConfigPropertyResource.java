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
import alpine.server.auth.PermissionRequired;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.QueryManager;

import jakarta.validation.Validator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;

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

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all ConfigProperties for the specified groupName",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all ConfigProperties for the specified groupName",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ConfigProperty.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response getConfigProperties() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final List<ConfigProperty> configProperties = qm.getConfigProperties();
            // Detaches the objects and closes the persistence manager so that if/when encrypted string
            // values are replaced by the placeholder, they are not erroneously persisted to the database.
            qm.getPersistenceManager().detachCopyAll(configProperties);
            qm.close();
            for (final ConfigProperty configProperty: configProperties) {
                // Replace the value of encrypted strings with the pre-defined placeholder
                if (ConfigProperty.PropertyType.ENCRYPTEDSTRING == configProperty.getPropertyType()) {
                    configProperty.setPropertyValue(ENCRYPTED_PLACEHOLDER);
                }
            }
            return Response.ok(configProperties).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates a config property",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated config property",
                    content = @Content(schema = @Schema(implementation = ConfigProperty.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The config property could not be found"),
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response updateConfigProperty(ConfigProperty json) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(json, "groupName"),
                validator.validateProperty(json, "propertyName"),
                validator.validateProperty(json, "propertyValue")
        );
        try (QueryManager qm = new QueryManager()) {
            final ConfigProperty property = qm.getConfigProperty(json.getGroupName(), json.getPropertyName());
            return updatePropertyValue(qm, json, property);
        }
    }

    @POST
    @Path("aggregate")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates an array of config properties",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated config properties",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ConfigProperty.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "One or more config properties could not be found"),
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response updateConfigProperty(List<ConfigProperty> list) {
        final Validator validator = super.getValidator();
        for (ConfigProperty item: list) {
            failOnValidationError(
                    validator.validateProperty(item, "groupName"),
                    validator.validateProperty(item, "propertyName"),
                    validator.validateProperty(item, "propertyValue")
            );
        }
        List<Object> returnList = new ArrayList<>();
        try (QueryManager qm = new QueryManager()) {
            for (ConfigProperty item : list) {
                final ConfigProperty property = qm.getConfigProperty(item.getGroupName(), item.getPropertyName());
                returnList.add(updatePropertyValue(qm, item, property).getEntity());
            }
        }
        return Response.ok(returnList).build();
    }


}
