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

import alpine.common.logging.Logger;
import alpine.model.ConfigProperty;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.QueryManager;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.StringReader;

/**
 * JAX-RS resource for customization settings.
 * Provides endpoints for managing custom vulnerability ID generation settings.
 *
 * @since 4.13.0
 */
@Path("/v1/customization")
@Tag(name = "customization")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class CustomizationResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(CustomizationResource.class);

    private static final String VULN_ID_ORG_CODE = "vuln.id.orgCode";
    private static final String VULN_ID_TEMPLATE = "vuln.id.template";
    private static final String VULN_ID_RESET_POLICY = "vuln.id.resetPolicy";
    private static final String VULN_ID_SEQUENCE_PADDING = "vuln.id.sequencePadding";

    /**
     * Get custom vulnerability ID settings
     * Returns current configuration for vulnerability ID generation.
     *
     * @return Response containing vulnerability ID settings
     */
    @GET
    @Path("/vulnerability-id")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Get custom vulnerability ID settings",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Vulnerability ID settings retrieved successfully",
                    content = @Content(
                            mediaType = MediaType.APPLICATION_JSON,
                            schema = @Schema(
                                    type = "object",
                                    example = "{\"orgCode\": \"DT\", \"template\": \"{ORG_CODE}-{PROJECT_NAME}-{YYYY}-{SEQUENCE}\", \"resetPolicy\": \"YEARLY\", \"sequencePadding\": 5}"
                            )
                    )
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Forbidden"),
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION_READ)
    public Response getVulnerabilityIdSettings() {
        try (QueryManager qm = new QueryManager()) {
            final JsonObjectBuilder builder = Json.createObjectBuilder();

            final ConfigProperty orgCodeProp = qm.getConfigProperty(VULN_ID_ORG_CODE);
            builder.add("orgCode", orgCodeProp != null && orgCodeProp.getPropertyValue() != null
                    ? orgCodeProp.getPropertyValue() : "DT");

            final ConfigProperty templateProp = qm.getConfigProperty(VULN_ID_TEMPLATE);
            builder.add("template", templateProp != null && templateProp.getPropertyValue() != null
                    ? templateProp.getPropertyValue() : "{ORG_CODE}-{PROJECT_NAME}-{YYYY}-{SEQUENCE}");

            final ConfigProperty resetPolicyProp = qm.getConfigProperty(VULN_ID_RESET_POLICY);
            builder.add("resetPolicy", resetPolicyProp != null && resetPolicyProp.getPropertyValue() != null
                    ? resetPolicyProp.getPropertyValue() : "YEARLY");

            final ConfigProperty paddingProp = qm.getConfigProperty(VULN_ID_SEQUENCE_PADDING);
            int padding = 5; // Default padding
            if (paddingProp != null && paddingProp.getPropertyValue() != null) {
                try {
                    padding = Integer.parseInt(paddingProp.getPropertyValue());
                } catch (NumberFormatException e) {
                    LOGGER.warn("Invalid sequence padding value, using default: " + e.getMessage());
                }
            }
            builder.add("sequencePadding", padding);

            final JsonObject settings = builder.build();
            return Response.ok(settings).build();
        } catch (Exception e) {
            LOGGER.error("Error retrieving vulnerability ID settings", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Error retrieving settings").build();
        }
    }

    /**
     * Update custom vulnerability ID settings
     * Persists new configuration for vulnerability ID generation.
     *
     * @param jsonSettings JSON object containing settings to update
     * @return Response indicating success or failure
     */
    @PUT
    @Path("/vulnerability-id")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Update custom vulnerability ID settings",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Settings updated successfully",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON)
            ),
            @ApiResponse(responseCode = "400", description = "Invalid request"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Forbidden"),
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION_WRITE)
    public Response updateVulnerabilityIdSettings(final String jsonSettings) {
        try (QueryManager qm = new QueryManager()) {
            JsonObject settings = Json.createReader(new StringReader(jsonSettings)).readObject();

            if (settings.containsKey("orgCode") && settings.get("orgCode") != null) {
                final String orgCode = settings.getString("orgCode");
                setOrUpdateConfigProperty(qm, VULN_ID_ORG_CODE, orgCode);
            }

            if (settings.containsKey("template") && settings.get("template") != null) {
                final String template = settings.getString("template");
                setOrUpdateConfigProperty(qm, VULN_ID_TEMPLATE, template);
            }

            if (settings.containsKey("resetPolicy") && settings.get("resetPolicy") != null) {
                final String resetPolicy = settings.getString("resetPolicy");
                setOrUpdateConfigProperty(qm, VULN_ID_RESET_POLICY, resetPolicy);
            }

            if (settings.containsKey("sequencePadding") && settings.get("sequencePadding") != null) {
                final int padding = settings.getInt("sequencePadding");
                setOrUpdateConfigProperty(qm, VULN_ID_SEQUENCE_PADDING, String.valueOf(padding));
            }

            LOGGER.info("Vulnerability ID settings updated");
            return Response.ok().build();
        } catch (Exception e) {
            LOGGER.error("Error updating vulnerability ID settings", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Error updating settings: " + e.getMessage()).build();
        }
    }

    private void setOrUpdateConfigProperty(QueryManager qm, final String propertyKey, final String propertyValue) {
        ConfigProperty property = qm.getConfigProperty(propertyKey);
        if (property == null) {
            property = new ConfigProperty();
            property.setGroupName("Vulnerability ID");
            property.setPropertyName(propertyKey);
            property.setPropertyValue(propertyValue);
            property.setDescription("Custom vulnerability ID generation setting");
            qm.persist(property);
        } else {
            property.setPropertyValue(propertyValue);
            qm.updateConfigProperty(property);
        }
    }
}
