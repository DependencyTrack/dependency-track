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
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.JsonUtil;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * JAX-RS resource for managing application customization settings.
 *
 * <p>All settings managed here are persisted in the standard {@code CONFIGPROPERTY} table using
 * the same group/name structure as the {@code /v1/configProperty} API. These endpoints are
 * domain-specific facades over that storage layer: they provide curated JSON responses and
 * business-rule validation, and the read endpoints are available to non-administrative users
 * so that portfolio views can consume the settings.
 *
 * <p>The underlying data can also be read and written via the existing
 * {@code GET/POST /v1/configProperty} endpoints using the group and property names defined in
 * {@link org.dependencytrack.model.ConfigPropertyConstants}. The two API surfaces are fully
 * compatible — both read from and write to the same database rows.
 */
@Path("/v1/customization")
@Tag(name = "Customization", description = "Endpoints for managing application customizations")
public class CustomizationResource extends AbstractConfigPropertyResource {

    /**
     * Retrieves the vulnerability source of discovery options.
     *
     * @return A JSON response containing the enabled flag and the configured source values
     */
    @GET
    @Path("/vulnerability-source")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Retrieve vulnerability source options",
               description = "Retrieves the admin-configurable vulnerability source of discovery dropdown options. <p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Vulnerability source options retrieved successfully",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON,
                                      schema = @Schema(type = "object", example = """
                                          {
                                              "enabled": false,
                                              "values": [{"label": "Penetration Test"}, {"label": "Bug Bounty"}]
                                          }
                                          """)))
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getVulnerabilitySourceOptions() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final ConfigProperty prop = qm.getConfigProperty(
                    ConfigPropertyConstants.VULNERABILITY_SOURCE_OPTIONS.getGroupName(),
                    ConfigPropertyConstants.VULNERABILITY_SOURCE_OPTIONS.getPropertyName());
            final String value = (prop != null) ? prop.getPropertyValue() : null;
            if (JsonUtil.isBlankJson(value)) {
                final String defaultValue = ConfigPropertyConstants.VULNERABILITY_SOURCE_OPTIONS.getDefaultPropertyValue();
                return Response.ok(defaultValue).type(MediaType.APPLICATION_JSON).build();
            }
            return Response.ok(value).type(MediaType.APPLICATION_JSON).build();
        }
    }

    /**
     * Updates the vulnerability source of discovery options.
     * Requires SYSTEM_CONFIGURATION permission.
     *
     * @param jsonInput The JSON payload containing the enabled flag and source values
     * @return A 204 No Content response on success
     */
    @PUT
    @Path("/vulnerability-source")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    @Operation(summary = "Update vulnerability source options",
               description = "Updates the admin-configurable vulnerability source of discovery dropdown options. <p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Vulnerability source options updated successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid input provided"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public Response updateVulnerabilitySourceOptions(String jsonInput) {
        if (JsonUtil.isBlankJson(jsonInput)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Vulnerability source configuration cannot be empty").build();
        }
        try {
            final JSONObject json = new JSONObject(jsonInput);
            if (!json.has("enabled") || !json.has("values")) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("Missing required field: 'enabled' and 'values' are required").build();
            }
            final String validationError = validateVulnerabilitySourceOptions(json);
            if (validationError != null) {
                return Response.status(Response.Status.BAD_REQUEST).entity(validationError).build();
            }
        } catch (JSONException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Invalid JSON: " + e.getMessage()).build();
        }
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            updateConfigProperty(qm, ConfigPropertyConstants.VULNERABILITY_SOURCE_OPTIONS, jsonInput);
            return Response.noContent().build();
        }
    }

    private String validateVulnerabilitySourceOptions(final JSONObject json) {
        final JSONArray values = json.optJSONArray("values");
        if (values == null) {
            return "Invalid input: 'values' must be an array";
        }

        final Set<String> seenLabels = new HashSet<>();

        for (int i = 0; i < values.length(); i++) {
            final JSONObject entry = values.optJSONObject(i);
            if (entry == null) {
                return "Invalid input: each vulnerability source must be an object";
            }

            final String label = entry.optString("label", "").trim();
            if (label.isBlank()) {
                return "Invalid input: source name cannot be empty";
            }

            if (!seenLabels.add(label.toLowerCase(Locale.ROOT))) {
                return "A source with this name already exists. Please use a unique name.";
            }
        }

        return null;
    }

    /**
     * Updates or creates a ConfigProperty with the given constant and value.
     *
     * <p>This mirrors the persistence logic in {@code ConfigPropertyResource} — the same
     * {@code CONFIGPROPERTY} row is written regardless of which API surface is used.
     *
     * @param qm The QueryManager
     * @param propertyConstant The ConfigPropertyConstants constant identifying the row
     * @param value The new value to persist
     */
    private void updateConfigProperty(QueryManager qm, ConfigPropertyConstants propertyConstant,
                                      String value) {
        ConfigProperty property = qm.getConfigProperty(
                propertyConstant.getGroupName(),
                propertyConstant.getPropertyName());

        if (property == null) {
            property = qm.createConfigProperty(
                    propertyConstant.getGroupName(),
                    propertyConstant.getPropertyName(),
                    value,
                    propertyConstant.getPropertyType(),
                    propertyConstant.getDescription());
        } else {
            property.setPropertyValue(value);
            qm.persist(property);
        }
    }
}
