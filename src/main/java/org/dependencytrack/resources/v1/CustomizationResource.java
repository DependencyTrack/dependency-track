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
import org.json.JSONException;
import org.json.JSONObject;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

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
     * Retrieves the text placeholder settings for create and audit forms.
     *
     * @return A JSON response containing the current placeholder texts
     */
    @GET
    @Path("/text-placeholders")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Retrieve text placeholder settings",
               description = "Retrieves customizable placeholder texts for create and audit forms. <p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Text placeholder settings retrieved successfully",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON,
                                      schema = @Schema(type = "object", example = """
                                          {
                                              "enabled": false,
                                              "descriptionPlaceholder": "<What is the vulnerability?>",
                                              "detailPlaceholder": "<Add additional details>",
                                              "recommendationPlaceholder": "<What fix is available?>",
                                              "referencesPlaceholder": "<Add any references>",
                                              "commentPlaceholder": "<Add all participants>",
                                              "analysisDetailsInstruction": "<Steps to follow during analysis>"
                                          }
                                          """)))
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getTextPlaceholderSettings() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final JSONObject response = new JSONObject();
            response.put("enabled", Boolean.parseBoolean(getConfigPropertyValue(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_ENABLED)));
            response.put("descriptionPlaceholder", getConfigPropertyValue(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_CREATE_DESCRIPTION));
            response.put("detailPlaceholder", getConfigPropertyValue(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_CREATE_DETAIL));
            response.put("recommendationPlaceholder", getConfigPropertyValue(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_CREATE_RECOMMENDATION));
            response.put("referencesPlaceholder", getConfigPropertyValue(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_CREATE_REFERENCES));
            response.put("commentPlaceholder", getConfigPropertyValue(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_AUDIT_COMMENT));
            response.put("analysisDetailsInstruction", getConfigPropertyValue(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_AUDIT_DETAILS_INSTRUCTION));
            return Response.ok(response.toString()).build();
        }
    }

    /**
     * Updates the text placeholder settings for create and audit forms.
     * Requires SYSTEM_CONFIGURATION permission.
     *
     * @param jsonInput The JSON payload containing the placeholder texts to update
     * @return A 204 No Content response on success
     */
    @PUT
    @Path("/text-placeholders")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    @Operation(summary = "Update text placeholder settings",
               description = "Updates customizable placeholder texts for create and audit forms. <p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Text placeholder settings updated successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid input provided"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public Response updateTextPlaceholderSettings(String jsonInput) {
        final JSONObject json;
        try {
            json = new JSONObject(jsonInput);
        } catch (JSONException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Invalid JSON: " + e.getMessage()).build();
        }

        final String[] supportedKeys = new String[] {
                "enabled",
                "descriptionPlaceholder",
                "detailPlaceholder",
                "recommendationPlaceholder",
                "referencesPlaceholder",
                "commentPlaceholder",
                "analysisDetailsInstruction"
        };

        boolean updated = false;
        for (final String key : supportedKeys) {
            if (json.has(key)) {
                if (json.isNull(key)) {
                    return Response.status(Response.Status.BAD_REQUEST)
                            .entity(key + " cannot be null").build();
                }
                updated = true;
            }
        }
        if (!updated) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("No supported text placeholder fields were provided").build();
        }

        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            if (json.has("enabled")) {
                updateConfigProperty(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_ENABLED,
                        String.valueOf(json.getBoolean("enabled")));
            }
            if (json.has("descriptionPlaceholder")) {
                updateConfigProperty(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_CREATE_DESCRIPTION,
                        json.getString("descriptionPlaceholder"));
            }
            if (json.has("detailPlaceholder")) {
                updateConfigProperty(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_CREATE_DETAIL,
                        json.getString("detailPlaceholder"));
            }
            if (json.has("recommendationPlaceholder")) {
                updateConfigProperty(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_CREATE_RECOMMENDATION,
                        json.getString("recommendationPlaceholder"));
            }
            if (json.has("referencesPlaceholder")) {
                updateConfigProperty(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_CREATE_REFERENCES,
                        json.getString("referencesPlaceholder"));
            }
            if (json.has("commentPlaceholder")) {
                updateConfigProperty(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_AUDIT_COMMENT,
                        json.getString("commentPlaceholder"));
            }
            if (json.has("analysisDetailsInstruction")) {
                updateConfigProperty(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_AUDIT_DETAILS_INSTRUCTION,
                        json.getString("analysisDetailsInstruction"));
            }
            return Response.noContent().build();
        }
    }

    private String getConfigPropertyValue(final QueryManager qm, final ConfigPropertyConstants propertyConstant) {
        final ConfigProperty property = qm.getConfigProperty(
                propertyConstant.getGroupName(),
                propertyConstant.getPropertyName());
        return property != null ? property.getPropertyValue() : propertyConstant.getDefaultPropertyValue();
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
