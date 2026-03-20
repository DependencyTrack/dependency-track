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
 * JAX-RS resource for managing application customizations including vulnerability ID configuration.
 */
@Path("/v1/customization")
@Tag(name = "Customization", description = "Endpoints for managing application customizations")
public class CustomizationResource extends AbstractConfigPropertyResource {

    /**
     * Retrieves the vulnerability ID customization settings.
     * 
     * @return A JSON response containing the current vulnerability ID configuration
     */
    @GET
    @Path("/vulnerability-id")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Retrieve vulnerability ID settings",
               description = "Retrieves the current vulnerability ID customization settings")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Vulnerability ID settings retrieved successfully",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON,
                                      schema = @Schema(type = "object", example = """
                                          {
                                              "orgCode": "TECAN",
                                              "projectCode": "myproject",
                                              "template": "{ORG_CODE}-{PROJECT_NAME}-{YYYY}-{SEQUENCE}",
                                              "resetPolicy": "YEARLY",
                                              "sequencePadding": 5
                                          }
                                          """)))
    })
    public Response getVulnerabilityIdSettings() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            JSONObject response = new JSONObject();
            
            // Get organization code
            ConfigProperty orgCodeProp = qm.getConfigProperty(
                    ConfigPropertyConstants.VULNERABILITY_ID_ORG_CODE.getGroupName(),
                    ConfigPropertyConstants.VULNERABILITY_ID_ORG_CODE.getPropertyName());
            response.put("orgCode", orgCodeProp != null
                    ? orgCodeProp.getPropertyValue()
                    : ConfigPropertyConstants.VULNERABILITY_ID_ORG_CODE.getDefaultPropertyValue());

            // Get default project code
            ConfigProperty projectCodeProp = qm.getConfigProperty(
                    ConfigPropertyConstants.VULNERABILITY_ID_PROJECT_CODE.getGroupName(),
                    ConfigPropertyConstants.VULNERABILITY_ID_PROJECT_CODE.getPropertyName());
            response.put("projectCode", projectCodeProp != null
                    ? projectCodeProp.getPropertyValue()
                    : ConfigPropertyConstants.VULNERABILITY_ID_PROJECT_CODE.getDefaultPropertyValue());
            
            // Get template
            ConfigProperty templateProp = qm.getConfigProperty(
                    ConfigPropertyConstants.VULNERABILITY_ID_TEMPLATE.getGroupName(),
                    ConfigPropertyConstants.VULNERABILITY_ID_TEMPLATE.getPropertyName());
            response.put("template", templateProp != null
                    ? templateProp.getPropertyValue()
                    : ConfigPropertyConstants.VULNERABILITY_ID_TEMPLATE.getDefaultPropertyValue());
            
            // Get reset policy
            ConfigProperty resetPolicyProp = qm.getConfigProperty(
                    ConfigPropertyConstants.VULNERABILITY_ID_RESET_POLICY.getGroupName(),
                    ConfigPropertyConstants.VULNERABILITY_ID_RESET_POLICY.getPropertyName());
            response.put("resetPolicy", resetPolicyProp != null
                    ? resetPolicyProp.getPropertyValue()
                    : ConfigPropertyConstants.VULNERABILITY_ID_RESET_POLICY.getDefaultPropertyValue());
            
            // Get sequence padding
            ConfigProperty sequencePaddingProp = qm.getConfigProperty(
                    ConfigPropertyConstants.VULNERABILITY_ID_SEQUENCE_PADDING.getGroupName(),
                    ConfigPropertyConstants.VULNERABILITY_ID_SEQUENCE_PADDING.getPropertyName());
            response.put("sequencePadding", sequencePaddingProp != null
                    ? Integer.parseInt(sequencePaddingProp.getPropertyValue())
                    : Integer.parseInt(ConfigPropertyConstants.VULNERABILITY_ID_SEQUENCE_PADDING.getDefaultPropertyValue()));
            
            return Response.ok(response.toString()).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(new JSONObject()
                            .put("error", "Error retrieving vulnerability ID settings: " + e.getMessage())
                            .toString())
                    .build();
        }
    }

    /**
     * Retrieves text placeholder settings used in create/audit forms.
     *
     * @return A JSON response containing text placeholder configuration
     */
    @GET
    @Path("/text-placeholders")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Retrieve text placeholder settings",
               description = "Retrieves customizable placeholder texts for create and audit forms")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Text placeholder settings retrieved successfully",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON,
                                      schema = @Schema(type = "object", example = """
                                          {
                                              "descriptionPlaceholder": "<Add detail description about the vulnerability>",
                                              "detailPlaceholder": "<Add additional details>",
                                              "recommendationPlaceholder": "<Add any recommendation from external companies / partners or internal security team>",
                                              "referencesPlaceholder": "<Add any references if available, example: CPE / CVE references>",
                                              "riskJustificationPlaceholder": "Explain why this risk is acceptable...",
                                              "residualRiskPlaceholder": "Describe any remaining risk after mitigation...",
                                              "commentPlaceholder": "<Add all participants for the review/assessment>",
                                              "analysisDetailsInstruction": "1.  Affected Software Items: Identify which software items are impacted..."
                                          }
                                          """)))
    })
    public Response getTextPlaceholderSettings() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final JSONObject response = new JSONObject();
            response.put("descriptionPlaceholder", getConfigPropertyValue(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_CREATE_DESCRIPTION));
            response.put("detailPlaceholder", getConfigPropertyValue(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_CREATE_DETAIL));
            response.put("recommendationPlaceholder", getConfigPropertyValue(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_CREATE_RECOMMENDATION));
            response.put("referencesPlaceholder", getConfigPropertyValue(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_CREATE_REFERENCES));
            response.put("riskJustificationPlaceholder", getConfigPropertyValue(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_AUDIT_RISK_JUSTIFICATION));
            response.put("residualRiskPlaceholder", getConfigPropertyValue(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_AUDIT_RESIDUAL_RISK));
            response.put("commentPlaceholder", getConfigPropertyValue(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_AUDIT_COMMENT));
            response.put("analysisDetailsInstruction", getConfigPropertyValue(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_AUDIT_DETAILS_INSTRUCTION));
            return Response.ok(response.toString()).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(new JSONObject()
                            .put("error", "Error retrieving text placeholder settings: " + e.getMessage())
                            .toString())
                    .build();
        }
    }

    /**
     * Updates the vulnerability ID customization settings.
     * Requires ADMIN or SYSTEM_CONFIGURATION permission.
     * 
     * @param jsonInput The JSON payload containing the updated settings
     * @return A 204 No Content response on success
     */
    @PUT
    @Path("/vulnerability-id")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    @Operation(summary = "Update vulnerability ID settings",
               description = "Updates the vulnerability ID customization settings")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Vulnerability ID settings updated successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid input provided"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public Response updateVulnerabilityIdSettings(String jsonInput) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            JSONObject json = new JSONObject(jsonInput);
            
            // Validate input
            if (!json.has("orgCode") || json.getString("orgCode").trim().isEmpty()) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(new JSONObject()
                                .put("error", "Organization code is required and cannot be empty")
                                .toString())
                        .build();
            }
            if (json.has("projectCode") && json.getString("projectCode").trim().isEmpty()) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(new JSONObject()
                                .put("error", "Project code cannot be empty when provided")
                                .toString())
                        .build();
            }
            if (!json.has("template") || json.getString("template").trim().isEmpty()) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(new JSONObject()
                                .put("error", "Template is required and cannot be empty")
                                .toString())
                        .build();
            }
            if (!json.has("resetPolicy") || json.getString("resetPolicy").trim().isEmpty()) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(new JSONObject()
                                .put("error", "Reset policy is required")
                                .toString())
                        .build();
            }
            if (!json.has("sequencePadding") || json.getInt("sequencePadding") < 1 ||
                json.getInt("sequencePadding") > 20) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(new JSONObject()
                                .put("error", "Sequence padding must be between 1 and 20")
                                .toString())
                        .build();
            }
            
            // Validate reset policy values
            String resetPolicy = json.getString("resetPolicy");
            if (!resetPolicy.matches("YEARLY|MONTHLY|DAILY|NEVER")) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(new JSONObject()
                                .put("error", "Invalid reset policy. Must be YEARLY, MONTHLY, DAILY, or NEVER")
                                .toString())
                        .build();
            }
            
            // Update org code
            updateConfigProperty(qm, ConfigPropertyConstants.VULNERABILITY_ID_ORG_CODE,
                    json.getString("orgCode"));

            // Update default project code
            if (json.has("projectCode")) {
                updateConfigProperty(qm, ConfigPropertyConstants.VULNERABILITY_ID_PROJECT_CODE,
                        json.getString("projectCode"));
            }
            
            // Update template
            updateConfigProperty(qm, ConfigPropertyConstants.VULNERABILITY_ID_TEMPLATE,
                    json.getString("template"));
            
            // Update reset policy
            updateConfigProperty(qm, ConfigPropertyConstants.VULNERABILITY_ID_RESET_POLICY,
                    resetPolicy);
            
            // Update sequence padding
            updateConfigProperty(qm, ConfigPropertyConstants.VULNERABILITY_ID_SEQUENCE_PADDING,
                    String.valueOf(json.getInt("sequencePadding")));
            
            return Response.noContent().build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(new JSONObject().put("error", e.getMessage()).toString())
                    .build();
        }
    }

    /**
     * Updates text placeholder settings used in create/audit forms.
     *
     * @param jsonInput The JSON payload containing one or more placeholder settings
     * @return A 204 No Content response on success
     */
    @PUT
    @Path("/text-placeholders")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    @Operation(summary = "Update text placeholder settings",
               description = "Updates customizable placeholder texts for create and audit forms")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Text placeholder settings updated successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid input provided"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public Response updateTextPlaceholderSettings(String jsonInput) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final JSONObject json = new JSONObject(jsonInput);
            final String[] supportedKeys = new String[] {
                    "descriptionPlaceholder",
                    "detailPlaceholder",
                    "recommendationPlaceholder",
                    "referencesPlaceholder",
                    "riskJustificationPlaceholder",
                    "residualRiskPlaceholder",
                    "commentPlaceholder",
                    "analysisDetailsInstruction"
            };

            boolean updated = false;
            for (String key : supportedKeys) {
                if (json.has(key)) {
                    if (json.isNull(key)) {
                        return Response.status(Response.Status.BAD_REQUEST)
                                .entity(new JSONObject()
                                        .put("error", key + " cannot be null")
                                        .toString())
                                .build();
                    }
                    updated = true;
                }
            }

            if (!updated) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(new JSONObject()
                                .put("error", "No supported text placeholder fields were provided")
                                .toString())
                        .build();
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
            if (json.has("riskJustificationPlaceholder")) {
                updateConfigProperty(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_AUDIT_RISK_JUSTIFICATION,
                        json.getString("riskJustificationPlaceholder"));
            }
            if (json.has("residualRiskPlaceholder")) {
                updateConfigProperty(qm, ConfigPropertyConstants.TEXT_PLACEHOLDER_AUDIT_RESIDUAL_RISK,
                        json.getString("residualRiskPlaceholder"));
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
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(new JSONObject().put("error", e.getMessage()).toString())
                    .build();
        }
    }

    /**
     * Retrieves the active custom risk matrix configuration.
     *
     * @return A JSON response containing the risk matrix config, or {} if not configured
     */
    @GET
    @Path("/risk-matrix")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Retrieve risk matrix configuration",
               description = "Retrieves the active custom risk matrix configuration")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Risk matrix configuration retrieved successfully")
    })
    public Response getRiskMatrixConfig() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final ConfigProperty prop = qm.getConfigProperty(
                    ConfigPropertyConstants.RISK_MATRIX_CONFIG.getGroupName(),
                    ConfigPropertyConstants.RISK_MATRIX_CONFIG.getPropertyName());
            final String value = (prop != null) ? prop.getPropertyValue() : null;
            if (JsonUtil.isBlankJson(value)) {
                return Response.ok("{}").type(MediaType.APPLICATION_JSON).build();
            }
            return Response.ok(value).type(MediaType.APPLICATION_JSON).build();
        }
    }

    /**
     * Updates the active custom risk matrix configuration.
     * Requires SYSTEM_CONFIGURATION permission.
     *
     * @param jsonInput The full risk matrix configuration JSON
     * @return A 204 No Content response on success
     */
    @PUT
    @Path("/risk-matrix")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    @Operation(summary = "Update risk matrix configuration",
               description = "Updates the active custom risk matrix configuration")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Risk matrix configuration updated successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid input provided"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public Response updateRiskMatrixConfig(String jsonInput) {
        if (JsonUtil.isBlankJson(jsonInput)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Risk matrix configuration cannot be empty").build();
        }
        try {
            final JSONObject json = new JSONObject(jsonInput);
            for (final String key : new String[]{"enabled", "impactValues", "likelihoodValues", "levels", "cells"}) {
                if (!json.has(key)) {
                    return Response.status(Response.Status.BAD_REQUEST)
                            .entity("Missing required field: " + key).build();
                }
            }
        } catch (JSONException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Invalid JSON: " + e.getMessage()).build();
        }
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            updateConfigProperty(qm, ConfigPropertyConstants.RISK_MATRIX_CONFIG, jsonInput);
            return Response.noContent().build();
        }
    }

    @GET
    @Path("/vulnerability-source")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Retrieve vulnerability source options",
               description = "Retrieves the admin-configurable vulnerability source of discovery dropdown options")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Vulnerability source options retrieved successfully")
    })
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

    @PUT
    @Path("/vulnerability-source")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    @Operation(summary = "Update vulnerability source options",
               description = "Updates the admin-configurable vulnerability source of discovery dropdown options")
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
        } catch (JSONException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Invalid JSON: " + e.getMessage()).build();
        }
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            updateConfigProperty(qm, ConfigPropertyConstants.VULNERABILITY_SOURCE_OPTIONS, jsonInput);
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
     * @param qm The QueryManager
     * @param propertyConstant The ConfigPropertyConstants constant
     * @param value The new value
     */
    private void updateConfigProperty(QueryManager qm, ConfigPropertyConstants propertyConstant,
                                      String value) {
        ConfigProperty property = qm.getConfigProperty(
                propertyConstant.getGroupName(),
                propertyConstant.getPropertyName());
        
        if (property == null) {
            // Create new property using QueryManager's method
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
