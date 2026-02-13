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
import org.json.JSONObject;

import jakarta.ws.rs.*;
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
