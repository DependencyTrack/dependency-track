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

import alpine.model.IConfigProperty;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static org.assertj.core.api.Assertions.assertThat;

class CustomizationResourceTest extends ResourceTest {

    private static final String V1_CUSTOMIZATION_VULNERABILITY_ID = "/v1/customization/vulnerability-id";
    private static final String V1_CUSTOMIZATION_TEXT_PLACEHOLDERS  = "/v1/customization/text-placeholders";
    private static final String V1_CUSTOMIZATION_RISK_MATRIX = "/v1/customization/risk-matrix";
    private static final String V1_CUSTOMIZATION_VULN_SOURCE = "/v1/customization/vulnerability-source";

    @RegisterExtension
    public static JerseyTestExtension jersey = new JerseyTestExtension(
            () -> new ResourceConfig(CustomizationResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    // -------------------------------------------------------------------------
    // GET /v1/customization/vulnerability-id
    // -------------------------------------------------------------------------

    @Test
    void getVulnerabilityIdSettingsReturnsDefaultsWhenNotConfigured() {
        Response response = jersey.target(V1_CUSTOMIZATION_VULNERABILITY_ID)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(200);

        JsonObject json = parseJsonObject(response);
        // Defaults come from ConfigPropertyConstants — they must at minimum be non-null strings
        assertThat(json.getString("orgCode")).isNotBlank();
        assertThat(json.getString("template")).isNotBlank();
        assertThat(json.getString("resetPolicy")).isNotBlank();
        assertThat(json.getInt("sequencePadding")).isGreaterThanOrEqualTo(1);
    }

    @Test
    void getVulnerabilityIdSettingsReturnsStoredValues() {
        qm.createConfigProperty(
                ConfigPropertyConstants.VULNERABILITY_ID_ORG_CODE.getGroupName(),
                ConfigPropertyConstants.VULNERABILITY_ID_ORG_CODE.getPropertyName(),
                "MYORG",
                IConfigProperty.PropertyType.STRING,
                ConfigPropertyConstants.VULNERABILITY_ID_ORG_CODE.getDescription());
        qm.createConfigProperty(
                ConfigPropertyConstants.VULNERABILITY_ID_PROJECT_CODE.getGroupName(),
                ConfigPropertyConstants.VULNERABILITY_ID_PROJECT_CODE.getPropertyName(),
                "myproject",
                IConfigProperty.PropertyType.STRING,
                ConfigPropertyConstants.VULNERABILITY_ID_PROJECT_CODE.getDescription());
        qm.createConfigProperty(
                ConfigPropertyConstants.VULNERABILITY_ID_TEMPLATE.getGroupName(),
                ConfigPropertyConstants.VULNERABILITY_ID_TEMPLATE.getPropertyName(),
                "{ORG_CODE}-{SEQUENCE}",
                IConfigProperty.PropertyType.STRING,
                ConfigPropertyConstants.VULNERABILITY_ID_TEMPLATE.getDescription());
        qm.createConfigProperty(
                ConfigPropertyConstants.VULNERABILITY_ID_RESET_POLICY.getGroupName(),
                ConfigPropertyConstants.VULNERABILITY_ID_RESET_POLICY.getPropertyName(),
                "NEVER",
                IConfigProperty.PropertyType.STRING,
                ConfigPropertyConstants.VULNERABILITY_ID_RESET_POLICY.getDescription());
        qm.createConfigProperty(
                ConfigPropertyConstants.VULNERABILITY_ID_SEQUENCE_PADDING.getGroupName(),
                ConfigPropertyConstants.VULNERABILITY_ID_SEQUENCE_PADDING.getPropertyName(),
                "8",
                IConfigProperty.PropertyType.INTEGER,
                ConfigPropertyConstants.VULNERABILITY_ID_SEQUENCE_PADDING.getDescription());

        Response response = jersey.target(V1_CUSTOMIZATION_VULNERABILITY_ID)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(200);

        JsonObject json = parseJsonObject(response);
        assertThat(json.getString("orgCode")).isEqualTo("MYORG");
        assertThat(json.getString("projectCode")).isEqualTo("myproject");
        assertThat(json.getString("template")).isEqualTo("{ORG_CODE}-{SEQUENCE}");
        assertThat(json.getString("resetPolicy")).isEqualTo("NEVER");
        assertThat(json.getInt("sequencePadding")).isEqualTo(8);
    }

    // -------------------------------------------------------------------------
    // PUT /v1/customization/vulnerability-id – happy path
    // -------------------------------------------------------------------------

    @Test
    void updateVulnerabilityIdSettingsSucceeds() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_VULNERABILITY_ID)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "orgCode": "ACME",
                            "projectCode": "myproj",
                            "template": "{ORG_CODE}-{PROJECT_NAME}-{YYYY}-{SEQUENCE}",
                            "resetPolicy": "YEARLY",
                            "sequencePadding": 5
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(204);
    }

    @Test
    void updateVulnerabilityIdSettingsRoundTrip() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        // First PUT to store values
        jersey.target(V1_CUSTOMIZATION_VULNERABILITY_ID)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "orgCode": "ACME",
                            "template": "{ORG_CODE}-{SEQUENCE}",
                            "resetPolicy": "MONTHLY",
                            "sequencePadding": 3
                        }
                        """, MediaType.APPLICATION_JSON));

        // Then GET to verify they were persisted
        Response response = jersey.target(V1_CUSTOMIZATION_VULNERABILITY_ID)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(200);
        JsonObject json = parseJsonObject(response);
        assertThat(json.getString("orgCode")).isEqualTo("ACME");
        assertThat(json.getString("template")).isEqualTo("{ORG_CODE}-{SEQUENCE}");
        assertThat(json.getString("resetPolicy")).isEqualTo("MONTHLY");
        assertThat(json.getInt("sequencePadding")).isEqualTo(3);
    }

    @Test
    void updateVulnerabilityIdSettingsAcceptsAllResetPolicies() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        for (String policy : new String[]{"YEARLY", "MONTHLY", "DAILY", "NEVER"}) {
            Response response = jersey.target(V1_CUSTOMIZATION_VULNERABILITY_ID)
                    .request()
                    .header(X_API_KEY, apiKey)
                    .put(Entity.entity(String.format("""
                            {
                                "orgCode": "ORG",
                                "template": "{ORG_CODE}",
                                "resetPolicy": "%s",
                                "sequencePadding": 5
                            }
                            """, policy), MediaType.APPLICATION_JSON));
            assertThat(response.getStatus())
                    .as("Expected 204 for resetPolicy=%s", policy)
                    .isEqualTo(204);
        }
    }

    // -------------------------------------------------------------------------
    // PUT /v1/customization/vulnerability-id – validation errors (400)
    // -------------------------------------------------------------------------

    @Test
    void updateVulnerabilityIdSettingsReturns400WhenOrgCodeMissing() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_VULNERABILITY_ID)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "template": "{ORG_CODE}-{SEQUENCE}",
                            "resetPolicy": "YEARLY",
                            "sequencePadding": 5
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).contains("Organization code");
    }

    @Test
    void updateVulnerabilityIdSettingsReturns400WhenOrgCodeEmpty() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_VULNERABILITY_ID)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "orgCode": "   ",
                            "template": "{ORG_CODE}-{SEQUENCE}",
                            "resetPolicy": "YEARLY",
                            "sequencePadding": 5
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    void updateVulnerabilityIdSettingsReturns400WhenTemplateMissing() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_VULNERABILITY_ID)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "orgCode": "ACME",
                            "resetPolicy": "YEARLY",
                            "sequencePadding": 5
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).contains("Template");
    }

    @Test
    void updateVulnerabilityIdSettingsReturns400WhenResetPolicyMissing() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_VULNERABILITY_ID)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "orgCode": "ACME",
                            "template": "{ORG_CODE}",
                            "sequencePadding": 5
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).contains("Reset policy");
    }

    @Test
    void updateVulnerabilityIdSettingsReturns400WhenResetPolicyInvalid() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_VULNERABILITY_ID)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "orgCode": "ACME",
                            "template": "{ORG_CODE}",
                            "resetPolicy": "WEEKLY",
                            "sequencePadding": 5
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).contains("Invalid reset policy");
    }

    @Test
    void updateVulnerabilityIdSettingsReturns400WhenSequencePaddingTooLow() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_VULNERABILITY_ID)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "orgCode": "ACME",
                            "template": "{ORG_CODE}",
                            "resetPolicy": "YEARLY",
                            "sequencePadding": 0
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).contains("Sequence padding");
    }

    @Test
    void updateVulnerabilityIdSettingsReturns400WhenSequencePaddingTooHigh() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_VULNERABILITY_ID)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "orgCode": "ACME",
                            "template": "{ORG_CODE}",
                            "resetPolicy": "YEARLY",
                            "sequencePadding": 21
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).contains("Sequence padding");
    }

    @Test
    void updateVulnerabilityIdSettingsReturns400WhenProjectCodeEmpty() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_VULNERABILITY_ID)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "orgCode": "ACME",
                            "projectCode": "   ",
                            "template": "{ORG_CODE}",
                            "resetPolicy": "YEARLY",
                            "sequencePadding": 5
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).contains("Project code");
    }

    // -------------------------------------------------------------------------
    // PUT /v1/customization/vulnerability-id – authorization (403)
    // -------------------------------------------------------------------------

    @Test
    void updateVulnerabilityIdSettingsReturns403WithoutPermission() {
        // No permissions added to the team
        Response response = jersey.target(V1_CUSTOMIZATION_VULNERABILITY_ID)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "orgCode": "ACME",
                            "template": "{ORG_CODE}",
                            "resetPolicy": "YEARLY",
                            "sequencePadding": 5
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(403);
    }

    // -------------------------------------------------------------------------
    // GET /v1/customization/text-placeholders
    // -------------------------------------------------------------------------

    @Test
    void getTextPlaceholderSettingsReturnsDefaultsWhenNotConfigured() {
        Response response = jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(200);

        JsonObject json = parseJsonObject(response);
        assertThat(json.getBoolean("enabled")).isTrue();
        assertThat(json.getString("descriptionPlaceholder")).isNotBlank();
        assertThat(json.getString("detailPlaceholder")).isNotBlank();
        assertThat(json.getString("recommendationPlaceholder")).isNotBlank();
        assertThat(json.getString("referencesPlaceholder")).isNotBlank();
        assertThat(json.getString("riskJustificationPlaceholder")).isNotBlank();
        assertThat(json.getString("residualRiskPlaceholder")).isNotBlank();
        assertThat(json.getString("commentPlaceholder")).isNotBlank();
        assertThat(json.getString("analysisDetailsInstruction")).isNotBlank();
    }

    @Test
    void getTextPlaceholderSettingsReturnsStoredValues() {
        qm.createConfigProperty(
                ConfigPropertyConstants.TEXT_PLACEHOLDER_CREATE_DESCRIPTION.getGroupName(),
                ConfigPropertyConstants.TEXT_PLACEHOLDER_CREATE_DESCRIPTION.getPropertyName(),
                "Enter a description",
                IConfigProperty.PropertyType.STRING,
                ConfigPropertyConstants.TEXT_PLACEHOLDER_CREATE_DESCRIPTION.getDescription());

        Response response = jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(200);
        JsonObject json = parseJsonObject(response);
        assertThat(json.getBoolean("enabled")).isTrue();
        assertThat(json.getString("descriptionPlaceholder")).isEqualTo("Enter a description");
    }

    // -------------------------------------------------------------------------
    // PUT /v1/customization/text-placeholders – happy path
    // -------------------------------------------------------------------------

    @Test
    void updateTextPlaceholderSettingsSucceeds() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "enabled": true,
                            "descriptionPlaceholder": "My custom description",
                            "commentPlaceholder": "My custom comment"
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(204);
    }

    @Test
    void updateTextPlaceholderSettingsRoundTrip() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "enabled": false,
                            "descriptionPlaceholder": "Updated desc",
                            "riskJustificationPlaceholder": "Updated risk"
                        }
                        """, MediaType.APPLICATION_JSON));

        Response response = jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(200);
        JsonObject json = parseJsonObject(response);
        assertThat(json.getBoolean("enabled")).isFalse();
        assertThat(json.getString("descriptionPlaceholder")).isEqualTo("Updated desc");
        assertThat(json.getString("riskJustificationPlaceholder")).isEqualTo("Updated risk");
    }

    @Test
    void updateTextPlaceholderSettingsCanOnlyToggleEnabledState() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "enabled": false
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(204);

        response = jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject json = parseJsonObject(response);
        assertThat(json.getBoolean("enabled")).isFalse();
    }

    @Test
    void updateTextPlaceholderSettingsAllFieldsSucceeds() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "enabled": true,
                            "descriptionPlaceholder": "desc",
                            "detailPlaceholder": "detail",
                            "recommendationPlaceholder": "recommendation",
                            "referencesPlaceholder": "references",
                            "riskJustificationPlaceholder": "risk",
                            "residualRiskPlaceholder": "residual",
                            "commentPlaceholder": "comment",
                            "analysisDetailsInstruction": "instructions"
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(204);
    }

    // -------------------------------------------------------------------------
    // PUT /v1/customization/text-placeholders – validation errors (400)
    // -------------------------------------------------------------------------

    @Test
    void updateTextPlaceholderSettingsReturns400WhenNoSupportedFieldsProvided() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "unknownField": "value"
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).contains("No supported text placeholder fields");
    }

    @Test
    void updateTextPlaceholderSettingsReturns400WhenFieldIsNull() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "descriptionPlaceholder": null
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).contains("cannot be null");
    }

    // -------------------------------------------------------------------------
    // PUT /v1/customization/text-placeholders – authorization (403)
    // -------------------------------------------------------------------------

    @Test
    void updateTextPlaceholderSettingsReturns403WithoutPermission() {
        Response response = jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "descriptionPlaceholder": "Should be rejected"
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(403);
    }

    // =========================================================================
    // GET /v1/customization/risk-matrix
    // =========================================================================

    @Test
    void getRiskMatrixConfigReturnsEmptyObjectWhenNotConfigured() {
        Response response = jersey.target(V1_CUSTOMIZATION_RISK_MATRIX)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(200);
        JsonObject json = parseJsonObject(response);
        assertThat(json).isEmpty();
    }

    @Test
    void getRiskMatrixConfigReturnsStoredValue() {
        final String matrixJson = """
                {"enabled":true,"impactValues":["LOW","HIGH"],"likelihoodValues":["UNLIKELY","LIKELY"],"levels":[{"key":"LOW","label":"Low","color":"#00ff00","sortOrder":1},{"key":"HIGH","label":"High","color":"#ff0000","sortOrder":2}],"cells":{"UNLIKELY::LOW":{"levelKey":"LOW"},"LIKELY::HIGH":{"levelKey":"HIGH"}}}""";
        qm.createConfigProperty(
                ConfigPropertyConstants.RISK_MATRIX_CONFIG.getGroupName(),
                ConfigPropertyConstants.RISK_MATRIX_CONFIG.getPropertyName(),
                matrixJson,
                IConfigProperty.PropertyType.STRING,
                ConfigPropertyConstants.RISK_MATRIX_CONFIG.getDescription());

        Response response = jersey.target(V1_CUSTOMIZATION_RISK_MATRIX)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(200);
        JsonObject json = parseJsonObject(response);
        assertThat(json.getBoolean("enabled")).isTrue();
        assertThat(json.getJsonArray("impactValues")).hasSize(2);
        assertThat(json.getJsonArray("likelihoodValues")).hasSize(2);
        assertThat(json.getJsonArray("levels")).hasSize(2);
    }

    // =========================================================================
    // PUT /v1/customization/risk-matrix – happy path
    // =========================================================================

    @Test
    void updateRiskMatrixConfigSucceeds() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_RISK_MATRIX)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "enabled": true,
                            "impactValues": ["LOW", "MEDIUM", "HIGH"],
                            "likelihoodValues": ["UNLIKELY", "LIKELY"],
                            "levels": [{"key": "LOW", "label": "Low", "color": "#00ff00", "sortOrder": 1}],
                            "cells": {"UNLIKELY::LOW": {"levelKey": "LOW"}}
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(204);
    }

    @Test
    void updateRiskMatrixConfigRoundTrip() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        jersey.target(V1_CUSTOMIZATION_RISK_MATRIX)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "enabled": false,
                            "impactValues": ["LOW", "HIGH"],
                            "likelihoodValues": ["UNLIKELY", "LIKELY"],
                            "levels": [{"key": "INFO", "label": "Info", "color": "#0000ff", "sortOrder": 1}],
                            "cells": {}
                        }
                        """, MediaType.APPLICATION_JSON));

        Response response = jersey.target(V1_CUSTOMIZATION_RISK_MATRIX)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(200);
        JsonObject json = parseJsonObject(response);
        assertThat(json.getBoolean("enabled")).isFalse();
        assertThat(json.getJsonArray("impactValues")).hasSize(2);
        assertThat(json.getJsonArray("levels")).hasSize(1);
    }

    // =========================================================================
    // PUT /v1/customization/risk-matrix – validation errors (400)
    // =========================================================================

    @Test
    void updateRiskMatrixConfigReturns400WhenEmpty() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_RISK_MATRIX)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("", MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    void updateRiskMatrixConfigReturns400WhenMissingEnabled() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_RISK_MATRIX)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "impactValues": ["LOW"],
                            "likelihoodValues": ["UNLIKELY"],
                            "levels": [],
                            "cells": {}
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).contains("enabled");
    }

    @Test
    void updateRiskMatrixConfigReturns400WhenMissingLevels() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_RISK_MATRIX)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "enabled": true,
                            "impactValues": ["LOW"],
                            "likelihoodValues": ["UNLIKELY"],
                            "cells": {}
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).contains("levels");
    }

    @Test
    void updateRiskMatrixConfigReturns400WhenMissingCells() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_RISK_MATRIX)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "enabled": true,
                            "impactValues": ["LOW"],
                            "likelihoodValues": ["UNLIKELY"],
                            "levels": []
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).contains("cells");
    }

    @Test
    void updateRiskMatrixConfigReturns400WhenInvalidJson() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_RISK_MATRIX)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("not valid json{{{", MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).contains("Invalid JSON");
    }

    // =========================================================================
    // PUT /v1/customization/risk-matrix – authorization (403)
    // =========================================================================

    @Test
    void updateRiskMatrixConfigReturns403WithoutPermission() {
        Response response = jersey.target(V1_CUSTOMIZATION_RISK_MATRIX)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "enabled": true,
                            "impactValues": [],
                            "likelihoodValues": [],
                            "levels": [],
                            "cells": {}
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(403);
    }

    // =========================================================================
    // GET /v1/customization/vulnerability-source
    // =========================================================================

    @Test
    void getVulnerabilitySourceOptionsReturnsDefaultsWhenNotConfigured() {
        Response response = jersey.target(V1_CUSTOMIZATION_VULN_SOURCE)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(200);
        JsonObject json = parseJsonObject(response);
        assertThat(json.getBoolean("enabled")).isTrue();
        assertThat(json.getJsonArray("values")).isNotEmpty();
        // Default values include CUSTOMER, PEN_TEST, SONARQUBE, INTERNAL_RESEARCH, VENDOR_ADVISORY, OTHER
        assertThat(json.getJsonArray("values")).hasSize(6);
    }

    @Test
    void getVulnerabilitySourceOptionsReturnsStoredValue() {
        final String sourceJson = """
                {"enabled":false,"values":[{"key":"CUSTOM_SRC","label":"Custom Source"}]}""";
        qm.createConfigProperty(
                ConfigPropertyConstants.VULNERABILITY_SOURCE_OPTIONS.getGroupName(),
                ConfigPropertyConstants.VULNERABILITY_SOURCE_OPTIONS.getPropertyName(),
                sourceJson,
                IConfigProperty.PropertyType.STRING,
                ConfigPropertyConstants.VULNERABILITY_SOURCE_OPTIONS.getDescription());

        Response response = jersey.target(V1_CUSTOMIZATION_VULN_SOURCE)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(200);
        JsonObject json = parseJsonObject(response);
        assertThat(json.getBoolean("enabled")).isFalse();
        assertThat(json.getJsonArray("values")).hasSize(1);
    }

    // =========================================================================
    // PUT /v1/customization/vulnerability-source – happy path
    // =========================================================================

    @Test
    void updateVulnerabilitySourceOptionsSucceeds() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_VULN_SOURCE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "enabled": true,
                            "values": [
                                {"key": "SRC1", "label": "Source One"},
                                {"key": "SRC2", "label": "Source Two"}
                            ]
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(204);
    }

    @Test
    void updateVulnerabilitySourceOptionsRoundTrip() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        jersey.target(V1_CUSTOMIZATION_VULN_SOURCE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "enabled": true,
                            "values": [
                                {"key": "PENTEST", "label": "Penetration Test"},
                                {"key": "SCAN", "label": "Automated Scan"}
                            ]
                        }
                        """, MediaType.APPLICATION_JSON));

        Response response = jersey.target(V1_CUSTOMIZATION_VULN_SOURCE)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(200);
        JsonObject json = parseJsonObject(response);
        assertThat(json.getBoolean("enabled")).isTrue();
        assertThat(json.getJsonArray("values")).hasSize(2);
    }

    // =========================================================================
    // PUT /v1/customization/vulnerability-source – validation errors (400)
    // =========================================================================

    @Test
    void updateVulnerabilitySourceOptionsReturns400WhenEmpty() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_VULN_SOURCE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("", MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    void updateVulnerabilitySourceOptionsReturns400WhenMissingEnabled() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_VULN_SOURCE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "values": [{"key": "X", "label": "X"}]
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).contains("enabled");
    }

    @Test
    void updateVulnerabilitySourceOptionsReturns400WhenMissingValues() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_VULN_SOURCE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "enabled": true
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).contains("values");
    }

    @Test
    void updateVulnerabilitySourceOptionsReturns400WhenInvalidJson() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_VULN_SOURCE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("{broken json!!!", MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).contains("Invalid JSON");
    }

    // =========================================================================
    // PUT /v1/customization/vulnerability-source – authorization (403)
    // =========================================================================

    @Test
    void updateVulnerabilitySourceOptionsReturns403WithoutPermission() {
        Response response = jersey.target(V1_CUSTOMIZATION_VULN_SOURCE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "enabled": true,
                            "values": []
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(403);
    }
}
