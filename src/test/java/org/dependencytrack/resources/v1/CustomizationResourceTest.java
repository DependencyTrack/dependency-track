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
                            "orgCode": "TECAN",
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
                            "orgCode": "TECAN",
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
                            "orgCode": "TECAN",
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
                            "orgCode": "TECAN",
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
                            "orgCode": "TECAN",
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
                            "orgCode": "TECAN",
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
                            "orgCode": "TECAN",
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
                            "orgCode": "TECAN",
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
        assertThat(json.getString("descriptionPlaceholder")).isEqualTo("Updated desc");
        assertThat(json.getString("riskJustificationPlaceholder")).isEqualTo("Updated risk");
    }

    @Test
    void updateTextPlaceholderSettingsAllFieldsSucceeds() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
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
}
