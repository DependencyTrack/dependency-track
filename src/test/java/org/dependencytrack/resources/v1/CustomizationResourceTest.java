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

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import alpine.server.filters.AuthorizationFilter;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static org.assertj.core.api.Assertions.assertThat;

class CustomizationResourceTest extends ResourceTest {

    private static final String V1_CUSTOMIZATION_TEXT_PLACEHOLDERS = "/v1/customization/text-placeholders";

    @RegisterExtension
    public static JerseyTestExtension jersey = new JerseyTestExtension(
            () -> new ResourceConfig(CustomizationResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class)
                    .register(AuthorizationFilter.class));

    // -------------------------------------------------------------------------
    // GET /v1/customization/text-placeholders
    // -------------------------------------------------------------------------

    @Test
    void getTextPlaceholderSettingsReturnsDefaultsWhenNotConfigured() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        Response response = jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertThat(response.getStatus()).isEqualTo(200);

        JsonObject json = parseJsonObject(response);
        assertThat(json.getBoolean("enabled")).isFalse();
        assertThat(json.getString("descriptionPlaceholder")).isNotBlank();
        assertThat(json.getString("recommendationPlaceholder")).isNotBlank();
        assertThat(json.getString("analysisDetailsInstruction")).isNotBlank();
    }

    // -------------------------------------------------------------------------
    // PUT /v1/customization/text-placeholders
    // -------------------------------------------------------------------------

    @Test
    void updateTextPlaceholderSettingsRoundTrip() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION, Permissions.VIEW_PORTFOLIO);

        Response putResponse = jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                            "enabled": true,
                            "descriptionPlaceholder": "Describe the issue here",
                            "commentPlaceholder": "List all reviewers"
                        }
                        """, MediaType.APPLICATION_JSON));
        assertThat(putResponse.getStatus()).isEqualTo(204);

        Response getResponse = jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        JsonObject json = parseJsonObject(getResponse);
        assertThat(json.getBoolean("enabled")).isTrue();
        assertThat(json.getString("descriptionPlaceholder")).isEqualTo("Describe the issue here");
        assertThat(json.getString("commentPlaceholder")).isEqualTo("List all reviewers");
        // Fields not included in the update keep their defaults
        assertThat(json.getString("recommendationPlaceholder")).isNotBlank();
    }

    @Test
    void updateTextPlaceholderSettingsRejectsUnknownOnlyFields() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("{\"somethingElse\": \"x\"}", MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    void updateTextPlaceholderSettingsRejectsNullValue() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("{\"descriptionPlaceholder\": null}", MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    void updateTextPlaceholderSettingsRejectsInvalidJson() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION);

        Response response = jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("not json at all", MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    void updateTextPlaceholderSettingsReturns403WithoutPermission() {
        // No permissions added to the team
        Response response = jersey.target(V1_CUSTOMIZATION_TEXT_PLACEHOLDERS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("{\"enabled\": true}", MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(403);
    }
}
