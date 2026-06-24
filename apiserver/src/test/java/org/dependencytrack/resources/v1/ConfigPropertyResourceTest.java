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

import alpine.model.IConfigProperty.PropertyType;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthFeature;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.ConfigPropertyVisibility;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.secret.management.SecretMetadata;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_CRITICAL;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_HIGH;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_LOW;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_MEDIUM;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_UNASSIGNED;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ConfigPropertyResourceTest extends ResourceTest {

    private static final SecretManager secretManager = mock(SecretManager.class);

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(ConfigPropertyResource.class)
                    .register(ApiFilter.class)
                    .register(AuthFeature.class)
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bind(secretManager).to(SecretManager.class);
                        }
                    }));

    @Test
    void shouldReturnFullJsonForGetConfigProperties() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        qm.createConfigProperty("my.group", "my.string", "ABC", PropertyType.STRING, "A string");
        qm.createConfigProperty("my.group", "my.integer", "1", PropertyType.INTEGER, "A integer");

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "groupName": "my.group",
                    "propertyName": "my.integer",
                    "propertyValue": "1",
                    "propertyType": "INTEGER",
                    "description": "A integer"
                  },
                  {
                    "groupName": "my.group",
                    "propertyName": "my.string",
                    "propertyValue": "ABC",
                    "propertyType": "STRING",
                    "description": "A string"
                  }
                ]
                """);
    }

    @Test
    void shouldUpdateStringProperty() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        qm.createConfigProperty("my.group", "my.string", "ABC", PropertyType.STRING, "A string");

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "my.group",
                          "propertyName": "my.string",
                          "propertyValue": "DEF"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "groupName": "my.group",
                  "propertyName": "my.string",
                  "propertyValue": "DEF",
                  "propertyType": "STRING",
                  "description": "A string"
                }
                """);
    }

    @Test
    void shouldUpdateBooleanProperty() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        qm.createConfigProperty("my.group", "my.boolean", "false", PropertyType.BOOLEAN, "A boolean");

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "my.group",
                          "propertyName": "my.boolean",
                          "propertyValue": "true"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "groupName": "my.group",
                  "propertyName": "my.boolean",
                  "propertyValue": "true",
                  "propertyType": "BOOLEAN",
                  "description": "A boolean"
                }
                """);
    }

    @Test
    void shouldUpdateNumberProperty() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        qm.createConfigProperty("my.group", "my.number", "7.75", PropertyType.NUMBER, "A number");

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "my.group",
                          "propertyName": "my.number",
                          "propertyValue": "5.50"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "groupName": "my.group",
                  "propertyName": "my.number",
                  "propertyValue": "5.50",
                  "propertyType": "NUMBER",
                  "description": "A number"
                }
                """);
    }

    @Test
    void shouldUpdateUrlProperty() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        qm.createConfigProperty("my.group", "my.url", "http://localhost", PropertyType.URL, "A url");

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "my.group",
                          "propertyName": "my.url",
                          "propertyValue": "http://localhost/path"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "groupName": "my.group",
                  "propertyName": "my.url",
                  "propertyValue": "http://localhost/path",
                  "propertyType": "URL",
                  "description": "A url"
                }
                """);
    }

    @Test
    void shouldUpdateUuidProperty() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        qm.createConfigProperty("my.group", "my.uuid", "a496cabc-749d-4751-b9e5-3b49b656d018", PropertyType.UUID, "A uuid");

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "my.group",
                          "propertyName": "my.uuid",
                          "propertyValue": "fe03c401-b5a1-4b86-bc3b-1b7a68f0f78d"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "groupName": "my.group",
                  "propertyName": "my.uuid",
                  "propertyValue": "fe03c401-b5a1-4b86-bc3b-1b7a68f0f78d",
                  "propertyType": "UUID",
                  "description": "A uuid"
                }
                """);
    }

    @Test
    void shouldRejectUpdateOfReadOnlyProperty() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        qm.createConfigProperty(
                ConfigPropertyConstants.INTERNAL_CLUSTER_ID.getGroupName(),
                ConfigPropertyConstants.INTERNAL_CLUSTER_ID.getPropertyName(),
                ConfigPropertyConstants.INTERNAL_CLUSTER_ID.getDefaultPropertyValue(),
                ConfigPropertyConstants.INTERNAL_CLUSTER_ID.getPropertyType(),
                ConfigPropertyConstants.INTERNAL_CLUSTER_ID.getDescription());

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "internal",
                          "propertyName": "cluster.id",
                          "propertyValue": "foobar"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("The property internal.cluster.id can not be modified");
    }

    @Test
    void shouldRejectInvalidRiskScore() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        createRiskScoreProperties();

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "risk-score",
                          "propertyName": "weight.critical",
                          "propertyValue": "11"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response))
                .isEqualTo("Risk score \"weight.critical\" must be between 1 and 10. An invalid value of 11 was provided.");
    }

    @Test
    void shouldUpdateRiskScore() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        createRiskScoreProperties();

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "risk-score",
                          "propertyName": "weight.critical",
                          "propertyValue": "8"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "groupName": "risk-score",
                  "propertyName": "weight.critical",
                  "propertyValue": "8",
                  "propertyType": "INTEGER",
                  "description": "Critical severity vulnerability weight (between 1-10)"
                }
                """);
    }

    @Test
    void shouldUpdateAggregatedProperties() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        qm.createConfigProperty("my.group", "my.string1", "ABC", PropertyType.STRING, "A string");
        qm.createConfigProperty("my.group", "my.string2", "DEF", PropertyType.STRING, "A string");
        qm.createConfigProperty("my.group", "my.string3", "GHI", PropertyType.STRING, "A string");

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY + "/aggregate")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        [
                          {
                            "groupName": "my.group",
                            "propertyName": "my.string1",
                            "propertyValue": "ABC"
                          },
                          {
                            "groupName": "my.group",
                            "propertyName": "my.string2",
                            "propertyValue": "DEF"
                          },
                          {
                            "groupName": "my.group",
                            "propertyName": "my.string3",
                            "propertyValue": "XYZ"
                          }
                        ]
                        """));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "groupName": "my.group",
                    "propertyName": "my.string1",
                    "propertyValue": "ABC",
                    "propertyType": "STRING",
                    "description": "A string"
                  },
                  {
                    "groupName": "my.group",
                    "propertyName": "my.string2",
                    "propertyValue": "DEF",
                    "propertyType": "STRING",
                    "description": "A string"
                  },
                  {
                    "groupName": "my.group",
                    "propertyName": "my.string3",
                    "propertyValue": "XYZ",
                    "propertyType": "STRING",
                    "description": "A string"
                  }
                ]
                """);
    }

    @Test
    void shouldPreserveMixedResponseShapeWhenAggregateIncludesUnknownProperty() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        qm.createConfigProperty("my.group", "known", "ABC", PropertyType.STRING, "A string");

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY + "/aggregate")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        [
                          {
                            "groupName": "my.group",
                            "propertyName": "known",
                            "propertyValue": "DEF"
                          },
                          {
                            "groupName": "my.group",
                            "propertyName": "unknown",
                            "propertyValue": "anything"
                          }
                        ]
                        """));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "groupName": "my.group",
                    "propertyName": "known",
                    "propertyValue": "DEF",
                    "propertyType": "STRING",
                    "description": "A string"
                  },
                  "The config property could not be found."
                ]
                """);
    }

    @Test
    void shouldUpdateBomValidationMode() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        qm.createConfigProperty(
                ConfigPropertyConstants.BOM_VALIDATION_MODE.getGroupName(),
                ConfigPropertyConstants.BOM_VALIDATION_MODE.getPropertyName(),
                ConfigPropertyConstants.BOM_VALIDATION_MODE.getDefaultPropertyValue(),
                ConfigPropertyConstants.BOM_VALIDATION_MODE.getPropertyType(),
                ConfigPropertyConstants.BOM_VALIDATION_MODE.getDescription());

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "artifact",
                          "propertyName": "bom.validation.mode",
                          "propertyValue": "ENABLED_FOR_TAGS"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "groupName": "artifact",
                  "propertyName": "bom.validation.mode",
                  "propertyValue": "ENABLED_FOR_TAGS",
                  "propertyType": "STRING",
                  "description": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    void shouldRejectInvalidBomValidationMode() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        qm.createConfigProperty(
                ConfigPropertyConstants.BOM_VALIDATION_MODE.getGroupName(),
                ConfigPropertyConstants.BOM_VALIDATION_MODE.getPropertyName(),
                ConfigPropertyConstants.BOM_VALIDATION_MODE.getDefaultPropertyValue(),
                ConfigPropertyConstants.BOM_VALIDATION_MODE.getPropertyType(),
                ConfigPropertyConstants.BOM_VALIDATION_MODE.getDescription());

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "artifact",
                          "propertyName": "bom.validation.mode",
                          "propertyValue": "foo"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response))
                .isEqualTo("Value must be any of: ENABLED, DISABLED, ENABLED_FOR_TAGS, DISABLED_FOR_TAGS");
    }

    @Test
    void shouldUpdateBomValidationTagsExclusive() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        qm.createConfigProperty(
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE.getGroupName(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE.getPropertyName(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE.getDefaultPropertyValue(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE.getPropertyType(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE.getDescription());

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "artifact",
                          "propertyName": "bom.validation.tags.exclusive",
                          "propertyValue": "[\\"foo\\"]"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "groupName": "artifact",
                  "propertyName": "bom.validation.tags.exclusive",
                  "propertyValue": "[\\"foo\\"]",
                  "propertyType": "STRING",
                  "description": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    void shouldRejectInvalidBomValidationTagsExclusive() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        qm.createConfigProperty(
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE.getGroupName(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE.getPropertyName(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE.getDefaultPropertyValue(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE.getPropertyType(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE.getDescription());

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "artifact",
                          "propertyName": "bom.validation.tags.exclusive",
                          "propertyValue": "foo"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("Value must be a valid JSON array of strings");
    }

    @Test
    void shouldUpdateBomValidationTagsInclusive() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        qm.createConfigProperty(
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE.getGroupName(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE.getPropertyName(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE.getDefaultPropertyValue(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE.getPropertyType(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE.getDescription());

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "artifact",
                          "propertyName": "bom.validation.tags.inclusive",
                          "propertyValue": "[\\"foo\\"]"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "groupName": "artifact",
                  "propertyName": "bom.validation.tags.inclusive",
                  "propertyValue": "[\\"foo\\"]",
                  "propertyType": "STRING",
                  "description": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    void shouldRejectInvalidBomValidationTagsInclusive() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        qm.createConfigProperty(
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE.getGroupName(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE.getPropertyName(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE.getDefaultPropertyValue(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE.getPropertyType(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE.getDescription());

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "artifact",
                          "propertyName": "bom.validation.tags.inclusive",
                          "propertyValue": "foo"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("Value must be a valid JSON array of strings");
    }

    @Test
    void shouldRejectUnknownSecretName() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        qm.createConfigProperty(
                ConfigPropertyConstants.FORTIFY_SSC_TOKEN.getGroupName(),
                ConfigPropertyConstants.FORTIFY_SSC_TOKEN.getPropertyName(),
                ConfigPropertyConstants.FORTIFY_SSC_TOKEN.getDefaultPropertyValue(),
                ConfigPropertyConstants.FORTIFY_SSC_TOKEN.getPropertyType(),
                ConfigPropertyConstants.FORTIFY_SSC_TOKEN.getDescription());

        when(secretManager.getSecretMetadata("nonexistent-secret")).thenReturn(null);

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "integrations",
                          "propertyName": "fortify.ssc.token",
                          "propertyValue": "nonexistent-secret"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response))
                .isEqualTo("The secret with name \"nonexistent-secret\" could not be found.");
    }

    @Test
    void shouldAcceptKnownSecretName() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        qm.createConfigProperty(
                ConfigPropertyConstants.KENNA_TOKEN.getGroupName(),
                ConfigPropertyConstants.KENNA_TOKEN.getPropertyName(),
                ConfigPropertyConstants.KENNA_TOKEN.getDefaultPropertyValue(),
                ConfigPropertyConstants.KENNA_TOKEN.getPropertyType(),
                ConfigPropertyConstants.KENNA_TOKEN.getDescription());

        when(secretManager.getSecretMetadata("my-secret"))
                .thenReturn(new SecretMetadata("my-secret", null, null, null));

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "integrations",
                          "propertyName": "kenna.token",
                          "propertyValue": "my-secret"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "groupName": "integrations",
                  "propertyName": "kenna.token",
                  "propertyValue": "my-secret",
                  "propertyType": "STRING",
                  "description": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    void shouldReturn404WhenUpdatingUnknownConfigProperty() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "my.group",
                          "propertyName": "does.not.exist",
                          "propertyValue": "anything"
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The config property could not be found.");
    }

    @Test
    void shouldReturnFullJsonForPublicConfigProperty() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY
                        + "/public/" + ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName()
                        + "/" + ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "groupName": "access-management",
                  "propertyName": "acl.enabled",
                  "propertyValue": "true",
                  "propertyType": "BOOLEAN",
                  "description": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    void shouldReturn403ForNonPublicConfigProperty() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        for (final ConfigPropertyConstants configProperty : ConfigPropertyConstants.values()) {
            qm.createConfigProperty(
                    configProperty.getGroupName(),
                    configProperty.getPropertyName(),
                    configProperty.getDefaultPropertyValue(),
                    configProperty.getPropertyType(),
                    configProperty.getDescription());

            final Response response = jersey
                    .target(V1_CONFIG_PROPERTY
                            + "/public/" + configProperty.getGroupName()
                            + "/" + configProperty.getPropertyName())
                    .request()
                    .header(X_API_KEY, apiKey)
                    .get();

            final int expectedStatus =
                    configProperty.getVisibility() == ConfigPropertyVisibility.PUBLIC
                            ? 200
                            : 403;
            assertThat(response.getStatus()).isEqualTo(expectedStatus);
        }
    }

    @Test
    void shouldReturn403WhenPublicEndpointPathParamsDoNotMatchKnownProperty() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY + "/public/unknown.group/unknown.property")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void shouldReturn404WhenPublicConfigPropertyDoesNotExist() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY
                        + "/public/" + ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName()
                        + "/" + ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The config property could not be found.");
    }

    @Test
    void shouldReturnFullJsonForInternalConfigProperty() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        qm.createConfigProperty(
                ConfigPropertyConstants.BANNER_CONFIG.getGroupName(),
                ConfigPropertyConstants.BANNER_CONFIG.getPropertyName(),
                ConfigPropertyConstants.BANNER_CONFIG.getDefaultPropertyValue(),
                ConfigPropertyConstants.BANNER_CONFIG.getPropertyType(),
                ConfigPropertyConstants.BANNER_CONFIG.getDescription());

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY
                        + "/internal/" + ConfigPropertyConstants.BANNER_CONFIG.getGroupName()
                        + "/" + ConfigPropertyConstants.BANNER_CONFIG.getPropertyName())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "groupName": "banner",
                  "propertyName": "config",
                  "propertyValue": "{}",
                  "propertyType": "STRING",
                  "description": "${json-unit.any-string}"
                }
                """);
    }

    @Test
    void shouldReturn403ForRestrictedConfigPropertyViaInternalEndpoint() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        for (final var configProperty : ConfigPropertyConstants.values()) {
            qm.createConfigProperty(
                    configProperty.getGroupName(),
                    configProperty.getPropertyName(),
                    configProperty.getDefaultPropertyValue(),
                    configProperty.getPropertyType(),
                    configProperty.getDescription());

            final Response response = jersey
                    .target(V1_CONFIG_PROPERTY
                            + "/internal/" + configProperty.getGroupName()
                            + "/" + configProperty.getPropertyName())
                    .request()
                    .header(X_API_KEY, apiKey)
                    .get();

            final int expectedStatus =
                    configProperty.getVisibility() == ConfigPropertyVisibility.RESTRICTED
                            ? 403
                            : 200;
            assertThat(response.getStatus()).isEqualTo(expectedStatus);
        }
    }

    @Test
    void shouldReadPublicConfigPropertyWithoutAuthentication() {
        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY
                        + "/public/" + ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName()
                        + "/" + ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName())
                .request()
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void shouldRequireAuthenticationForInternalConfigProperty() {
        qm.createConfigProperty(
                ConfigPropertyConstants.BANNER_CONFIG.getGroupName(),
                ConfigPropertyConstants.BANNER_CONFIG.getPropertyName(),
                ConfigPropertyConstants.BANNER_CONFIG.getDefaultPropertyValue(),
                ConfigPropertyConstants.BANNER_CONFIG.getPropertyType(),
                ConfigPropertyConstants.BANNER_CONFIG.getDescription());

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY
                        + "/internal/" + ConfigPropertyConstants.BANNER_CONFIG.getGroupName()
                        + "/" + ConfigPropertyConstants.BANNER_CONFIG.getPropertyName())
                .request()
                .get();

        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void shouldReadInternalConfigPropertyWithoutPermission() {
        qm.createConfigProperty(
                ConfigPropertyConstants.BANNER_CONFIG.getGroupName(),
                ConfigPropertyConstants.BANNER_CONFIG.getPropertyName(),
                ConfigPropertyConstants.BANNER_CONFIG.getDefaultPropertyValue(),
                ConfigPropertyConstants.BANNER_CONFIG.getPropertyType(),
                ConfigPropertyConstants.BANNER_CONFIG.getDescription());

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY
                        + "/internal/" + ConfigPropertyConstants.BANNER_CONFIG.getGroupName()
                        + "/" + ConfigPropertyConstants.BANNER_CONFIG.getPropertyName())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void shouldReturnPublicConfigPropertyViaInternalEndpoint() {
        qm.createConfigProperty(
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(),
                "true",
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(),
                ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());

        final Response response = jersey
                .target(V1_CONFIG_PROPERTY
                        + "/internal/" + ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName()
                        + "/" + ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "groupName": "access-management",
                  "propertyName": "acl.enabled",
                  "propertyValue": "true",
                  "propertyType": "BOOLEAN",
                  "description": "${json-unit.any-string}"
                }
                """);
    }

    private void createRiskScoreProperties() {
        qm.createConfigProperty(
                CUSTOM_RISK_SCORE_CRITICAL.getGroupName(),
                CUSTOM_RISK_SCORE_CRITICAL.getPropertyName(),
                CUSTOM_RISK_SCORE_CRITICAL.getDefaultPropertyValue(),
                CUSTOM_RISK_SCORE_CRITICAL.getPropertyType(),
                CUSTOM_RISK_SCORE_CRITICAL.getDescription());
        qm.createConfigProperty(
                CUSTOM_RISK_SCORE_HIGH.getGroupName(),
                CUSTOM_RISK_SCORE_HIGH.getPropertyName(),
                CUSTOM_RISK_SCORE_HIGH.getDefaultPropertyValue(),
                CUSTOM_RISK_SCORE_HIGH.getPropertyType(),
                CUSTOM_RISK_SCORE_HIGH.getDescription());
        qm.createConfigProperty(
                CUSTOM_RISK_SCORE_MEDIUM.getGroupName(),
                CUSTOM_RISK_SCORE_MEDIUM.getPropertyName(),
                CUSTOM_RISK_SCORE_MEDIUM.getDefaultPropertyValue(),
                CUSTOM_RISK_SCORE_MEDIUM.getPropertyType(),
                CUSTOM_RISK_SCORE_MEDIUM.getDescription());
        qm.createConfigProperty(
                CUSTOM_RISK_SCORE_LOW.getGroupName(),
                CUSTOM_RISK_SCORE_LOW.getPropertyName(),
                CUSTOM_RISK_SCORE_LOW.getDefaultPropertyValue(),
                CUSTOM_RISK_SCORE_LOW.getPropertyType(),
                CUSTOM_RISK_SCORE_LOW.getDescription());
        qm.createConfigProperty(
                CUSTOM_RISK_SCORE_UNASSIGNED.getGroupName(),
                CUSTOM_RISK_SCORE_UNASSIGNED.getPropertyName(),
                CUSTOM_RISK_SCORE_UNASSIGNED.getDefaultPropertyValue(),
                CUSTOM_RISK_SCORE_UNASSIGNED.getPropertyType(),
                CUSTOM_RISK_SCORE_UNASSIGNED.getDescription());
    }

}
