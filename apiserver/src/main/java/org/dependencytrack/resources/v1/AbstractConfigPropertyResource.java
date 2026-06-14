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

import alpine.common.util.BooleanUtil;
import alpine.common.util.UuidUtil;
import alpine.model.IConfigProperty;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
import jakarta.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.BomValidationMode;
import org.dependencytrack.model.ConfigPropertyAccessMode;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.util.PersistenceUtil;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.StringReader;
import java.math.BigDecimal;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.stream.Collectors;

@NullMarked
abstract class AbstractConfigPropertyResource extends AbstractApiResource {

    private final Logger LOGGER = LoggerFactory.getLogger(this.getClass()); // Use the classes that extend this, not this class itself
    private final SecretManager secretManager;

    AbstractConfigPropertyResource(SecretManager secretManager) {
        this.secretManager = secretManager;
    }

    Response updatePropertyValue(IConfigProperty json, @Nullable IConfigProperty property) {
        if (property == null) {
            return Response
                    .status(Response.Status.NOT_FOUND)
                    .entity("The config property could not be found.")
                    .build();
        }

        final Response check = applyPropertyValue(json.getPropertyValue(), property);
        if (check != null) {
            return check;
        }

        return Response.ok(property).build();
    }

    @Nullable Response applyPropertyValue(@Nullable String requestedValue, IConfigProperty property) {
        PersistenceUtil.assertPersistent(property, "property must be persistent");

        final var wellKnownProperty = ConfigPropertyConstants.ofProperty(property);
        if (wellKnownProperty != null
                && wellKnownProperty.getAccessMode() == ConfigPropertyAccessMode.READ_ONLY) {
            return Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity("The property %s.%s can not be modified".formatted(
                            property.getGroupName(), property.getPropertyName()))
                    .build();
        }

        if (wellKnownProperty != null && wellKnownProperty.isSecretName()) {
            final String secretName = StringUtils.trimToNull(requestedValue);
            if (secretName != null && secretManager.getSecretMetadata(secretName) == null) {
                return Response
                        .status(Response.Status.BAD_REQUEST)
                        .entity("The secret with name \"%s\" could not be found.".formatted(secretName))
                        .build();
            }

            property.setPropertyValue(secretName);
            return null;
        }

        if (property.getPropertyType() == IConfigProperty.PropertyType.BOOLEAN) {
            final boolean propertyValue = BooleanUtil.valueOf(requestedValue);
            if (ConfigPropertyConstants.CUSTOM_RISK_SCORE_HISTORY_ENABLED.getPropertyName().equals(property.getPropertyName())) {
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Attribute \"" + property.getPropertyName() + "\" was changed to value: " + propertyValue + " by user " + super.getPrincipal().getName());
            }
            property.setPropertyValue(String.valueOf(propertyValue));
        } else if (property.getPropertyType() == IConfigProperty.PropertyType.INTEGER) {
            try {
                final int propertyValue = Integer.parseInt(requestedValue);
                if (ConfigPropertyConstants.CUSTOM_RISK_SCORE_CRITICAL.getPropertyName().equals(property.getPropertyName())
                        || ConfigPropertyConstants.CUSTOM_RISK_SCORE_HIGH.getPropertyName().equals(property.getPropertyName())
                        || ConfigPropertyConstants.CUSTOM_RISK_SCORE_MEDIUM.getPropertyName().equals(property.getPropertyName())
                        || ConfigPropertyConstants.CUSTOM_RISK_SCORE_LOW.getPropertyName().equals(property.getPropertyName())
                        || ConfigPropertyConstants.CUSTOM_RISK_SCORE_UNASSIGNED.getPropertyName().equals(property.getPropertyName())) {
                    if (propertyValue < 1 || propertyValue > 10) {
                        return Response
                                .status(Response.Status.BAD_REQUEST)
                                .entity("Risk score \"" + property.getPropertyName() + "\" must be between 1 and 10. An invalid value of " + propertyValue + " was provided.")
                                .build();
                    }

                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Risk score \"" + property.getPropertyName() + "\" changed to value: " + propertyValue + " by user " + super.getPrincipal().getName());
                }
                property.setPropertyValue(String.valueOf(propertyValue));
            } catch (NumberFormatException e) {
                return Response
                        .status(Response.Status.BAD_REQUEST)
                        .entity("The property expected an integer and an integer was not sent.")
                        .build();
            }
        } else if (property.getPropertyType() == IConfigProperty.PropertyType.NUMBER) {
            try {
                new BigDecimal(requestedValue);  // don't actually use it, just see if it's parses without exception
                property.setPropertyValue(requestedValue);
            } catch (NumberFormatException e) {
                return Response
                        .status(Response.Status.BAD_REQUEST)
                        .entity("The property expected a number and a number was not sent.")
                        .build();
            }
        } else if (property.getPropertyType() == IConfigProperty.PropertyType.URL) {
            if (requestedValue == null) {
                property.setPropertyValue(null);
            } else {
                try {
                    final URL url = new URI(requestedValue).toURL();
                    property.setPropertyValue(url.toExternalForm());
                } catch (MalformedURLException | URISyntaxException | IllegalArgumentException e) {
                    return Response
                            .status(Response.Status.BAD_REQUEST)
                            .entity("The property expected a URL but the URL was malformed.")
                            .build();
                }
            }
        } else if (property.getPropertyType() == IConfigProperty.PropertyType.UUID) {
            if (UuidUtil.isValidUUID(requestedValue)) {
                property.setPropertyValue(requestedValue);
            } else {
                return Response
                        .status(Response.Status.BAD_REQUEST)
                        .entity("The property expected a UUID but a valid UUID was not sent.")
                        .build();
            }
        } else if (ConfigPropertyConstants.BOM_VALIDATION_MODE.getPropertyName().equals(property.getPropertyName())) {
            try {
                BomValidationMode.valueOf(requestedValue);
                property.setPropertyValue(requestedValue);
            } catch (IllegalArgumentException e) {
                return Response
                        .status(Response.Status.BAD_REQUEST)
                        .entity("Value must be any of: %s".formatted(Arrays.stream(BomValidationMode.values()).map(Enum::name).collect(Collectors.joining(", "))))
                        .build();
            }
        } else if (ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE.getPropertyName().equals(property.getPropertyName())
                || ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE.getPropertyName().equals(property.getPropertyName())) {
            try {
                final JsonReader jsonReader = Json.createReader(new StringReader(requestedValue));
                final JsonArray jsonArray = jsonReader.readArray();
                jsonArray.getValuesAs(JsonString::getString);

                // NB: Storing the string representation of the parsed array instead of the original value,
                // since this removes any unnecessary whitespace.
                property.setPropertyValue(jsonArray.toString());
            } catch (RuntimeException e) {
                return Response
                        .status(Response.Status.BAD_REQUEST)
                        .entity("Value must be a valid JSON array of strings")
                        .build();
            }
        } else {
            property.setPropertyValue(requestedValue);
        }

        return null;
    }
}
