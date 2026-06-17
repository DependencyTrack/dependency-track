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
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.secret.management.SecretManager;
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

abstract class AbstractConfigPropertyResource extends AbstractApiResource {

    private final Logger LOGGER = LoggerFactory.getLogger(this.getClass()); // Use the classes that extend this, not this class itself
    private final SecretManager secretManager;

    AbstractConfigPropertyResource(SecretManager secretManager) {
        this.secretManager = secretManager;
    }

    Response updatePropertyValue(QueryManager qm, IConfigProperty json, IConfigProperty property) {
        if (property != null) {
            final Response check = updatePropertyValueInternal(json, property);
            if (check != null) {
                return check;
            }
            property = qm.persist(property);
            IConfigProperty detached = qm.detach(property.getClass(), property.getId());
            return Response.ok(detached).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).entity("The config property could not be found.").build();
        }
    }

    private Response updatePropertyValueInternal(IConfigProperty json, IConfigProperty property) {
        final var wellKnownProperty = ConfigPropertyConstants.ofProperty(property);
        if (wellKnownProperty != null && wellKnownProperty.getAccessMode() == ConfigPropertyAccessMode.READ_ONLY) {
            return Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity("The property %s.%s can not be modified".formatted(property.getGroupName(), property.getPropertyName()))
                    .build();
        }

        if (wellKnownProperty != null && wellKnownProperty.isSecretName()) {
            final String secretName = StringUtils.trimToNull(json.getPropertyValue());
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
            boolean propertyValue = BooleanUtil.valueOf(json.getPropertyValue());
            if (ConfigPropertyConstants.CUSTOM_RISK_SCORE_HISTORY_ENABLED.getPropertyName().equals(json.getPropertyName())) {
                super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Attribute \"" + json.getPropertyName() + "\" was changed to value: " + String.valueOf(propertyValue) + " by user " + super.getPrincipal().getName());
            }
            property.setPropertyValue(String.valueOf(BooleanUtil.valueOf(json.getPropertyValue())));
        } else if (property.getPropertyType() == IConfigProperty.PropertyType.INTEGER) {
            try {
                int propertyValue = Integer.parseInt(json.getPropertyValue());
                if (ConfigPropertyConstants.CUSTOM_RISK_SCORE_CRITICAL.getPropertyName().equals(json.getPropertyName()) ||
                        ConfigPropertyConstants.CUSTOM_RISK_SCORE_HIGH.getPropertyName().equals(json.getPropertyName()) ||
                        ConfigPropertyConstants.CUSTOM_RISK_SCORE_MEDIUM.getPropertyName().equals(json.getPropertyName()) ||
                        ConfigPropertyConstants.CUSTOM_RISK_SCORE_LOW.getPropertyName().equals(json.getPropertyName()) ||
                        ConfigPropertyConstants.CUSTOM_RISK_SCORE_UNASSIGNED.getPropertyName().equals(json.getPropertyName())
                ) {
                    if (propertyValue < 1 || propertyValue > 10) {
                        return Response.status(Response.Status.BAD_REQUEST).entity("Risk score \"" + json.getPropertyName() + "\" must be between 1 and 10. An invalid value of " + propertyValue + " was provided.").build();
                    }
                    super.logSecurityEvent(LOGGER, SecurityMarkers.SECURITY_AUDIT, "Risk score \"" + json.getPropertyName() + "\" changed to value: " + propertyValue + " by user " + super.getPrincipal().getName());
                }
                property.setPropertyValue(String.valueOf(propertyValue));
            } catch (NumberFormatException e) {
                return Response.status(Response.Status.BAD_REQUEST).entity("The property expected an integer and an integer was not sent.").build();
            }
        } else if (property.getPropertyType() == IConfigProperty.PropertyType.NUMBER) {
            try {
                new BigDecimal(json.getPropertyValue());  // don't actually use it, just see if it's parses without exception
                property.setPropertyValue(json.getPropertyValue());
            } catch (NumberFormatException e) {
                return Response.status(Response.Status.BAD_REQUEST).entity("The property expected a number and a number was not sent.").build();
            }
        } else if (property.getPropertyType() == IConfigProperty.PropertyType.URL) {
            if (json.getPropertyValue() == null) {
                property.setPropertyValue(null);
            } else {
                try {
                    final URL url = new URI(json.getPropertyValue()).toURL();
                    property.setPropertyValue(url.toExternalForm());
                } catch (MalformedURLException | URISyntaxException | IllegalArgumentException e) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("The property expected a URL but the URL was malformed.").build();
                }
            }
        } else if (property.getPropertyType() == IConfigProperty.PropertyType.UUID) {
            if (UuidUtil.isValidUUID(json.getPropertyValue())) {
                property.setPropertyValue(json.getPropertyValue());
            } else {
                return Response.status(Response.Status.BAD_REQUEST).entity("The property expected a UUID but a valid UUID was not sent.").build();
            }
        } else if (ConfigPropertyConstants.BOM_VALIDATION_MODE.getPropertyName().equals(json.getPropertyName())) {
            try {
                BomValidationMode.valueOf(json.getPropertyValue());
                property.setPropertyValue(json.getPropertyValue());
            } catch (IllegalArgumentException e) {
                return Response
                        .status(Response.Status.BAD_REQUEST)
                        .entity("Value must be any of: %s".formatted(Arrays.stream(BomValidationMode.values()).map(Enum::name).collect(Collectors.joining(", "))))
                        .build();
            }
        } else if (ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE.getPropertyName().equals(json.getPropertyName())
                || ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE.getPropertyName().equals(json.getPropertyName())) {
            try {
                final JsonReader jsonReader = Json.createReader(new StringReader(json.getPropertyValue()));
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
            property.setPropertyValue(json.getPropertyValue());
        }
        return null;
    }
}
