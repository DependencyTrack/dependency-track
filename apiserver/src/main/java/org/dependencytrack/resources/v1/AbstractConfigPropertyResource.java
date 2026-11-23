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
import alpine.model.IConfigProperty.PropertyType;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.BomValidationMode;
import org.dependencytrack.model.ConfigPropertyAccessMode;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.secret.management.SecretManager;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.core.Response;

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

    private final Logger LOGGER =
            LoggerFactory.getLogger(this.getClass()); // Use the classes that extend this, not this class itself
    private final SecretManager secretManager;

    AbstractConfigPropertyResource(SecretManager secretManager) {
        this.secretManager = secretManager;
    }

    @Nullable
    String normalizePropertyValue(
            String groupName, String propertyName, PropertyType propertyType, @Nullable String requestedValue) {
        final var wellKnownProperty = ConfigPropertyConstants.ofProperty(groupName, propertyName);
        if (wellKnownProperty != null && wellKnownProperty.getAccessMode() == ConfigPropertyAccessMode.READ_ONLY) {
            throw new ClientErrorException(Response.status(Response.Status.BAD_REQUEST)
                    .entity("The property %s.%s can not be modified".formatted(groupName, propertyName))
                    .build());
        }

        if (wellKnownProperty != null && wellKnownProperty.isSecretName()) {
            final String secretName = StringUtils.trimToNull(requestedValue);
            if (secretName != null && secretManager.getSecretMetadata(secretName) == null) {
                throw new ClientErrorException(Response.status(Response.Status.BAD_REQUEST)
                        .entity("The secret with name \"%s\" could not be found.".formatted(secretName))
                        .build());
            }

            return secretName;
        }

        if (propertyType == PropertyType.BOOLEAN) {
            final boolean propertyValue = BooleanUtil.valueOf(requestedValue);
            if (ConfigPropertyConstants.CUSTOM_RISK_SCORE_HISTORY_ENABLED
                    .getPropertyName()
                    .equals(propertyName)) {
                super.logSecurityEvent(
                        LOGGER,
                        SecurityMarkers.SECURITY_AUDIT,
                        "Attribute \"" + propertyName + "\" was changed to value: " + propertyValue + " by user "
                                + super.getPrincipal().getName());
            }
            return String.valueOf(propertyValue);
        }

        if (propertyType == PropertyType.INTEGER) {
            final int propertyValue;
            try {
                propertyValue = Integer.parseInt(requestedValue);
            } catch (NumberFormatException e) {
                throw new ClientErrorException(
                        Response.status(Response.Status.BAD_REQUEST)
                                .entity("The property expected an integer and an integer was not sent.")
                                .build(),
                        e);
            }
            if (ConfigPropertyConstants.CUSTOM_RISK_SCORE_CRITICAL
                            .getPropertyName()
                            .equals(propertyName)
                    || ConfigPropertyConstants.CUSTOM_RISK_SCORE_HIGH
                            .getPropertyName()
                            .equals(propertyName)
                    || ConfigPropertyConstants.CUSTOM_RISK_SCORE_MEDIUM
                            .getPropertyName()
                            .equals(propertyName)
                    || ConfigPropertyConstants.CUSTOM_RISK_SCORE_LOW
                            .getPropertyName()
                            .equals(propertyName)
                    || ConfigPropertyConstants.CUSTOM_RISK_SCORE_UNASSIGNED
                            .getPropertyName()
                            .equals(propertyName)) {
                if (propertyValue < 1 || propertyValue > 10) {
                    throw new ClientErrorException(Response.status(Response.Status.BAD_REQUEST)
                            .entity("Risk score \"" + propertyName
                                    + "\" must be between 1 and 10. An invalid value of " + propertyValue
                                    + " was provided.")
                            .build());
                }

                super.logSecurityEvent(
                        LOGGER,
                        SecurityMarkers.SECURITY_AUDIT,
                        "Risk score \"" + propertyName + "\" changed to value: " + propertyValue + " by user "
                                + super.getPrincipal().getName());
            }
            return String.valueOf(propertyValue);
        }

        if (propertyType == PropertyType.NUMBER) {
            try {
                new BigDecimal(requestedValue); // don't actually use it, just see if it's parses without exception
                return requestedValue;
            } catch (NumberFormatException e) {
                throw new ClientErrorException(
                        Response.status(Response.Status.BAD_REQUEST)
                                .entity("The property expected a number and a number was not sent.")
                                .build(),
                        e);
            }
        }

        if (propertyType == PropertyType.URL) {
            if (requestedValue == null) {
                return null;
            }
            try {
                final URL url = new URI(requestedValue).toURL();
                return url.toExternalForm();
            } catch (MalformedURLException | URISyntaxException | IllegalArgumentException e) {
                throw new ClientErrorException(
                        Response.status(Response.Status.BAD_REQUEST)
                                .entity("The property expected a URL but the URL was malformed.")
                                .build(),
                        e);
            }
        }

        if (propertyType == PropertyType.UUID) {
            if (!UuidUtil.isValidUUID(requestedValue)) {
                throw new ClientErrorException(Response.status(Response.Status.BAD_REQUEST)
                        .entity("The property expected a UUID but a valid UUID was not sent.")
                        .build());
            }
            return requestedValue;
        }

        if (ConfigPropertyConstants.BOM_VALIDATION_MODE.getPropertyName().equals(propertyName)) {
            try {
                BomValidationMode.valueOf(requestedValue);
                return requestedValue;
            } catch (IllegalArgumentException e) {
                throw new ClientErrorException(
                        Response.status(Response.Status.BAD_REQUEST)
                                .entity("Value must be any of: %s"
                                        .formatted(Arrays.stream(BomValidationMode.values())
                                                .map(Enum::name)
                                                .collect(Collectors.joining(", "))))
                                .build(),
                        e);
            }
        }

        if (ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE
                        .getPropertyName()
                        .equals(propertyName)
                || ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE
                        .getPropertyName()
                        .equals(propertyName)) {
            try {
                final JsonReader jsonReader = Json.createReader(new StringReader(requestedValue));
                final JsonArray jsonArray = jsonReader.readArray();
                jsonArray.getValuesAs(JsonString::getString);

                // NB: Storing the string representation of the parsed array instead of the original value,
                // since this removes any unnecessary whitespace.
                return jsonArray.toString();
            } catch (RuntimeException e) {
                throw new ClientErrorException(
                        Response.status(Response.Status.BAD_REQUEST)
                                .entity("Value must be a valid JSON array of strings")
                                .build(),
                        e);
            }
        }

        return requestedValue;
    }
}
