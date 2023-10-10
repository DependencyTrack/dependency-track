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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.resources.v1;

import alpine.common.logging.Logger;
import alpine.common.util.BooleanUtil;
import alpine.common.util.UuidUtil;
import alpine.model.IConfigProperty;
import alpine.security.crypto.DataEncryption;
import alpine.server.resources.AlpineResource;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.persistence.QueryManager;

import javax.ws.rs.core.Response;
import java.math.BigDecimal;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

abstract class AbstractConfigPropertyResource extends AlpineResource {

    private final Logger LOGGER = Logger.getLogger(this.getClass()); // Use the classes that extend this, not this class itself
    static final String ENCRYPTED_PLACEHOLDER = "HiddenDecryptedPropertyPlaceholder";

    Response updatePropertyValue(QueryManager qm, IConfigProperty json, IConfigProperty property) {
        if (property != null) {
            final Response check = updatePropertyValueInternal(json, property);
            if (check != null) {
                return check;
            }
            property = qm.persist(property);
            IConfigProperty detached = qm.detach(property.getClass(), property.getId());
            if (IConfigProperty.PropertyType.ENCRYPTEDSTRING == detached.getPropertyType()) {
                detached.setPropertyValue(ENCRYPTED_PLACEHOLDER);
            }
            return Response.ok(detached).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).entity("The config property could not be found.").build();
        }
    }

    private Response updatePropertyValueInternal(IConfigProperty json, IConfigProperty property) {
        if (property.getPropertyType() == IConfigProperty.PropertyType.BOOLEAN) {
            property.setPropertyValue(String.valueOf(BooleanUtil.valueOf(json.getPropertyValue())));
        } else if (property.getPropertyType() == IConfigProperty.PropertyType.INTEGER) {
            try {
                int propertyValue = Integer.parseInt(json.getPropertyValue());
                if(ConfigPropertyConstants.TASK_SCHEDULER_LDAP_SYNC_CADENCE.getGroupName().equals(json.getGroupName()) && propertyValue <= 0) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("A Task scheduler cadence ("+json.getPropertyName()+") cannot be inferior to one hour.A value of "+propertyValue+" was provided.").build();
                }
                if(ConfigPropertyConstants.SEARCH_INDEXES_CONSISTENCY_CHECK_DELTA_THRESHOLD.getPropertyName().equals(json.getPropertyName()) && (propertyValue < 1 || propertyValue > 100)) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("Lucene index delta threshold ("+json.getPropertyName()+") cannot be inferior to 1 or superior to 100.A value of "+propertyValue+" was provided.").build();
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
                    final URL url = new URL(json.getPropertyValue());
                    property.setPropertyValue(url.toExternalForm());
                } catch (MalformedURLException e) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("The property expected a URL but the URL was malformed.").build();
                }
            }
        } else if (property.getPropertyType() == IConfigProperty.PropertyType.UUID) {
            if (UuidUtil.isValidUUID(json.getPropertyValue())) {
                property.setPropertyValue(json.getPropertyValue());
            } else {
                return Response.status(Response.Status.BAD_REQUEST).entity("The property expected a UUID but a valid UUID was not sent.").build();
            }
        } else if (property.getPropertyType() == IConfigProperty.PropertyType.ENCRYPTEDSTRING) {
            if (json.getPropertyValue() == null) {
                property.setPropertyValue(null);
            } else {
                try {
                    // Determine if the value of the encrypted property value is that of the placeholder. If so, the value has not been modified and should not be saved.
                    if (ENCRYPTED_PLACEHOLDER.equals(json.getPropertyValue())) {
                        return Response.notModified().build();
                    }
                    property.setPropertyValue(DataEncryption.encryptAsString(json.getPropertyValue()));
                } catch (Exception e) {
                    LOGGER.error("An error occurred while encrypting config property value", e);
                    return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("An error occurred while encrypting property value. Check log for details.").build();
                }
            }
        } else if(ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getPropertyName().equals(json.getPropertyName())) {
            String propertyValue = json.getPropertyValue();
            if (propertyValue != null && !propertyValue.isBlank()) {
                Set<String> ecosystems = Arrays.stream(propertyValue.split(";")).map(String::trim).collect(Collectors.toSet());
                property.setPropertyValue(String.join(";", ecosystems));
            } else {
                property.setPropertyValue(propertyValue);
            }
        } else {
            property.setPropertyValue(json.getPropertyValue());
        }
        return null;
    }
}
