/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.resources.v1;

import alpine.auth.PermissionRequired;
import alpine.crypto.DataEncryption;
import alpine.logging.Logger;
import alpine.model.ConfigProperty;
import alpine.resources.AlpineResource;
import alpine.util.BooleanUtil;
import alpine.util.UuidUtil;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.QueryManager;
import javax.validation.Validator;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.math.BigDecimal;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

/**
 * JAX-RS resources for processing ConfigProperties
 *
 * @author Steve Springett
 * @since 3.2.0
 */
@Path("/v1/configProperty")
@Api(value = "configProperty", authorizations = @Authorization(value = "X-Api-Key"))
public class ConfigPropertyResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(ConfigPropertyResource.class);
    private static final String ENCRYPTED_PLACEHOLDER = "HiddenDecryptedPropertyPlaceholder";

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all ConfigProperties for the specified groupName",
            response = ConfigProperty.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response getConfigProperties() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final List<ConfigProperty> configProperties = qm.getConfigProperties();
            // Detaches the objects and closes the persistence manager so that if/when encrypted string
            // values are replaced by the placeholder, they are not erroneously persisted to the database.
            qm.getPersistenceManager().detachCopyAll(configProperties);
            qm.close();
            for (ConfigProperty configProperty: configProperties) {
                // Replace the value of encrypted strings with the pre-defined placeholder
                if (ConfigProperty.PropertyType.ENCRYPTEDSTRING == configProperty.getPropertyType()) {
                    configProperty.setPropertyValue(ENCRYPTED_PLACEHOLDER);
                }
            }
            return Response.ok(configProperties).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Updates a config property",
            response = ConfigProperty.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The config property could not be found"),
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response updateConfigProperty(ConfigProperty json) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(json, "groupName"),
                validator.validateProperty(json, "propertyName"),
                validator.validateProperty(json, "propertyValue")
        );
        try (QueryManager qm = new QueryManager()) {
            ConfigProperty configProperty = qm.getConfigProperty(json.getGroupName(), json.getPropertyName());
            if (configProperty != null) {

                if (configProperty.getPropertyType() == ConfigProperty.PropertyType.BOOLEAN) {
                    configProperty.setPropertyValue(String.valueOf(BooleanUtil.valueOf(json.getPropertyValue())));
                } else if (configProperty.getPropertyType() == ConfigProperty.PropertyType.INTEGER) {
                    try {
                        configProperty.setPropertyValue(String.valueOf(Integer.parseInt(json.getPropertyValue())));
                    } catch (NumberFormatException e) {
                        return Response.status(Response.Status.BAD_REQUEST).entity("The config property expected an integer and an integer was not sent.").build();
                    }
                } else if (configProperty.getPropertyType() == ConfigProperty.PropertyType.NUMBER) {
                    try {
                        new BigDecimal(json.getPropertyValue());  // don't actually use it, just see if it's parses without exception
                        configProperty.setPropertyValue(json.getPropertyValue());
                    } catch (NumberFormatException e) {
                        return Response.status(Response.Status.BAD_REQUEST).entity("The config property expected a number and a number was not sent.").build();
                    }
                } else if (configProperty.getPropertyType() == ConfigProperty.PropertyType.URL) {
                    try {
                        URL url = new URL(json.getPropertyValue());
                        configProperty.setPropertyValue(url.toExternalForm());
                    } catch (MalformedURLException e) {
                        return Response.status(Response.Status.BAD_REQUEST).entity("The config property expected a URL but the URL was malformed.").build();
                    }
                } else if (configProperty.getPropertyType() == ConfigProperty.PropertyType.UUID) {
                    if (UuidUtil.isValidUUID(json.getPropertyValue())) {
                        configProperty.setPropertyValue(json.getPropertyValue());
                    } else {
                        return Response.status(Response.Status.BAD_REQUEST).entity("The config property expected a UUID but a valid UUID was not sent.").build();
                    }
                } else if (configProperty.getPropertyType() == ConfigProperty.PropertyType.ENCRYPTEDSTRING) {
                    try {
                        // Determine if the value of the encrypted property value is that of the placeholder. If so, the value has not been modified and should not be saved.
                        if (ENCRYPTED_PLACEHOLDER.equals(json.getPropertyValue())) {
                            return Response.notModified().build();
                        }
                        configProperty.setPropertyValue(DataEncryption.encryptAsString(json.getPropertyValue()));
                    } catch (Exception e) {
                        LOGGER.error("An error occurred while encrypting config property value", e);
                        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("An error occurred while encrypting config property value. Check log for details.").build();
                    }
                } else {
                    configProperty.setPropertyValue(json.getPropertyValue());
                }

                configProperty = qm.persist(configProperty);
                return Response.ok(configProperty).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The config property could not be found.").build();
            }
        }
    }
}
