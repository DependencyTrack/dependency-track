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

import alpine.auth.PermissionRequired;
import alpine.logging.Logger;
import alpine.model.ConfigProperty;
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
import java.util.ArrayList;
import java.util.List;

/**
 * JAX-RS resources for processing ConfigProperties
 *
 * @author Steve Springett
 * @since 3.2.0
 */
@Path("/v1/configProperty")
@Api(value = "configProperty", authorizations = @Authorization(value = "X-Api-Key"))
public class ConfigPropertyResource extends AbstractConfigPropertyResource {

    private static final Logger LOGGER = Logger.getLogger(ConfigPropertyResource.class);

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
            for (final ConfigProperty configProperty: configProperties) {
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
            final ConfigProperty property = qm.getConfigProperty(json.getGroupName(), json.getPropertyName());
            return updatePropertyValue(qm, json, property);
        }
    }

    @POST
    @Path("aggregate")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Updates an array of config properties",
            response = ConfigProperty.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "One or more config properties could not be found"),
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response updateConfigProperty(List<ConfigProperty> list) {
        final Validator validator = super.getValidator();
        for (ConfigProperty item: list) {
            failOnValidationError(
                    validator.validateProperty(item, "groupName"),
                    validator.validateProperty(item, "propertyName"),
                    validator.validateProperty(item, "propertyValue")
            );
        }
        List<Object> returnList = new ArrayList<>();
        try (QueryManager qm = new QueryManager()) {
            for (ConfigProperty item : list) {
                final ConfigProperty property = qm.getConfigProperty(item.getGroupName(), item.getPropertyName());
                returnList.add(updatePropertyValue(qm, item, property).getEntity());
            }
        }
        return Response.ok(returnList).build();
    }
}
