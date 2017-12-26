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
package org.owasp.dependencytrack.resources.v1;

import alpine.auth.PermissionRequired;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineResource;
import alpine.validation.RegexSequence;
import alpine.validation.ValidationTask;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.ResponseHeader;
import org.apache.commons.lang.StringUtils;
import org.owasp.dependencytrack.auth.Permission;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.License;
import org.owasp.dependencytrack.persistence.QueryManager;
import javax.validation.Validator;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * JAX-RS resources for processing components.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/component")
@Api(value = "component", authorizations = @Authorization(value = "X-Api-Key"))
public class ComponentResource extends AlpineResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all components",
            response = Component.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of components")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permission.COMPONENT_VIEW)
    public Response getAllComponents() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getComponents();
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @GET
    @Path("/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a specific component",
            response = Component.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The component could not be found")
    })
    @PermissionRequired(Permission.COMPONENT_VIEW)
    public Response getComponentByUuid(
            @ApiParam(value = "The UUID of the component to retrieve", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component != null) {
                return Response.ok(component).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
        }
    }

    @GET
    @Path("/hash/{hash}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a specific component",
            response = Component.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The component could not be found")
    })
    @PermissionRequired(Permission.COMPONENT_VIEW)
    public Response getComponentByHash(
            @ApiParam(value = "The MD5 or SHA1 hash of the component to retrieve", required = true)
            @PathParam("hash") String hash) {
        try (QueryManager qm = new QueryManager()) {
            failOnValidationError(
                    new ValidationTask(RegexSequence.Pattern.HASH_MD5_SHA1, hash, "Invalid MD5 or SHA1 hash.")
            );
            final Component component = qm.getComponentByHash(hash);
            if (component != null) {
                return Response.ok(component).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Creates a new component",
            notes = "Requires 'manage component' permission.",
            response = Component.class,
            code = 201
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permission.COMPONENT_MANAGE)
    public Response createComponent(Component jsonComponent) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonComponent, "name"),
                validator.validateProperty(jsonComponent, "version"),
                validator.validateProperty(jsonComponent, "group"),
                validator.validateProperty(jsonComponent, "description"),
                validator.validateProperty(jsonComponent, "license"),
                validator.validateProperty(jsonComponent, "purl")
        );

        try (QueryManager qm = new QueryManager()) {
            Component parent = null;
            if (jsonComponent.getParent() != null && jsonComponent.getParent().getUuid() != null) {
                parent = qm.getObjectByUuid(Component.class, jsonComponent.getParent().getUuid());
            }
            final Component component = qm.createComponent(
                    StringUtils.trimToNull(jsonComponent.getName()),
                    StringUtils.trimToNull(jsonComponent.getVersion()),
                    StringUtils.trimToNull(jsonComponent.getGroup()),
                    null, null, null,
                    StringUtils.trimToNull(jsonComponent.getDescription()),
                    qm.getLicense(jsonComponent.getLicense()),
                    null,
                    parent,
                    StringUtils.trimToNull(jsonComponent.getPurl()),
                    true);
            return Response.status(Response.Status.CREATED).entity(component).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Updates a component",
            notes = "Requires 'manage component' permission.",
            response = Component.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the component could not be found"),
    })
    @PermissionRequired(Permission.PROJECT_MANAGE)
    public Response updateProject(Component jsonComponent) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonComponent, "name"),
                validator.validateProperty(jsonComponent, "description"),
                validator.validateProperty(jsonComponent, "version"),
                validator.validateProperty(jsonComponent, "group"),
                validator.validateProperty(jsonComponent, "purl")
        );
        try (QueryManager qm = new QueryManager()) {
            Component component = qm.getObjectByUuid(Component.class, jsonComponent.getUuid());
            if (component != null) {
                // Name cannot be empty or null - prevent it
                String name = StringUtils.trimToNull(jsonComponent.getName());
                if (name != null) {
                    component.setName(name);
                }
                component.setDescription(StringUtils.trimToNull(jsonComponent.getDescription()));
                component.setVersion(StringUtils.trimToNull(jsonComponent.getVersion()));
                component.setGroup(StringUtils.trimToNull(jsonComponent.getGroup()));
                component.setPurl(StringUtils.trimToNull(jsonComponent.getPurl()));

                String license = StringUtils.trimToNull(jsonComponent.getLicense());
                License resolvedLicense = qm.getLicense(license);
                component.setResolvedLicense(resolvedLicense);

                return Response.ok(qm.updateComponent(component, true)).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the component could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Deletes a component",
            notes = "Requires 'manage component' permission.",
            code = 204
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the component could not be found")
    })
    @PermissionRequired(Permission.PROJECT_MANAGE)
    public Response deleteProject(
            @ApiParam(value = "The UUID of the component to delete", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, uuid, Component.FetchGroup.ALL.name());
            if (component != null) {
                qm.recursivelyDelete(component, false);
                qm.commitSearchIndex(Component.class);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the component could not be found.").build();
            }
        }
    }

}
