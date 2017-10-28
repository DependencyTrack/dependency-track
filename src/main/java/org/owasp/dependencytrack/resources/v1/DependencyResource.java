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
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.ResponseHeader;
import org.owasp.dependencytrack.auth.Permission;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.Dependency;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.persistence.QueryManager;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * JAX-RS resources for processing dependencies.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/dependency")
@Api(value = "dependency", authorizations = @Authorization(value = "X-Api-Key"))
public class DependencyResource extends AlpineResource {

    @GET
    @Path("/project/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all dependencies for a specific project",
            response = Dependency.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of dependencies")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permission.PROJECT_VIEW)
    public Response getDependencies(@PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                final PaginatedResult result = qm.getDependencies(project);
                return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/component/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all dependencies for a specific component",
            response = Dependency.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of dependencies")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The component could not be found")
    })
    @PermissionRequired(Permission.PROJECT_VIEW)
    public Response getDependency(@PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component != null) {
                final PaginatedResult result = qm.getDependencies(component);
                return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
        }
    }

}
