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
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.owasp.dependencytrack.auth.Permission;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.ComponentMetrics;
import org.owasp.dependencytrack.model.PortfolioMetrics;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.model.ProjectMetrics;
import org.owasp.dependencytrack.persistence.QueryManager;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * JAX-RS resources for processing metrics.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/metrics")
@Api(value = "metrics", authorizations = @Authorization(value = "X-Api-Key"))
public class MetricsResource extends AlpineResource {

    @GET
    @Path("/portfolio/current")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns current metrics for the entire portfolio",
            response = PortfolioMetrics.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permission.PROJECT_VIEW)
    public Response getPortfolioCurrentMetrics() {
        try (QueryManager qm = new QueryManager()) {
            final PortfolioMetrics metrics = qm.getMostRecentPortfolioMetrics();
            return Response.ok(metrics).build();
        }
    }

    @GET
    @Path("/project/{uuid}/current")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns current metrics for a specific project",
            response = ProjectMetrics.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permission.PROJECT_VIEW)
    public Response getProjectCurrentMetrics(
            @ApiParam(value = "The UUID of the project to retrieve metrics for", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                final ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
                return Response.ok(metrics).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/component/{uuid}/current")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns current metrics for a specific component",
            response = ComponentMetrics.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The component could not be found")
    })
    @PermissionRequired(Permission.COMPONENT_VIEW)
    public Response getComponentCurrentMetrics(
            @ApiParam(value = "The UUID of the component to retrieve metrics for", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component != null) {
                final ComponentMetrics metrics = qm.getMostRecentComponentMetrics(component);
                return Response.ok(metrics).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
        }
    }

}
