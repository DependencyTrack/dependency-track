/*
 * This file is part of Dependency-Track.
 *
 * Dependency-Track is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Track is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Track. If not, see http://www.gnu.org/licenses/.
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
