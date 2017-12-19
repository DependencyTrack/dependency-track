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
import alpine.event.framework.SingleThreadedEventService;
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.apache.commons.lang3.time.DateUtils;
import org.owasp.dependencytrack.auth.Permission;
import org.owasp.dependencytrack.event.MetricsUpdateEvent;
import org.owasp.dependencytrack.model.Component;
import org.owasp.dependencytrack.model.ComponentMetrics;
import org.owasp.dependencytrack.model.PortfolioMetrics;
import org.owasp.dependencytrack.model.Project;
import org.owasp.dependencytrack.model.ProjectMetrics;
import org.owasp.dependencytrack.model.VulnerabilityMetrics;
import org.owasp.dependencytrack.persistence.QueryManager;
import org.owasp.dependencytrack.util.DateUtil;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Date;
import java.util.List;

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
    @Path("/vulnerability")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns the sum of all vulnerabilities in the database by year and month",
            response = VulnerabilityMetrics.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permission.PROJECT_VIEW)
    public Response getVulnerabilityMetrics() {
        try (QueryManager qm = new QueryManager()) {
            final List<VulnerabilityMetrics> metrics = qm.getVulnerabilityMetrics();
            return Response.ok(metrics).build();
        }
    }

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
    @Path("/portfolio/since/{date}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns historical metrics for the entire portfolio from a specific date",
            notes = "Date format must be YYYYMMDD",
            response = PortfolioMetrics.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permission.PROJECT_VIEW)
    public Response getPortfolioMetricsSince(
            @ApiParam(value = "The start date to retrieve metrics for", required = true)
            @PathParam("date") String date) {

        Date since = DateUtil.parseShortDate(date);
        if (since == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("The specified date format is incorrect.").build();
        }
        try (QueryManager qm = new QueryManager()) {
            final List<PortfolioMetrics> metrics = qm.getPortfolioMetricsSince(since);
            return Response.ok(metrics).build();
        }
    }

    @GET
    @Path("/portfolio/{days}/days")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns X days of historical metrics for the entire portfolio",
            response = PortfolioMetrics.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permission.PROJECT_VIEW)
    public Response getPortfolioMetricsXDays(
            @ApiParam(value = "The number of days back to retrieve metrics for", required = true)
            @PathParam("days") int days) {

        Date since = DateUtils.addDays(new Date(), -days);
        try (QueryManager qm = new QueryManager()) {
            final List<PortfolioMetrics> metrics = qm.getPortfolioMetricsSince(since);
            return Response.ok(metrics).build();
        }
    }

    @GET
    @Path("/portfolio/refresh")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Requests a refresh of the portfolio metrics",
            response = PortfolioMetrics.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permission.PROJECT_VIEW)
    public Response RefreshPortfolioMetrics() {
        SingleThreadedEventService.getInstance().publish(new MetricsUpdateEvent(MetricsUpdateEvent.Type.PORTFOLIO));
        return Response.ok().build();
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
    @Path("/project/{uuid}/since/{date}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns historical metrics for a specific project from a specific date",
            notes = "Date format must be YYYYMMDD",
            response = ProjectMetrics.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permission.PROJECT_VIEW)
    public Response getProjectMetricsSince(
            @ApiParam(value = "The UUID of the project to retrieve metrics for", required = true)
            @PathParam("uuid") String uuid,
            @ApiParam(value = "The start date to retrieve metrics for", required = true)
            @PathParam("date") String date) {

        Date since = DateUtil.parseShortDate(date);
        return getProjectMetrics(uuid, since);
    }

    @GET
    @Path("/project/{uuid}/days/{days}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns X days of historical metrics for a specific project",
            response = ProjectMetrics.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permission.PROJECT_VIEW)
    public Response getProjectMetricsXDays(
            @ApiParam(value = "The UUID of the project to retrieve metrics for", required = true)
            @PathParam("uuid") String uuid,
            @ApiParam(value = "The number of days back to retrieve metrics for", required = true)
            @PathParam("days") int days) {

        Date since = DateUtils.addDays(new Date(), -days);
        return getProjectMetrics(uuid, since);
    }

    @GET
    @Path("/project/{uuid}/refresh")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Requests a refresh of a specific projects metrics"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    @PermissionRequired(Permission.PROJECT_VIEW)
    public Response RefreshProjectMetrics(
            @ApiParam(value = "The UUID of the project to refresh metrics on", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                SingleThreadedEventService.getInstance().publish(new MetricsUpdateEvent(project));
                return Response.ok().build();
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

    @GET
    @Path("/component/{uuid}/since/{date}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns historical metrics for a specific component from a specific date",
            notes = "Date format must be YYYYMMDD",
            response = ProjectMetrics.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The component could not be found")
    })
    @PermissionRequired(Permission.COMPONENT_VIEW)
    public Response getComponentMetricsSince(
            @ApiParam(value = "The UUID of the component to retrieve metrics for", required = true)
            @PathParam("uuid") String uuid,
            @ApiParam(value = "The start date to retrieve metrics for", required = true)
            @PathParam("date") String date) {

        Date since = DateUtil.parseShortDate(date);
        if (since == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("The specified date format is incorrect.").build();
        }
        return getComponentMetrics(uuid, since);
    }

    @GET
    @Path("/component/{uuid}/days/{days}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns X days of historical metrics for a specific component",
            response = ComponentMetrics.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The component could not be found")
    })
    @PermissionRequired(Permission.COMPONENT_VIEW)
    public Response getComponentMetricsXDays(
            @ApiParam(value = "The UUID of the component to retrieve metrics for", required = true)
            @PathParam("uuid") String uuid,
            @ApiParam(value = "The number of days back to retrieve metrics for", required = true)
            @PathParam("days") int days) {

        Date since = DateUtils.addDays(new Date(), -days);
        return getComponentMetrics(uuid, since);
    }

    @GET
    @Path("/component/{uuid}/refresh")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Requests a refresh of a specific components metrics"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The component could not be found")
    })
    @PermissionRequired(Permission.PROJECT_VIEW)
    public Response RefreshComponentMetrics(
            @ApiParam(value = "The UUID of the component to refresh metrics on", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component != null) {
                SingleThreadedEventService.getInstance().publish(new MetricsUpdateEvent(component));
                return Response.ok().build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
        }
    }

    /**
     * Private method common to retrieving project metrics based on a time period.
     * @param uuid the UUID of the project
     * @param since the Date to start retrieving metrics from
     * @return a Response object
     */
    private Response getProjectMetrics(String uuid, Date since) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                final List<ProjectMetrics> metrics = qm.getProjectMetricsSince(project, since);
                return Response.ok(metrics).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    /**
     * Private method common to retrieving component metrics based on a time period.
     * @param uuid the UUID of the component
     * @param since the Date to start retrieving metrics from
     * @return a Response object
     */
    private Response getComponentMetrics(String uuid, Date since) {
        try (QueryManager qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component != null) {
                final List<ComponentMetrics> metrics = qm.getComponentMetricsSince(component, since);
                return Response.ok(metrics).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
        }
    }
}
