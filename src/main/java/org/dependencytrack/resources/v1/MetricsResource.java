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

import alpine.event.framework.Event;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.apache.commons.lang3.time.DateUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.ComponentMetricsUpdateEvent;
import org.dependencytrack.event.PortfolioMetricsUpdateEvent;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.VulnerabilityMetrics;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.DateUtil;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Date;
import java.util.List;

/**
 * JAX-RS resources for processing metrics.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/metrics")
@Tag(name = "metrics")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class MetricsResource extends AlpineResource {

    @GET
    @Path("/vulnerability")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns the sum of all vulnerabilities in the database by year and month",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The sum of all vulnerabilities in the database by year and month",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = VulnerabilityMetrics.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getVulnerabilityMetrics() {
        try (QueryManager qm = new QueryManager()) {
            final List<VulnerabilityMetrics> metrics = qm.getVulnerabilityMetrics();
            return Response.ok(metrics).build();
        }
    }

    @GET
    @Path("/portfolio/current")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns current metrics for the entire portfolio",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Current metrics for the entire portfolio",
                    content = @Content(schema = @Schema(implementation = PortfolioMetrics.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getPortfolioCurrentMetrics() {
        try (QueryManager qm = new QueryManager()) {
            final PortfolioMetrics metrics = qm.getMostRecentPortfolioMetrics();
            return Response.ok(metrics).build();
        }
    }

    @GET
    @Path("/portfolio/since/{date}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns historical metrics for the entire portfolio from a specific date",
            description = """
                    <p>Date format must be <code>YYYYMMDD</code></p>
                    <p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"""
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Historical metrics for the entire portfolio from a specific date",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = PortfolioMetrics.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getPortfolioMetricsSince(
            @Parameter(description = "The start date to retrieve metrics for", required = true)
            @PathParam("date") String date) {

        final Date since = DateUtil.parseShortDate(date);
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
    @Operation(
            summary = "Returns X days of historical metrics for the entire portfolio",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "X days of historical metrics for the entire portfolio",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = PortfolioMetrics.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getPortfolioMetricsXDays(
            @Parameter(description = "The number of days back to retrieve metrics for", required = true)
            @PathParam("days") int days) {

        final Date since = DateUtils.addDays(new Date(), -days);
        try (QueryManager qm = new QueryManager()) {
            final List<PortfolioMetrics> metrics = qm.getPortfolioMetricsSince(since);
            return Response.ok(metrics).build();
        }
    }

    @GET
    @Path("/portfolio/refresh")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Requests a refresh of the portfolio metrics",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Refresh requested successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response RefreshPortfolioMetrics() {
        Event.dispatch(new PortfolioMetricsUpdateEvent());
        return Response.ok().build();
    }

    @GET
    @Path("/project/{uuid}/current")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns current metrics for a specific project",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Current metrics for a specific project",
                    content = @Content(schema = @Schema(implementation = ProjectMetrics.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProjectCurrentMetrics(
            @Parameter(description = "The UUID of the project to retrieve metrics for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    final ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
                    return Response.ok(metrics).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/project/{uuid}/since/{date}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns historical metrics for a specific project from a specific date",
            description = """
                    <p>Date format must be <code>YYYYMMDD</code></p>
                    <p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"""
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Historical metrics for a specific project from a specific date",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ProjectMetrics.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProjectMetricsSince(
            @Parameter(description = "The UUID of the project to retrieve metrics for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "The start date to retrieve metrics for", required = true)
            @PathParam("date") String date) {

        final Date since = DateUtil.parseShortDate(date);
        return getProjectMetrics(uuid, since);
    }

    @GET
    @Path("/project/{uuid}/days/{days}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns X days of historical metrics for a specific project",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "X days of historical metrics for a specific project",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ProjectMetrics.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProjectMetricsXDays(
            @Parameter(description = "The UUID of the project to retrieve metrics for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "The number of days back to retrieve metrics for", required = true)
            @PathParam("days") int days) {

        final Date since = DateUtils.addDays(new Date(), -days);
        return getProjectMetrics(uuid, since);
    }

    @GET
    @Path("/project/{uuid}/refresh")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Requests a refresh of a specific projects metrics",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Refresh requested successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response RefreshProjectMetrics(
            @Parameter(description = "The UUID of the project to refresh metrics on", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    Event.dispatch(new ProjectMetricsUpdateEvent(project.getUuid()));
                    return Response.ok().build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/component/{uuid}/current")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns current metrics for a specific component",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Current metrics for a specific component",
                    content = @Content(schema = @Schema(implementation = DependencyMetrics.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified component is forbidden"),
            @ApiResponse(responseCode = "404", description = "The component could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getComponentCurrentMetrics(
            @Parameter(description = "The UUID of the component to retrieve metrics for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component != null) {
                if (qm.hasAccess(super.getPrincipal(), component.getProject())) {
                    final DependencyMetrics metrics = qm.getMostRecentDependencyMetrics(component);
                    return Response.ok(metrics).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified component is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
        }
    }

    @GET
    @Path("/component/{uuid}/since/{date}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns historical metrics for a specific component from a specific date",
            description = """
                    <p>Date format must be <code>YYYYMMDD</code></p>
                    <p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"""
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Historical metrics for a specific component from a specific date",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = DependencyMetrics.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified component is forbidden"),
            @ApiResponse(responseCode = "404", description = "The component could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getComponentMetricsSince(
            @Parameter(description = "The UUID of the component to retrieve metrics for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "The start date to retrieve metrics for", required = true)
            @PathParam("date") String date) {

        final Date since = DateUtil.parseShortDate(date);
        if (since == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("The specified date format is incorrect.").build();
        }
        return getComponentMetrics(uuid, since);
    }

    @GET
    @Path("/component/{uuid}/days/{days}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns X days of historical metrics for a specific component",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "X days of historical metrics for a specific component",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = DependencyMetrics.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified component is forbidden"),
            @ApiResponse(responseCode = "404", description = "The component could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getComponentMetricsXDays(
            @Parameter(description = "The UUID of the component to retrieve metrics for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "The number of days back to retrieve metrics for", required = true)
            @PathParam("days") int days) {

        final Date since = DateUtils.addDays(new Date(), -days);
        return getComponentMetrics(uuid, since);
    }

    @GET
    @Path("/component/{uuid}/refresh")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Requests a refresh of a specific components metrics",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Refresh requested successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified component is forbidden"),
            @ApiResponse(responseCode = "404", description = "The component could not be found")
    })
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response RefreshComponentMetrics(
            @Parameter(description = "The UUID of the component to refresh metrics on", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component != null) {
                if (qm.hasAccess(super.getPrincipal(), component.getProject())) {
                    Event.dispatch(new ComponentMetricsUpdateEvent(component.getUuid()));
                    return Response.ok().build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified component is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
        }
    }

    /**
     * Private method common to retrieving project metrics based on a time period.
     *
     * @param uuid  the UUID of the project
     * @param since the Date to start retrieving metrics from
     * @return a Response object
     */
    private Response getProjectMetrics(String uuid, Date since) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (qm.hasAccess(super.getPrincipal(), project)) {
                    final List<ProjectMetrics> metrics = qm.getProjectMetricsSince(project, since);
                    return Response.ok(metrics).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    /**
     * Private method common to retrieving component metrics based on a time period.
     *
     * @param uuid  the UUID of the component
     * @param since the Date to start retrieving metrics from
     * @return a Response object
     */
    private Response getComponentMetrics(String uuid, Date since) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component != null) {
                if (qm.hasAccess(super.getPrincipal(), component.getProject())) {
                    final List<DependencyMetrics> metrics = qm.getDependencyMetricsSince(component, since);
                    return Response.ok(metrics).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified component is forbidden").build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
        }
    }

}
