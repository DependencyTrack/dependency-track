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

import alpine.server.auth.PermissionRequired;
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
import jakarta.inject.Inject;
import jakarta.validation.constraints.Positive;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.metrics.UpdatePortfolioMetricsWorkflow;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.VulnerabilityMetrics;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.jdbi.ComponentDao;
import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.persistence.jdbi.ProjectDao.ProjectInfoRow;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.util.DateUtil;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Date;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

import static org.apache.commons.lang3.time.DateUtils.addDays;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_METRICS_RETENTION_DAYS;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

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
public class MetricsResource extends AbstractApiResource {

    private final DexEngine dexEngine;

    @Inject
    MetricsResource(DexEngine dexEngine) {
        this.dexEngine = dexEngine;
    }

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
        final List<VulnerabilityMetrics> metrics =
                withJdbiHandle(handle -> handle.attach(MetricsDao.class).getVulnerabilityMetrics());
        return Response.ok(metrics).build();
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
        PortfolioMetrics metrics = withJdbiHandle(
                getAlpineRequest(),
                handle -> handle.attach(MetricsDao.class).getMostRecentPortfolioMetrics());
        return Response.ok(metrics).build();
    }

    @GET
    @Path("/portfolio/since/{date}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns historical metrics for the entire portfolio from a specific date",
            description = """
                    <p>Date format must be <code>YYYYMMDD</code></p>
                    <p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>""")
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
        final LocalDate since;
        try {
            since = LocalDate.parse(date, DateTimeFormatter.ofPattern("yyyyMMdd"));
        } catch (DateTimeParseException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity("The specified date format is incorrect.").build();
        }
        List<PortfolioMetrics> metrics = withJdbiHandle(getAlpineRequest(), handle -> {
            final int retentionDays = handle.attach(ConfigPropertyDao.class)
                    .getOptionalValue(MAINTENANCE_METRICS_RETENTION_DAYS, Integer.class)
                    .orElseGet(() -> Integer.parseInt(MAINTENANCE_METRICS_RETENTION_DAYS.getDefaultPropertyValue()));

            // NB: Calculate days between the given date and *tomorrow*,
            // because LocalDate#until's end date is exclusive,
            // and we want to include data for *today*.
            final var sincePeriod = since.until(LocalDate.now().plusDays(1));
            final int sinceDays = sincePeriod.getDays();

            return handle.attach(MetricsDao.class).getPortfolioMetricsForDays(Math.min(retentionDays, sinceDays));
        });
        return Response.ok(metrics).build();
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
            @PathParam("days") @Positive int days) {
        List<PortfolioMetrics> metrics = withJdbiHandle(getAlpineRequest(), handle -> {
            final int retentionDays = handle.attach(ConfigPropertyDao.class)
                    .getOptionalValue(MAINTENANCE_METRICS_RETENTION_DAYS, Integer.class)
                    .orElseGet(() -> Integer.parseInt(MAINTENANCE_METRICS_RETENTION_DAYS.getDefaultPropertyValue()));

            return handle.attach(MetricsDao.class).getPortfolioMetricsForDays(Math.min(days, retentionDays));
        });
        return Response.ok(metrics).build();
    }

    @GET
    @Path("/portfolio/refresh")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Requests a refresh of the portfolio metrics",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Refresh requested successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE})
    public Response RefreshPortfolioMetrics() {
        dexEngine.createRun(
                new CreateWorkflowRunRequest<>(UpdatePortfolioMetricsWorkflow.class)
                        .withWorkflowInstanceId(UpdatePortfolioMetricsWorkflow.INSTANCE_ID));
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
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProjectCurrentMetrics(
            @Parameter(description = "The UUID of the project to retrieve metrics for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        return withJdbiHandle(getAlpineRequest(), handle -> {
            requireProjectAccess(handle, UUID.fromString(uuid));

            final ProjectInfoRow projectInfo = handle
                    .attach(ProjectDao.class)
                    .getProjectInfo(UUID.fromString(uuid));
            if (projectInfo == null) {
                throw new NoSuchElementException("Project could not be found");
            }

            final var metricsDao = handle.attach(MetricsDao.class);

            ProjectMetrics metrics;
            if (projectInfo.isCollection()) {
                metrics = metricsDao.getMostRecentCollectionProjectMetrics(projectInfo.id());
            } else {
                metrics = metricsDao.getMostRecentProjectMetrics(projectInfo.id());
            }

            if (metrics == null) {
                metrics = new ProjectMetrics();
                final var now = new Date();
                metrics.setFirstOccurrence(now);
                metrics.setLastOccurrence(now);
            }

            return Response.ok(metrics).build();
        });
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
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProjectMetricsSince(
            @Parameter(description = "The UUID of the project to retrieve metrics for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "The start date to retrieve metrics for", required = true)
            @PathParam("date") String date) {
        final Date since = DateUtil.parseShortDate(date);
        return getProjectMetrics(UUID.fromString(uuid), since);
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
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProjectMetricsXDays(
            @Parameter(description = "The UUID of the project to retrieve metrics for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "The number of days back to retrieve metrics for", required = true)
            @PathParam("days") int days) {
        final Date since = addDays(new Date(), -days);
        return getProjectMetrics(UUID.fromString(uuid), since);
    }

    @GET
    @Path("/project/{uuid}/refresh")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Requests a refresh of a specific projects metrics",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Refresh requested successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE})
    public Response RefreshProjectMetrics(
            @Parameter(description = "The UUID of the project to refresh metrics on", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        final var projectUuid = UUID.fromString(uuid);

        useJdbiTransaction(getAlpineRequest(), handle -> {
            requireProjectAccess(handle, projectUuid);

            handle.attach(MetricsDao.class).updateProjectMetrics(projectUuid);
        });

        return Response.ok().build();
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
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested component is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The component could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getComponentCurrentMetrics(
            @Parameter(description = "The UUID of the component to retrieve metrics for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        return withJdbiHandle(getAlpineRequest(), handle -> {
            var componentId = handle.attach(ComponentDao.class).getComponentId(UUID.fromString(uuid));
            if (componentId == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
            requireComponentAccess(handle, UUID.fromString(uuid));
            final DependencyMetrics metrics = handle.attach(MetricsDao.class).getMostRecentDependencyMetrics(componentId);
            return Response.ok(metrics).build();
        });
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
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested component is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
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
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested component is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The component could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getComponentMetricsXDays(
            @Parameter(description = "The UUID of the component to retrieve metrics for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            @Parameter(description = "The number of days back to retrieve metrics for", required = true)
            @PathParam("days") int days) {
        final Date since = addDays(new Date(), -days);
        return getComponentMetrics(uuid, since);
    }

    @GET
    @Path("/component/{uuid}/refresh")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Requests a refresh of a specific components metrics",
            description = "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Refresh requested successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested component is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The component could not be found")
    })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE})
    public Response RefreshComponentMetrics(
            @Parameter(description = "The UUID of the component to refresh metrics on", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        final var componentUuid = UUID.fromString(uuid);

        useJdbiTransaction(getAlpineRequest(), handle -> {
            requireComponentAccess(handle, componentUuid);
            handle.attach(MetricsDao.class).updateComponentMetrics(componentUuid);
        });

        return Response.ok().build();
    }

    private Response getProjectMetrics(UUID uuid, Date since) {
        return withJdbiHandle(getAlpineRequest(), handle -> {
            requireProjectAccess(handle, uuid);

            final ProjectInfoRow projectInfo = handle
                    .attach(ProjectDao.class)
                    .getProjectInfo(uuid);
            if (projectInfo == null) {
                throw new NoSuchElementException("Project could not be found");
            }

            final int retentionDays = handle.attach(ConfigPropertyDao.class)
                    .getOptionalValue(MAINTENANCE_METRICS_RETENTION_DAYS, Integer.class)
                    .orElseGet(() -> Integer.parseInt(MAINTENANCE_METRICS_RETENTION_DAYS.getDefaultPropertyValue()));
            final Date retentionCutoff = addDays(new Date(), -retentionDays);
            final Date effectiveSince = since.before(retentionCutoff) ? retentionCutoff : since;

            final var metricsDao = handle.attach(MetricsDao.class);

            final List<ProjectMetrics> metrics;
            if (projectInfo.isCollection()) {
                metrics = metricsDao.getCollectionProjectMetricsSince(
                        projectInfo.id(),
                        effectiveSince.toInstant());
            } else {
                metrics = metricsDao.getProjectMetricsSince(projectInfo.id(), effectiveSince.toInstant());
            }

            return Response.ok(metrics).build();
        });
    }

    /**
     * Private method common to retrieving component metrics based on a time period.
     *
     * @param uuid  the UUID of the component
     * @param since the Date to start retrieving metrics from
     * @return a Response object
     */
    private Response getComponentMetrics(String uuid, Date since) {
        return withJdbiHandle(getAlpineRequest(), handle -> {
            var componentId = handle.attach(ComponentDao.class).getComponentId(UUID.fromString(uuid));
            if (componentId == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }
            requireComponentAccess(handle, UUID.fromString(uuid));

            final int retentionDays = handle.attach(ConfigPropertyDao.class)
                    .getOptionalValue(MAINTENANCE_METRICS_RETENTION_DAYS, Integer.class)
                    .orElseGet(() -> Integer.parseInt(MAINTENANCE_METRICS_RETENTION_DAYS.getDefaultPropertyValue()));
            final Date retentionCutoff = addDays(new Date(), -retentionDays);
            final Date effectiveSince = since.before(retentionCutoff) ? retentionCutoff : since;

            final List<DependencyMetrics> metrics = handle.attach(MetricsDao.class).getDependencyMetricsSince(componentId, effectiveSince.toInstant());
            return Response.ok(metrics).build();
        });
    }
}
