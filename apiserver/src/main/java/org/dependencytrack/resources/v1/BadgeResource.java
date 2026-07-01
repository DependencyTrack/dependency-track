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

import alpine.model.ConfigProperty;
import alpine.server.auth.AuthenticationNotRequired;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.misc.Badger;

import static org.dependencytrack.model.ConfigPropertyConstants.GENERAL_BADGE_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.GENERAL_BASE_URL;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * JAX-RS resources for processing metrics.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
@Path("/v1/badge")
@Tag(name = "badge")
public class BadgeResource extends AbstractApiResource {

    private static final String SVG_MEDIA_TYPE = "image/svg+xml";

    @GET
    @Path("/vulns/project/{uuid}")
    @Produces(SVG_MEDIA_TYPE)
    @Operation(
            summary = "Returns current metrics for a specific project"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A badge displaying current vulnerability metrics for a project in SVG format",
                    content = @Content(schema = @Schema(type = "string"))
            ),
            @ApiResponse(responseCode = "403", description = "Badges are disabled"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @AuthenticationNotRequired
    public Response getProjectVulnerabilitiesBadge(
            @Parameter(description = "The UUID of the project to retrieve metrics for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            if (!qm.isEnabled(GENERAL_BADGE_ENABLED)) {
                return Response.status(Response.Status.FORBIDDEN).build();
            }
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                final ProjectMetrics metrics = withJdbiHandle(handle -> {
                    final var dao = handle.attach(MetricsDao.class);
                    return project.getCollectionLogic() == null
                            ? dao.getMostRecentProjectMetrics(project.getId())
                            : dao.getMostRecentCollectionProjectMetrics(project.getId());
                });
                final var badger = new Badger();

                String linkToProjectVuln = null;
                final ConfigProperty baseUrl = qm.getConfigProperty(GENERAL_BASE_URL.getGroupName(), GENERAL_BASE_URL.getPropertyName());
                if (baseUrl != null && baseUrl.getPropertyValue() != null) {
                    linkToProjectVuln = baseUrl.getPropertyValue() + "/projects/" + project.getUuid() + "/findings";
                }
                return Response.ok(badger.generateVulnerabilities(metrics, linkToProjectVuln)).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/vulns/project/{name}/{version}")
    @Produces(SVG_MEDIA_TYPE)
    @Operation(
            summary = "Returns current metrics for a specific project"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A badge displaying current vulnerability metrics for a project in SVG format",
                    content = @Content(schema = @Schema(type = "string"))
            ),
            @ApiResponse(responseCode = "403", description = "Badges are disabled"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @AuthenticationNotRequired
    public Response getProjectVulnerabilitiesBadge(
            @Parameter(description = "The name of the project to query on", required = true)
            @PathParam("name") String name,
            @Parameter(description = "The version of the project to query on", required = true)
            @PathParam("version") String version) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            if (!qm.isEnabled(GENERAL_BADGE_ENABLED)) {
                return Response.status(Response.Status.FORBIDDEN).build();
            }
            final Project project = qm.getProject(name, version);
            if (project != null) {
                final ProjectMetrics metrics = withJdbiHandle(handle -> {
                    final var dao = handle.attach(MetricsDao.class);
                    return project.getCollectionLogic() == null
                            ? dao.getMostRecentProjectMetrics(project.getId())
                            : dao.getMostRecentCollectionProjectMetrics(project.getId());
                });
                final var badger = new Badger();

                String linkToProjectVuln = null;
                final ConfigProperty baseUrl = qm.getConfigProperty(GENERAL_BASE_URL.getGroupName(), GENERAL_BASE_URL.getPropertyName());
                if (baseUrl != null && baseUrl.getPropertyValue() != null) {
                    linkToProjectVuln = baseUrl.getPropertyValue() + "/projects/" + project.getUuid() + "/findings";
                }
                return Response.ok(badger.generateVulnerabilities(metrics, linkToProjectVuln)).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/violations/project/{uuid}")
    @Produces(SVG_MEDIA_TYPE)
    @Operation(
            summary = "Returns a policy violations badge for a specific project"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A badge displaying current policy violation metrics of a project in SVG format",
                    content = @Content(schema = @Schema(type = "string"))
            ),
            @ApiResponse(responseCode = "403", description = "Badges are disabled"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @AuthenticationNotRequired
    public Response getProjectPolicyViolationsBadge(
            @Parameter(description = "The UUID of the project to retrieve a badge for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            if (!qm.isEnabled(GENERAL_BADGE_ENABLED)) {
                return Response.status(Response.Status.FORBIDDEN).build();
            }
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                final ProjectMetrics metrics = withJdbiHandle(handle -> {
                    final var dao = handle.attach(MetricsDao.class);
                    return project.getCollectionLogic() == null
                            ? dao.getMostRecentProjectMetrics(project.getId())
                            : dao.getMostRecentCollectionProjectMetrics(project.getId());
                });
                final var badger = new Badger();

                String linkToProjectViolations = null;
                final ConfigProperty baseUrl = qm.getConfigProperty(GENERAL_BASE_URL.getGroupName(), GENERAL_BASE_URL.getPropertyName());
                if (baseUrl != null && baseUrl.getPropertyValue() != null) {
                    linkToProjectViolations = baseUrl.getPropertyValue() + "/projects/" + project.getUuid() + "/policyViolations";
                }
                return Response.ok(badger.generateViolations(metrics, linkToProjectViolations)).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/violations/project/{name}/{version}")
    @Produces(SVG_MEDIA_TYPE)
    @Operation(
            summary = "Returns a policy violations badge for a specific project"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A badge displaying current policy violation metrics of a project in SVG format",
                    content = @Content(schema = @Schema(type = "string"))
            ),
            @ApiResponse(responseCode = "403", description = "Badges are disabled"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @AuthenticationNotRequired
    public Response getProjectPolicyViolationsBadge(
            @Parameter(description = "The name of the project to query on", required = true)
            @PathParam("name") String name,
            @Parameter(description = "The version of the project to query on", required = true)
            @PathParam("version") String version) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            if (!qm.isEnabled(GENERAL_BADGE_ENABLED)) {
                return Response.status(Response.Status.FORBIDDEN).build();
            }
            final Project project = qm.getProject(name, version);
            if (project != null) {
                final ProjectMetrics metrics = withJdbiHandle(handle -> {
                    final var dao = handle.attach(MetricsDao.class);
                    return project.getCollectionLogic() == null
                            ? dao.getMostRecentProjectMetrics(project.getId())
                            : dao.getMostRecentCollectionProjectMetrics(project.getId());
                });
                final var badger = new Badger();

                String linkToProjectViolations = null;
                final ConfigProperty baseUrl = qm.getConfigProperty(GENERAL_BASE_URL.getGroupName(), GENERAL_BASE_URL.getPropertyName());
                if (baseUrl != null && baseUrl.getPropertyValue() != null) {
                    linkToProjectViolations = baseUrl.getPropertyValue() + "/projects/" + project.getUuid() + "/policyViolations";
                }
                return Response.ok(badger.generateViolations(metrics, linkToProjectViolations)).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }
}
