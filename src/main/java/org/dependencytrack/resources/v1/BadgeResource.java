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

import alpine.server.auth.AllowApiKeyInQueryParameter;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.misc.Badger;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Response;

/**
 * JAX-RS resources for processing metrics.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
@Path("/v1/badge")
@Tag(name = "badge")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth"),
        @SecurityRequirement(name = "ApiKeyQueryAuth")
})
public class BadgeResource extends AlpineResource {

    private static final String SVG_MEDIA_TYPE = "image/svg+xml";

    @GET
    @Path("/vulns/project/{uuid}")
    @Produces(SVG_MEDIA_TYPE)
    @Operation(
            summary = "Returns current metrics for a specific project",
            description = "<p>Requires permission <strong>VIEW_BADGES</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A badge displaying current vulnerability metrics for a project in SVG format",
                    content = @Content(schema = @Schema(type = "string"))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_BADGES)
    @AllowApiKeyInQueryParameter
    public Response getProjectVulnerabilitiesBadge(
            @Parameter(description = "The UUID of the project to retrieve metrics for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (!qm.hasAccess(super.getPrincipal(), project)) {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
                final ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
                final Badger badger = new Badger();
                return Response.ok(badger.generateVulnerabilities(metrics)).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/vulns/project/{name}/{version}")
    @Produces(SVG_MEDIA_TYPE)
    @Operation(
            summary = "Returns current metrics for a specific project",
            description = "<p>Requires permission <strong>VIEW_BADGES</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A badge displaying current vulnerability metrics for a project in SVG format",
                    content = @Content(schema = @Schema(type = "string"))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_BADGES)
    @AllowApiKeyInQueryParameter
    public Response getProjectVulnerabilitiesBadge(
            @Parameter(description = "The name of the project to query on", required = true)
            @PathParam("name") String name,
            @Parameter(description = "The version of the project to query on", required = true)
            @PathParam("version") String version) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getProject(name, version);
            if (project != null) {
                if (!qm.hasAccess(super.getPrincipal(), project)) {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
                final ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
                final Badger badger = new Badger();
                return Response.ok(badger.generateVulnerabilities(metrics)).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/violations/project/{uuid}")
    @Produces(SVG_MEDIA_TYPE)
    @Operation(
            summary = "Returns a policy violations badge for a specific project",
            description = "<p>Requires permission <strong>VIEW_BADGES</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A badge displaying current policy violation metrics of a project in SVG format",
                    content = @Content(schema = @Schema(type = "string"))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_BADGES)
    @AllowApiKeyInQueryParameter
    public Response getProjectPolicyViolationsBadge(
            @Parameter(description = "The UUID of the project to retrieve a badge for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (!qm.hasAccess(super.getPrincipal(), project)) {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
                final ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
                final Badger badger = new Badger();
                return Response.ok(badger.generateViolations(metrics)).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/violations/project/{name}/{version}")
    @Produces(SVG_MEDIA_TYPE)
    @Operation(
            summary = "Returns a policy violations badge for a specific project",
            description = "<p>Requires permission <strong>VIEW_BADGES</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A badge displaying current policy violation metrics of a project in SVG format",
                    content = @Content(schema = @Schema(type = "string"))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VIEW_BADGES)
    @AllowApiKeyInQueryParameter
    public Response getProjectPolicyViolationsBadge(
            @Parameter(description = "The name of the project to query on", required = true)
            @PathParam("name") String name,
            @Parameter(description = "The version of the project to query on", required = true)
            @PathParam("version") String version) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getProject(name, version);
            if (project != null) {
                if (!qm.hasAccess(super.getPrincipal(), project)) {
                    return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
                }
                final ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
                final Badger badger = new Badger();
                return Response.ok(badger.generateViolations(metrics)).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }
}
