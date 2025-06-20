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

import alpine.common.logging.Logger;
import alpine.model.ApiKey;
import alpine.model.UserPrincipal;
import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.server.auth.ApiKeyAuthenticationService;
import alpine.server.auth.JwtAuthenticationService;
import alpine.server.auth.AuthenticationNotRequired;
import alpine.server.filters.AuthenticationFilter;
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
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Response;
import org.glassfish.jersey.server.ContainerRequest;
import org.owasp.security.logging.SecurityMarkers;

import javax.naming.AuthenticationException;
import java.security.Principal;

import static org.dependencytrack.model.ConfigPropertyConstants.GENERAL_BADGE_ENABLED;

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

    private final Logger LOGGER = Logger.getLogger(AuthenticationFilter.class);

    // Stand-in methods for alpine.server.filters.AuthenticationFilter and
    // alpine.server.filters.AuthorizationFilter to allow enabling and disabling of
    // unauthenticated access to the badges API during runtime, used solely to offer
    // a deprecation period for unauthenticated access to badges.
    private boolean passesAuthentication() {
        ContainerRequest request = (ContainerRequest) super.getRequestContext().getRequest();

        if (HttpMethod.OPTIONS.equals(request.getMethod())) {
            return true;
        }

        Principal principal = null;

        final ApiKeyAuthenticationService apiKeyAuthService = new ApiKeyAuthenticationService(request, true);
        if (apiKeyAuthService.isSpecified()) {
            try {
                principal = apiKeyAuthService.authenticate();
            } catch (AuthenticationException e) {
                LOGGER.info(SecurityMarkers.SECURITY_FAILURE, "Invalid API key asserted");
                return false;
            }
        }

        final JwtAuthenticationService jwtAuthService = new JwtAuthenticationService(request);
        if (jwtAuthService.isSpecified()) {
            try {
                principal = jwtAuthService.authenticate();
            } catch (AuthenticationException e) {
                LOGGER.info(SecurityMarkers.SECURITY_FAILURE, "Invalid JWT asserted");
                return false;
            }
        }

        if (principal == null) {
            return false;
        } else {
            super.getRequestContext().setProperty("Principal", principal);
            return true;
        }
    }

    private boolean passesAuthorization(final QueryManager qm) {
        final Principal principal = (Principal) super.getRequestContext().getProperty("Principal");
        if (principal == null) {
            LOGGER.info(SecurityMarkers.SECURITY_FAILURE, "A request was made without the assertion of a valid user principal");
            return false;
        }

        final String[] permissions = { Permissions.Constants.VIEW_BADGES };

        if (principal instanceof ApiKey) {
            final ApiKey apiKey = (ApiKey)principal;
            for (final String permission: permissions) {
                if (qm.hasPermission(apiKey, permission)) {
                    return true;
                }
            }
            LOGGER.info(SecurityMarkers.SECURITY_FAILURE, "Unauthorized access attempt made by API Key "
                    + apiKey.getMaskedKey() + " to " + ((ContainerRequest) super.getRequestContext()).getRequestUri().toString());
        } else {
            UserPrincipal user = null;
            if (principal instanceof ManagedUser) {
                user = qm.getManagedUser(((ManagedUser) principal).getUsername());
            } else if (principal instanceof LdapUser) {
                user = qm.getLdapUser(((LdapUser) principal).getUsername());
            } else if (principal instanceof OidcUser) {
                user = qm.getOidcUser(((OidcUser) principal).getUsername());
            }
            if (user == null) {
                LOGGER.info(SecurityMarkers.SECURITY_FAILURE, "A request was made but the system in unable to find the user principal");
                return false;
            }
            for (final String permission : permissions) {
                if (qm.hasPermission(user, permission, true)) {
                    return true;
                }
            }
            LOGGER.info(SecurityMarkers.SECURITY_FAILURE, "Unauthorized access attempt made by "
                    + user.getUsername() + " to " + ((ContainerRequest) super.getRequestContext()).getRequestUri().toString());
        }
        return false;
    }

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
            @ApiResponse(responseCode = "403", description = "Forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @AuthenticationNotRequired
    public Response getProjectVulnerabilitiesBadge(
            @Parameter(description = "The UUID of the project to retrieve metrics for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final boolean shouldBypassAuth = qm.isEnabled(GENERAL_BADGE_ENABLED);
            if (!shouldBypassAuth && !passesAuthentication()) {
                return Response.status(Response.Status.UNAUTHORIZED).build();
            }
            if (!shouldBypassAuth && !passesAuthorization(qm)) {
                return Response.status(Response.Status.FORBIDDEN).build();
            }
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (!shouldBypassAuth && !qm.hasAccess(super.getPrincipal(), project)) {
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
            @ApiResponse(responseCode = "403", description = "Forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @AuthenticationNotRequired
    public Response getProjectVulnerabilitiesBadge(
            @Parameter(description = "The name of the project to query on", required = true)
            @PathParam("name") String name,
            @Parameter(description = "The version of the project to query on", required = true)
            @PathParam("version") String version) {
        try (QueryManager qm = new QueryManager()) {
            final boolean shouldBypassAuth = qm.isEnabled(GENERAL_BADGE_ENABLED);
            if (!shouldBypassAuth && !passesAuthentication()) {
                return Response.status(Response.Status.UNAUTHORIZED).build();
            }
            if (!shouldBypassAuth && !passesAuthorization(qm)) {
                return Response.status(Response.Status.FORBIDDEN).build();
            }
            final Project project = qm.getProject(name, version);
            if (project != null) {
                if (!shouldBypassAuth && !qm.hasAccess(super.getPrincipal(), project)) {
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
            @ApiResponse(responseCode = "403", description = "Forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @AuthenticationNotRequired
    public Response getProjectPolicyViolationsBadge(
            @Parameter(description = "The UUID of the project to retrieve a badge for", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final boolean shouldBypassAuth = qm.isEnabled(GENERAL_BADGE_ENABLED);
            if (!shouldBypassAuth && !passesAuthentication()) {
                return Response.status(Response.Status.UNAUTHORIZED).build();
            }
            if (!shouldBypassAuth && !passesAuthorization(qm)) {
                return Response.status(Response.Status.FORBIDDEN).build();
            }
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                if (!shouldBypassAuth && !qm.hasAccess(super.getPrincipal(), project)) {
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
            @ApiResponse(responseCode = "403", description = "Forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @AuthenticationNotRequired
    public Response getProjectPolicyViolationsBadge(
            @Parameter(description = "The name of the project to query on", required = true)
            @PathParam("name") String name,
            @Parameter(description = "The version of the project to query on", required = true)
            @PathParam("version") String version) {
        try (QueryManager qm = new QueryManager()) {
            final boolean shouldBypassAuth = qm.isEnabled(GENERAL_BADGE_ENABLED);
            if (!shouldBypassAuth && !passesAuthentication()) {
                return Response.status(Response.Status.UNAUTHORIZED).build();
            }
            if (!shouldBypassAuth && !passesAuthorization(qm)) {
                return Response.status(Response.Status.FORBIDDEN).build();
            }
            final Project project = qm.getProject(name, version);
            if (project != null) {
                if (!shouldBypassAuth && !qm.hasAccess(super.getPrincipal(), project)) {
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
