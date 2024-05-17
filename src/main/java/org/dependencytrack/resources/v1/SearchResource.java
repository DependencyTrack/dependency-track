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
import alpine.server.resources.AlpineResource;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.resources.v1.vo.BomUploadResponse;
import org.dependencytrack.search.FuzzyVulnerableSoftwareSearchManager;
import org.dependencytrack.search.SearchManager;
import org.dependencytrack.search.SearchResult;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Collections;
import java.util.Set;

/**
 * JAX-RS resources for processing search requests.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/search")
@Tag(name = "search")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class SearchResource extends AlpineResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Processes and returns search results",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The search result",
                    content = @Content(schema = @Schema(implementation = SearchResult.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response aggregateSearch(@QueryParam("query") String query) {
        final SearchManager searchManager = new SearchManager();
        final SearchResult searchResult = searchManager.searchIndices(query, 1000);
        return Response.ok(searchResult).build();
    }

    @Path("/project")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Processes and returns search results",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The search result",
                    content = @Content(schema = @Schema(implementation = SearchResult.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response projectSearch(@QueryParam("query") String query) {
        final SearchManager searchManager = new SearchManager();
        final SearchResult searchResult = searchManager.searchProjectIndex(query, 1000);
        return Response.ok(searchResult).build();
    }

    @Path("/component")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Processes and returns search results",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The search result",
                    content = @Content(schema = @Schema(implementation = SearchResult.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response componentSearch(@QueryParam("query") String query) {
        final SearchManager searchManager = new SearchManager();
        final SearchResult searchResult = searchManager.searchComponentIndex(query, 1000);
        return Response.ok(searchResult).build();
    }

    @Path("/service")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Processes and returns search results",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The search result",
                    content = @Content(schema = @Schema(implementation = SearchResult.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response serviceSearch(@QueryParam("query") String query) {
        final SearchManager searchManager = new SearchManager();
        final SearchResult searchResult = searchManager.searchServiceComponentIndex(query, 1000);
        return Response.ok(searchResult).build();
    }

    @Path("/license")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Processes and returns search results",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The search result",
                    content = @Content(schema = @Schema(implementation = SearchResult.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response licenseSearch(@QueryParam("query") String query) {
        final SearchManager searchManager = new SearchManager();
        final SearchResult searchResult = searchManager.searchLicenseIndex(query, 1000);
        return Response.ok(searchResult).build();
    }

    @Path("/vulnerability")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Processes and returns search results",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The search result",
                    content = @Content(schema = @Schema(implementation = SearchResult.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response vulnerabilitySearch(@QueryParam("query") String query) {
        final SearchManager searchManager = new SearchManager();
        final SearchResult searchResult = searchManager.searchVulnerabilityIndex(query, 1000);
        return Response.ok(searchResult).build();
    }

    @Path("/vulnerablesoftware")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Processes and returns search results",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The search result",
                    content = @Content(schema = @Schema(implementation = SearchResult.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response vulnerableSoftwareSearch(@QueryParam("query") String query, @QueryParam("cpe") String cpe) {
        if (StringUtils.isNotBlank(cpe)) {
            final FuzzyVulnerableSoftwareSearchManager searchManager = new FuzzyVulnerableSoftwareSearchManager(false);
            final SearchResult searchResult = searchManager.searchIndex(FuzzyVulnerableSoftwareSearchManager.getLuceneCpeRegexp(cpe));
            return Response.ok(searchResult).build();
        } else {
            final SearchManager searchManager = new SearchManager();
            final SearchResult searchResult = searchManager.searchVulnerableSoftwareIndex(query, 1000);
            return Response.ok(searchResult).build();
        }
    }

    @Path("/reindex")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Rebuild lucene indexes for search operations",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Token to be used for checking index rebuild progress",
                    content = @Content(schema = @Schema(implementation = BomUploadResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "400", description = "No valid index type was provided")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response reindex(@QueryParam("type") Set<String> type) {
        if (type == null || type.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("No valid index type was provided").build();
        }
        try {
            final SearchManager searchManager = new SearchManager();
            String chainIdentifier = searchManager.reindex(type);
            return Response.ok(Collections.singletonMap("token", chainIdentifier)).build();
        } catch (IllegalArgumentException exception) {
            return Response.status(Response.Status.BAD_REQUEST).entity(exception.getMessage()).build();
        }
    }
}
