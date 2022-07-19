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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.resources.v1;

import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.search.FuzzyVulnerableSoftwareSearchManager;
import org.dependencytrack.search.SearchManager;
import org.dependencytrack.search.SearchResult;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * JAX-RS resources for processing search requests.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/v1/search")
@Api(value = "search", authorizations = @Authorization(value = "X-Api-Key"))
public class SearchResource extends AlpineResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Processes and returns search results",
            response = SearchResult.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
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
    @ApiOperation(
            value = "Processes and returns search results",
            response = SearchResult.class,
            notes = "Preferred search endpoint"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
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
    @ApiOperation(
            value = "Processes and returns search results",
            response = SearchResult.class,
            notes = "Preferred search endpoint"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
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
    @ApiOperation(
            value = "Processes and returns search results",
            response = SearchResult.class,
            notes = "Preferred search endpoint"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
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
    @ApiOperation(
            value = "Processes and returns search results",
            response = SearchResult.class,
            notes = "Preferred search endpoint"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
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
    @ApiOperation(
            value = "Processes and returns search results",
            response = SearchResult.class,
            notes = "Preferred search endpoint"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
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
    @ApiOperation(
            value = "Processes and returns search results",
            response = SearchResult.class,
            notes = "Preferred search endpoint"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
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
}
