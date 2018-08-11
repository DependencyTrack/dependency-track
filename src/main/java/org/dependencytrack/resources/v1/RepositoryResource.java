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
package org.dependencytrack.resources.v1;

import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineResource;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.ResponseHeader;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.QueryManager;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * JAX-RS resources for processing repositories.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
@Path("/v1/repository")
@Api(value = "repository", authorizations = @Authorization(value = "X-Api-Key"))
public class RepositoryResource extends AlpineResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all repositories",
            response = Repository.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of repositories")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    public Response getRepositories() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getRepositories();
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @GET
    @Path("/{type}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns repositories that support the specific type",
            response = Repository.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of repositories")

    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    public Response getRepositoriesByType(
            @ApiParam(value = "The type of repositories to retrieve", required = true)
            @PathParam("type")RepositoryType type) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getRepositories(type);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @GET
    @Path("/latest")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Attempts to resolve the latest version of the component available in the configured repositories",
            response = RepositoryMetaComponent.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 204, message = "The request was successful, but no repositories are configured to support the specified Package URL"),
            @ApiResponse(code = 400, message = "The specified Package URL is invalid and not in the correct format"),
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    public Response getRepositoryMetaComponent(
            @ApiParam(value = "The Package URL for the component to query", required = true)
            @QueryParam("purl") String purl) {
        try {
            PackageURL packageURL = new PackageURL(purl);
            try (QueryManager qm = new QueryManager(getAlpineRequest())) {
                final RepositoryType type = RepositoryType.resolve(packageURL);
                if (RepositoryType.UNSUPPORTED == type) {
                    return Response.noContent().build();
                }
                final RepositoryMetaComponent result = qm.getRepositoryMetaComponent(
                        RepositoryType.resolve(packageURL), packageURL.getNamespace(), packageURL.getName());
                return Response.ok(result).build();
            }
        } catch (MalformedPackageURLException e) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }

}
