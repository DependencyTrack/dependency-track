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
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.owasp.dependencytrack.auth.Permission;
import org.owasp.dependencytrack.search.SearchManager;
import org.owasp.dependencytrack.search.SearchResult;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
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
    @Path("/{query}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Processes and returns search results",
            response = SearchResult.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permission.PROJECT_VIEW)
    public Response search(@PathParam("query") String query) {
        final SearchManager searchManager = new SearchManager();
        final SearchResult searchResult = searchManager.searchIndices(query, 10);
        return Response.ok(searchResult).build();
    }

}
