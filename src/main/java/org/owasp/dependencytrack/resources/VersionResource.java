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
package org.owasp.dependencytrack.resources;

import alpine.auth.AuthenticationNotRequired;
import org.owasp.dependencytrack.model.About;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.GenericEntity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * JAX-RS resource that provides Dependency-Track version information.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
@Path("/version")
@Produces(MediaType.APPLICATION_JSON)
@Api(value = "version")
public final class VersionResource {

    @GET
    @ApiOperation(
            value = "Returns application version information",
            notes = "Returns a simple json object containing the name of the application and the version",
            response = About.class
    )
    @AuthenticationNotRequired
    public Response getVersion() {
        return Response.ok(new GenericEntity<About>(new About()) { }).build();
    }

}
