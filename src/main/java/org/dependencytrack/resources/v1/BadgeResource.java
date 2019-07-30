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

import alpine.auth.AuthenticationNotRequired;
import alpine.resources.AlpineResource;
import io.swagger.annotations.*;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.misc.Badger;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

/**
 * JAX-RS resources for processing metrics.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
@Path("/v1/badge")
@Api(value = "badge", authorizations = @Authorization(value = "X-Api-Key"))
public class BadgeResource extends AlpineResource {

    private static final String SVG_MEDIA_TYPE = "image/svg+xml";

    @GET
    @Path("/vulns/project/{uuid}")
    @Produces(SVG_MEDIA_TYPE)
    @ApiOperation(
            value = "Returns current metrics for a specific project",
            response = ProjectMetrics.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The project could not be found")
    })
    //@PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    @AuthenticationNotRequired // todo remove this
    public Response getProjectVulnerabilitiesBadge(
            @ApiParam(value = "The UUID of the project to retrieve metrics for", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                final ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
                final Badger badger = new Badger();
                return Response.ok(badger.generate(metrics)).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }
}