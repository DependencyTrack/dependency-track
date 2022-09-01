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

import alpine.common.logging.Logger;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.annotations.*;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.tasks.OsvDownloadTask;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.List;

@Path("/v1/ecosystem")
@Api(value = "ecosystem", authorizations = @Authorization(value = "X-Api-Key"))
public class OsvEcosytemResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(OsvEcosytemResource.class);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all ecosystems in OSV",
            response = alpine.model.Permission.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response getAllEcosystems() {
        try (QueryManager qm = new QueryManager()) {
            OsvDownloadTask osvDownloadTask = new OsvDownloadTask();
            final List<String> ecosystems = osvDownloadTask.getEcosystems();
            return Response.ok(ecosystems).build();
        }
    }
}
