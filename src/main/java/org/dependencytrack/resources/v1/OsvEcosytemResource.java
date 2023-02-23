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
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.tasks.OsvDownloadTask;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.stream.Collectors;

@Path("/v1/integration/osv/ecosystem")
@Api(value = "ecosystem", authorizations = @Authorization(value = "X-Api-Key"))
public class OsvEcosytemResource extends AlpineResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all ecosystems in OSV",
            response = String.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response getAllEcosystems() {
        OsvDownloadTask osvDownloadTask = new OsvDownloadTask();
        final List<String> ecosystems = osvDownloadTask.getEcosystems();
        return Response.ok(ecosystems).build();
    }

    @GET
    @Path("/inactive")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of available inactive ecosystems in OSV to be selected by user",
            response = String.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response getInactiveEcosystems() {
        OsvDownloadTask osvDownloadTask = new OsvDownloadTask();
        var selectedEcosystems = osvDownloadTask.getEnabledEcosystems();
        final List<String> ecosystems = osvDownloadTask.getEcosystems().stream()
                .filter(element -> !selectedEcosystems.contains(element))
                .collect(Collectors.toList());
        return Response.ok(ecosystems).build();
    }
}
