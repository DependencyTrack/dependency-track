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

import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.vo.BannerConfig;

import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import io.swagger.v3.oas.annotations.Operation;

@Path("/v1/banner")
@Tag(name = "banner")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})

public class BannerResource extends AlpineResource {

    public static final String CFG_GROUP = "banner";
    public static final String CFG_NAME = "config";

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Fetch banner configuration.")

    public Response getBannerConfiguration() {
        try (final QueryManager qm = new QueryManager(getAlpineRequest())) {
            final BannerConfig config = qm.getBannerConfig();
            return Response.ok(config).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Failed to fetch banner configuration")
                    .build();
        }

    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Update banner configuration.")
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)

    public Response updateBannerConfiguration(BannerConfig config) {
        if (config == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Banner configuration is required").build();
        }
        if (config.activateBanner) {
            if (config.customMode) {
                if (config.html == null || config.html.trim().isEmpty()) {
                    return Response.status(Response.Status.BAD_REQUEST)
                            .entity("Banner HTML is required when banner is active in custom mode").build();
                }
            } else {
                if (config.message == null || config.message.trim().isEmpty()) {
                    return Response.status(Response.Status.BAD_REQUEST)
                            .entity("Banner message is required when banner is active").build();
                }
            }
        }
        try (final QueryManager qm = new QueryManager(getAlpineRequest())) {
            final BannerConfig saved = qm.setBannerConfig(config);
            return Response.ok(saved).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Failed to update banner configuration").build();
        }
    }

}
