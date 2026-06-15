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
import com.github.packageurl.PackageURL;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonException;
import jakarta.json.JsonReader;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.DependencyGraphResponse;
import org.dependencytrack.util.PurlUtil;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * JAX-RS resources for processing requests related to DependencyGraph.
 */
@Path("/v1/dependencyGraph")
@Tag(name = "dependencyGraph")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class DependencyGraphResource extends AbstractApiResource {

    @GET
    @Path("/project/{uuid}/directDependencies")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of specific components and services from project UUID",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of specific components and services from project UUID",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = DependencyGraphResponse.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "Any component can be found"),
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getComponentsAndServicesByProjectUuid(@Parameter(description = "The UUID of the project", schema = @Schema(type = "string", format = "uuid"), required = true) final @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);

            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }

            requireAccess(qm, project);

            final String directDependenciesJSON = project.getDirectDependencies();

            if (directDependenciesJSON != null) {
                final List<DependencyGraphResponse> response = getDependencyGraphFromDirectDependenciesJSON(qm, directDependenciesJSON);
                return Response.ok(response).build();
            } else {
                return Response.ok(List.of()).build();
            }
        }
    }

    @GET
    @Path("/component/{uuid}/directDependencies")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of specific components and services from component UUID",
            description = "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of specific components and services from component UUID",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = DependencyGraphResponse.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "Any component can be found"),
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getComponentsAndServicesByComponentUuid(@Parameter(description = "The UUID of the component", schema = @Schema(type = "string", format = "uuid"), required = true) final @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }

            requireAccess(qm, component.getProject());

            final String directDependenciesJSON = component.getDirectDependencies();

            if (directDependenciesJSON != null) {
                final List<DependencyGraphResponse> response = getDependencyGraphFromDirectDependenciesJSON(qm, directDependenciesJSON);
                return Response.ok(response).build();
            } else {
                return Response.ok(List.of()).build();
            }
        }
    }


    /**
     * This method takes a {@link QueryManager} and a JSON string representing direct dependencies,
     * and returns a list of {@link DependencyGraphResponse} objects.
     *
     * @param qm                     the {@link QueryManager} used to fetch dependencies
     * @param directDependenciesJSON the JSON string representing direct dependencies
     * @return a list of {@link DependencyGraphResponse} objects representing the dependency graph
     * @since 4.9.0
     */
    private List<DependencyGraphResponse> getDependencyGraphFromDirectDependenciesJSON(final QueryManager qm, final String directDependenciesJSON) {
        // Parse the JSON to collect the UUIDs
        JsonArray directDependencies = null;

        try (final JsonReader jsonReader = Json.createReader(new StringReader(directDependenciesJSON))) {
            directDependencies = jsonReader.readArray();
        } catch (JsonException e) {
            return List.of();
        }

        final List<DependencyGraphResponse> response = new ArrayList<>(directDependencies.size());

        // Collect all the UUIDs
        final List<UUID> uuids = directDependencies.stream().map(directDependency -> directDependency.asJsonObject().getString("uuid")).map(UUID::fromString).toList();

        // Fetch all child components
        final List<DependencyGraphResponse> components = qm.getComponentDependencyGraphByUuids(uuids);

        final var componentsByPurlPackage = new HashMap<DependencyGraphResponse, String>(components.size());
        final var purlPackages = new HashSet<String>(components.size());

        for (final DependencyGraphResponse dependencyGraphResponse : components) {
            String purlPackage = null;
            if (dependencyGraphResponse.purl() != null) {
                final PackageURL purl = PurlUtil.silentPurl(dependencyGraphResponse.purl());
                if (purl != null && RepositoryType.UNSUPPORTED != RepositoryType.resolve(purl)) {
                    purlPackage = PurlUtil.purlPackageOnly(purl);
                    purlPackages.add(purlPackage);
                }
            }
            componentsByPurlPackage.put(dependencyGraphResponse, purlPackage);
        }

        final var latestVersionByPurl = new HashMap<String, String>();
        if (!purlPackages.isEmpty()) {
            final List<PackageMetadata> packageMetadataList = withJdbiHandle(
                    handle -> new PackageMetadataDao(handle).getAll(purlPackages));
            for (final PackageMetadata pm : packageMetadataList) {
                if (pm.latestVersion() != null) {
                    latestVersionByPurl.put(pm.purl().canonicalize(), pm.latestVersion());
                }
            }
        }

        for (final Map.Entry<DependencyGraphResponse, String> entry : componentsByPurlPackage.entrySet()) {
            if (entry.getValue() == null) {
                response.add(entry.getKey());
            } else {
                response.add(new DependencyGraphResponse(entry.getKey(), latestVersionByPurl.get(entry.getValue())));
            }
        }

        // if the response size is not equal to the uuids size, then we have some services to add
        if (uuids.size() != components.size()) {
            response.addAll(qm.getServiceDependencyGraphByUuids(uuids));
        }

        return response;
    }
}