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
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.RepositoryQueryManager;
import org.dependencytrack.resources.v1.vo.DependencyGraphResponse;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonException;
import javax.json.JsonReader;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * JAX-RS resources for processing requests related to DependencyGraph.
 */
@Path("/v1/dependencyGraph")
@Api(value = "dependencyGraph", authorizations = @Authorization(value = "X-Api-Key"))
public class DependencyGraphResource extends AlpineResource {

    @GET
    @Path("/project/{uuid}/directDependencies")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of specific components and services from project UUID",
            response = DependencyGraphResponse.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to a specified component is forbidden"),
            @ApiResponse(code = 404, message = "Any component can be found"),
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getComponentsAndServicesByProjectUuid(final @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);

            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }

            if (!qm.hasAccess(super.getPrincipal(), project)) {
                return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified project is forbidden").build();
            }

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
    @ApiOperation(
            value = "Returns a list of specific components and services from component UUID",
            response = DependencyGraphResponse.class,
            responseContainer = "List"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 403, message = "Access to a specified component is forbidden"),
            @ApiResponse(code = 404, message = "Any component can be found"),
    })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getComponentsAndServicesByComponentUuid(final @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, uuid);
            if (component == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The component could not be found.").build();
            }

            if (!qm.hasAccess(super.getPrincipal(), component.getProject())) {
                return Response.status(Response.Status.FORBIDDEN).entity("Access to the specified component is forbidden").build();
            }

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

        // Map the components to their respective repository types
        final HashMap<DependencyGraphResponse, RepositoryQueryManager.RepositoryMetaComponentSearch> repoMetaComponentSearchListHashMap = new HashMap<>(components.size());

        // Set of unique repository meta components
        final HashSet<RepositoryQueryManager.RepositoryMetaComponentSearch> repoMetaComponentSearches = new HashSet<>(components.size());


        PackageURL purl = null;
        RepositoryType type = null;
        RepositoryQueryManager.RepositoryMetaComponentSearch repositoryMetaComponentSearch = null;

        // Fetch all the latest versions for the components
        for (DependencyGraphResponse dependencyGraphResponse : components) {

            // Only components that got a purl can be searched for latest version
            if (dependencyGraphResponse.purl() != null) {
                try {
                    purl = new PackageURL(dependencyGraphResponse.purl());
                } catch (MalformedPackageURLException e) {
                    purl = null;
                }

                if (purl != null) {
                    type = RepositoryType.resolve(purl);
                    if (RepositoryType.UNSUPPORTED != type) {

                        // Create a new repository meta component search
                        repositoryMetaComponentSearch = new RepositoryQueryManager.RepositoryMetaComponentSearch(type, purl.getNamespace(), purl.getName());

                        // Add the repository meta component search to the set
                        repoMetaComponentSearches.add(repositoryMetaComponentSearch);
                    }
                }
            }

            // Keep the link between the component and the repository meta component search
            repoMetaComponentSearchListHashMap.put(dependencyGraphResponse, repositoryMetaComponentSearch);
        }

        // Fetch the latest versions for the components
        final List<RepositoryMetaComponent> repositoryMetaComponents = qm.getRepositoryMetaComponentsBatch(repoMetaComponentSearches.stream().toList());

        // Create HashMap with the repository meta components and their latest version
        final HashMap<RepositoryQueryManager.RepositoryMetaComponentSearch, String> repositoryMetaComponentsSet = new HashMap<>(repositoryMetaComponents.size());

        for (RepositoryMetaComponent repositoryMetaComponent : repositoryMetaComponents) {
            repositoryMetaComponentsSet.put(new RepositoryQueryManager.RepositoryMetaComponentSearch(repositoryMetaComponent.getRepositoryType(), repositoryMetaComponent.getNamespace(), repositoryMetaComponent.getName()), repositoryMetaComponent.getLatestVersion());
        }

        // Add the latest version to the components
        for (Map.Entry<DependencyGraphResponse, RepositoryQueryManager.RepositoryMetaComponentSearch> dependencyGraphResponseEntry : repoMetaComponentSearchListHashMap.entrySet()) {
            if (dependencyGraphResponseEntry.getValue() == null) {
                response.add(dependencyGraphResponseEntry.getKey());
            } else {
                response.add(new DependencyGraphResponse(dependencyGraphResponseEntry.getKey(), repositoryMetaComponentsSet.get(dependencyGraphResponseEntry.getValue())));
            }
        }

        // if the response size is not equal to the uuids size, then we have some services to add
        if (uuids.size() != components.size()) {
            response.addAll(qm.getServiceDependencyGraphByUuids(uuids));
        }

        return response;
    }
}
