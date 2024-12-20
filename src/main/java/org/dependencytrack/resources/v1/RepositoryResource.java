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

import alpine.persistence.PaginatedResult;
import alpine.security.crypto.DataEncryption;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;

import jakarta.validation.Validator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import static org.dependencytrack.resources.v1.AbstractConfigPropertyResource.ENCRYPTED_PLACEHOLDER;

/**
 * JAX-RS resources for processing repositories.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
@Path("/v1/repository")
@Tag(name = "repository")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class RepositoryResource extends AlpineResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all repositories",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all repositories",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of repositories", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = Repository.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response getRepositories() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getRepositories();
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @GET
    @Path("/{type}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns repositories that support the specific type",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of repositories that support the provided type",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of repositories", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = Repository.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response getRepositoriesByType(
            @Parameter(description = "The type of repositories to retrieve", required = true)
            @PathParam("type") RepositoryType type) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getRepositories(type);
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @GET
    @Path("/latest")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Attempts to resolve the latest version of the component available in the configured repositories")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The latest version of the component available in the configured repositories",
                    content = @Content(schema = @Schema(implementation = RepositoryMetaComponent.class))
            ),
            @ApiResponse(responseCode = "204", description = "The request was successful, but no repositories are configured to support the specified Package URL"),
            @ApiResponse(responseCode = "400", description = "The specified Package URL is invalid and not in the correct format"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The repository metadata for the specified component cannot be found"),
    })
    public Response getRepositoryMetaComponent(
            @Parameter(description = "The Package URL for the component to query", required = true)
            @QueryParam("purl") String purl) {
        try {
            final PackageURL packageURL = new PackageURL(purl);
            try (QueryManager qm = new QueryManager(getAlpineRequest())) {
                final RepositoryType type = RepositoryType.resolve(packageURL);
                if (RepositoryType.UNSUPPORTED == type) {
                    return Response.noContent().build();
                }
                final RepositoryMetaComponent result = qm.getRepositoryMetaComponent(
                        RepositoryType.resolve(packageURL), packageURL.getNamespace(), packageURL.getName());
                if (result == null) {
                    return Response.status(Response.Status.NOT_FOUND).entity("The repository metadata for the specified component cannot be found.").build();
                } else {
                    //todo: future enhancement: provide pass-thru capability for component metadata not already present and being tracked
                    return Response.ok(result).build();
                }
            }
        } catch (MalformedPackageURLException e) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new repository",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created repository",
                    content = @Content(schema = @Schema(implementation = Repository.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "A repository with the specified identifier already exists")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response createRepository(Repository jsonRepository) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonRepository, "identifier"),
                validator.validateProperty(jsonRepository, "url")
        );

        try (QueryManager qm = new QueryManager()) {
            final boolean exists = qm.repositoryExist(jsonRepository.getType(), StringUtils.trimToNull(jsonRepository.getIdentifier()));
            if (!exists) {
                final Repository repository = qm.createRepository(
                        jsonRepository.getType(),
                        StringUtils.trimToNull(jsonRepository.getIdentifier()),
                        StringUtils.trimToNull(jsonRepository.getUrl()),
                        jsonRepository.isEnabled(),
                        jsonRepository.isInternal(),
                        jsonRepository.isAuthenticationRequired(),
                        jsonRepository.getUsername(), jsonRepository.getPassword(),
                        jsonRepository.getBearerToken());

                return Response.status(Response.Status.CREATED).entity(repository).build();
            } else {
                return Response.status(Response.Status.CONFLICT).entity("A repository with the specified identifier already exists.").build();
            }
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates a repository",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated repository",
                    content = @Content(schema = @Schema(implementation = Repository.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the repository could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response updateRepository(Repository jsonRepository) {
        final Validator validator = super.getValidator();
        failOnValidationError(validator.validateProperty(jsonRepository, "identifier"),
                validator.validateProperty(jsonRepository, "url")
        );

        try (QueryManager qm = new QueryManager()) {
            Repository repository = qm.getObjectByUuid(Repository.class, jsonRepository.getUuid());
            if (repository != null) {
                final String url = StringUtils.trimToNull(jsonRepository.getUrl());
                String msg = "password";
                try {
                    // The password is not passed to the front-end, so it should only be overwritten if it is not null or not set to default value coming from ui
                    final String updatedPassword = jsonRepository.getPassword()!=null && !jsonRepository.getPassword().equals(ENCRYPTED_PLACEHOLDER)
                            ? DataEncryption.encryptAsString(jsonRepository.getPassword())
                            : repository.getPassword();

                    // The bearerToken is not passed to the front-end, so it should only be overwritten if it is not null or not set to default value coming from ui
                    msg = "bearerToken";
                    final String updatedBearerToken = jsonRepository.getBearerToken()!=null && !jsonRepository.getBearerToken().equals(ENCRYPTED_PLACEHOLDER)
                            ? DataEncryption.encryptAsString(jsonRepository.getBearerToken())
                            : repository.getBearerToken();

                    repository = qm.updateRepository(jsonRepository.getUuid(), repository.getIdentifier(), url,
                            jsonRepository.isInternal(), jsonRepository.isAuthenticationRequired(), jsonRepository.getUsername(), updatedPassword, updatedBearerToken, jsonRepository.isEnabled());
                    return Response.ok(repository).build();
                } catch (Exception e) {
                    return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("The specified repository %s could not be encrypted.".formatted(msg)).build();
                }
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the repository could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a repository",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Repository removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the repository could not be found")
    })
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response deleteRepository(
            @Parameter(description = "The UUID of the repository to delete", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Repository repository = qm.getObjectByUuid(Repository.class, uuid);
            if (repository != null) {
                qm.delete(repository);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the repository could not be found.").build();
            }
        }
    }
}
