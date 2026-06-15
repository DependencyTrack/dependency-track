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
import alpine.server.auth.PermissionRequired;
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
import jakarta.inject.Inject;
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
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;
import org.dependencytrack.resources.v1.vo.CreateRepositoryRequest;
import org.dependencytrack.resources.v1.vo.RepositoryResponse;
import org.dependencytrack.resources.v1.vo.UpdateRepositoryRequest;
import org.dependencytrack.secret.management.SecretManager;

import java.util.List;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

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
public class RepositoryResource extends AbstractApiResource {

    private final SecretManager secretManager;

    @Inject
    RepositoryResource(SecretManager secretManager) {
        this.secretManager = secretManager;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all repositories",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_READ</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all repositories",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of repositories", schema = @Schema(type = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = RepositoryResponse.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getRepositories() {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getRepositories();
            final List<RepositoryResponse> responses =
                    result.getList(Repository.class).stream()
                            .map(RepositoryResponse::of)
                            .toList();

            return Response
                    .ok(responses)
                    .header(TOTAL_COUNT_HEADER, result.getTotal())
                    .build();
        }
    }

    @GET
    @Path("/{type}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns repositories that support the specific type",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_READ</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of repositories that support the provided type",
                    headers = @Header(description = "The total number of repositories", name = TOTAL_COUNT_HEADER, schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = RepositoryResponse.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getRepositoriesByType(
            @Parameter(description = "The type of repositories to retrieve", required = true)
            @PathParam("type") RepositoryType type) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getRepositories(type);
            final List<RepositoryResponse> responses =
                    result.getList(Repository.class).stream()
                            .map(RepositoryResponse::of)
                            .toList();

            return Response
                    .ok(responses)
                    .header(TOTAL_COUNT_HEADER, result.getTotal())
                    .build();
        }
    }

    @GET
    @Path("/latest")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Attempts to resolve the latest version of the component available in the configured repositories"
    )
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
        final PackageURL parsedPurl;
        try {
            parsedPurl = new PackageURL(purl);
        } catch (MalformedPackageURLException e) {
            return Response
                    .status(Response.Status.BAD_REQUEST)
                    .build();
        }

        final RepositoryType type = RepositoryType.resolve(parsedPurl);
        if (RepositoryType.UNSUPPORTED == type) {
            return Response.noContent().build();
        }

        final PackageMetadata pm = withJdbiHandle(handle -> new PackageMetadataDao(handle).get(parsedPurl));
        if (pm == null) {
            return Response
                    .status(Response.Status.NOT_FOUND)
                    .entity("The repository metadata for the specified component cannot be found.")
                    .build();
        }

        return Response
                .ok(RepositoryMetaComponent.of(pm))
                .build();
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new repository",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_CREATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created repository",
                    content = @Content(schema = @Schema(implementation = RepositoryResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "A repository with the specified identifier already exists")
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_CREATE
    })
    public Response createRepository(CreateRepositoryRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(validator.validate(request));

        if (request.authenticationRequired() && request.password() == null) {
            return Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity("A password secret name is required when authentication is enabled.")
                    .build();
        }

        try (final var qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                final boolean exists = qm.repositoryExist(request.type(), request.identifier());
                if (!exists) {
                    if (request.password() != null
                            && secretManager.getSecretMetadata(request.password()) == null) {
                        return Response
                                .status(Response.Status.BAD_REQUEST)
                                .entity("The secret with name \"%s\" could not be found.".formatted(request.password()))
                                .build();
                    }

                    final Repository repository = qm.createRepository(
                            request.type(),
                            request.identifier(),
                            request.url(),
                            request.enabled(),
                            Boolean.TRUE.equals(request.internal()),
                            request.authenticationRequired(),
                            request.username(),
                            request.password());

                    return Response
                            .status(Response.Status.CREATED)
                            .entity(RepositoryResponse.of(repository))
                            .build();
                } else {
                    return Response
                            .status(Response.Status.CONFLICT)
                            .entity("A repository with the specified identifier already exists.")
                            .build();
                }
            });
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates a repository",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated repository",
                    content = @Content(schema = @Schema(implementation = RepositoryResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the repository could not be found")
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE
    })
    public Response updateRepository(UpdateRepositoryRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(validator.validate(request));

        if (request.authenticationRequired() && request.password() == null) {
            return Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity("A password secret name is required when authentication is enabled.")
                    .build();
        }

        try (final var qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                var repository = qm.getObjectByUuid(Repository.class, request.uuid());
                if (repository != null) {
                    if (request.password() != null && secretManager.getSecretMetadata(request.password()) == null) {
                        return Response.status(Response.Status.BAD_REQUEST)
                                .entity("The secret with name \"%s\" could not be found.".formatted(request.password()))
                                .build();
                    }

                    repository = qm.updateRepository(
                            request.uuid(),
                            repository.getIdentifier(),
                            request.url(),
                            Boolean.TRUE.equals(request.internal()),
                            request.authenticationRequired(),
                            request.username(),
                            request.password(),
                            request.enabled());

                    return Response
                            .ok(RepositoryResponse.of(repository))
                            .build();
                } else {
                    return Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The UUID of the repository could not be found.")
                            .build();
                }
            });
        }
    }

    @DELETE
    @Path("/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a repository",
            description = "<p>Requires permission <strong>SYSTEM_CONFIGURATION</strong> or <strong>SYSTEM_CONFIGURATION_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Repository removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the repository could not be found")
    })
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_DELETE
    })
    public Response deleteRepository(
            @Parameter(description = "The UUID of the repository to delete", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                final var repository = qm.getObjectByUuid(Repository.class, uuid);
                if (repository != null) {
                    qm.delete(repository);
                    return Response
                            .status(Response.Status.NO_CONTENT)
                            .build();
                } else {
                    return Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The UUID of the repository could not be found.")
                            .build();
                }
            });
        }
    }

}
