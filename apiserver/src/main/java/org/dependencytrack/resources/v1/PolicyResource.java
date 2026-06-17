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
import jakarta.validation.Validator;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;
import org.dependencytrack.resources.v1.problems.ProblemDetails;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * JAX-RS resources for processing policies.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
@Path("/v1/policy")
@io.swagger.v3.oas.annotations.tags.Tag(name = "policy")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class PolicyResource extends AbstractApiResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a list of all policies",
            description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong> or <strong>POLICY_MANAGEMENT_READ</strong></p>"
    )
    @PaginatedApi
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all policies",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of policies", schema = @Schema(format = "integer")),
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = Policy.class)))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired({Permissions.Constants.POLICY_MANAGEMENT, Permissions.Constants.POLICY_MANAGEMENT_READ})
    public Response getPolicies() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getPolicies();
            final List<Policy> policies = result.getList(Policy.class);

            qm.makeTransientAll(policies);

            final Set<UUID> accessibleProjectUuids =
                    filterAccessibleProjects(
                            policies.stream()
                                    .map(Policy::getProjects)
                                    .filter(Objects::nonNull)
                                    .flatMap(List::stream)
                                    .toList())
                            .stream()
                            .map(Project::getUuid)
                            .collect(Collectors.toSet());
            for (final Policy policy : policies) {
                final List<Project> projects = policy.getProjects();
                if (projects == null) {
                    policy.setProjects(List.of());
                    continue;
                }

                policy.setProjects(projects.stream()
                        .filter(project -> accessibleProjectUuids.contains(project.getUuid()))
                        .toList());
            }

            return Response.ok(policies).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @GET
    @Path("/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a specific policy"
            , description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong> or <strong>POLICY_MANAGEMENT_READ</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A specific policy",
                    content = @Content(schema = @Schema(implementation = Policy.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The policy could not be found")
    })
    @PermissionRequired({Permissions.Constants.POLICY_MANAGEMENT, Permissions.Constants.POLICY_MANAGEMENT_READ})
    public Response getPolicy(
            @Parameter(description = "The UUID of the policy to retrieve", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Policy policy = qm.getObjectByUuid(Policy.class, uuid);
            if (policy == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The policy could not be found.").build();
            }

            qm.makeTransient(policy);
            policy.setProjects(filterAccessibleProjects(policy.getProjects()));
            return Response.ok(policy).build();
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new policy",
            description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong> or <strong>POLICY_MANAGEMENT_CREATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created policy",
                    content = @Content(schema = @Schema(implementation = Policy.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "409", description = "A policy with the specified name already exists")
    })
    @PermissionRequired({Permissions.Constants.POLICY_MANAGEMENT, Permissions.Constants.POLICY_MANAGEMENT_CREATE})
    public Response createPolicy(Policy jsonPolicy) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonPolicy, "name")
        );

        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                Policy policy = qm.getPolicy(StringUtils.trimToNull(jsonPolicy.getName()));
                if (policy == null) {
                    Policy.Operator operator = jsonPolicy.getOperator();
                    if (operator == null) {
                        operator = Policy.Operator.ANY;
                    }
                    Policy.ViolationState violationState = jsonPolicy.getViolationState();
                    if (violationState == null) {
                        violationState = Policy.ViolationState.INFO;
                    }
                    policy = qm.createPolicy(
                            StringUtils.trimToNull(jsonPolicy.getName()),
                            operator, violationState, jsonPolicy.isOnlyLatestProjectVersion());
                    return Response.status(Response.Status.CREATED).entity(policy).build();
                } else {
                    return Response.status(Response.Status.CONFLICT).entity("A policy with the specified name already exists.").build();
                }
            });
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates a policy",
            description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong> or <strong>POLICY_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated policy",
                    content = @Content(schema = @Schema(implementation = Policy.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The policy could not be found")
    })
    @PermissionRequired({Permissions.Constants.POLICY_MANAGEMENT, Permissions.Constants.POLICY_MANAGEMENT_UPDATE})
    public Response updatePolicy(Policy jsonPolicy) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonPolicy, "name")
        );
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Policy updatedPolicy = qm.callInTransaction(() -> {
                final Policy policy = qm.getObjectByUuid(Policy.class, jsonPolicy.getUuid());
                if (policy == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The policy could not be found.")
                            .build());
                }
                policy.setName(StringUtils.trimToNull(jsonPolicy.getName()));
                policy.setOperator(jsonPolicy.getOperator());
                policy.setViolationState(jsonPolicy.getViolationState());
                policy.setIncludeChildren(jsonPolicy.isIncludeChildren());
                policy.setOnlyLatestProjectVersion(jsonPolicy.isOnlyLatestProjectVersion());
                return qm.persist(policy);
            });

            qm.makeTransient(updatedPolicy);
            updatedPolicy.setProjects(filterAccessibleProjects(updatedPolicy.getProjects()));
            return Response.ok(updatedPolicy).build();
        }
    }

    @DELETE
    @Path("/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a policy"
            , description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong> or <strong>POLICY_MANAGEMENT_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Policy removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the policy could not be found")
    })
    @PermissionRequired({Permissions.Constants.POLICY_MANAGEMENT, Permissions.Constants.POLICY_MANAGEMENT_DELETE})
    public Response deletePolicy(
            @Parameter(description = "The UUID of the policy to delete", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                final Policy policy = qm.getObjectByUuid(Policy.class, uuid);
                if (policy != null) {
                    qm.delete(policy);
                    return Response.status(Response.Status.NO_CONTENT).build();
                } else {
                    return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the policy could not be found.").build();
                }
            });
        }
    }

    @POST
    @Path("/{policyUuid}/project/{projectUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Adds a project to a policy",
            description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong> or <strong>POLICY_MANAGEMENT_UPDATE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated policy",
                    content = @Content(schema = @Schema(implementation = Policy.class))
            ),
            @ApiResponse(responseCode = "304", description = "The policy already has the specified project assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The policy or project could not be found")
    })
    @PermissionRequired({Permissions.Constants.POLICY_MANAGEMENT, Permissions.Constants.POLICY_MANAGEMENT_UPDATE})
    public Response addProjectToPolicy(
            @Parameter(description = "The UUID of the policy to add a project to", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("policyUuid") @ValidUuid String policyUuid,
            @Parameter(description = "The UUID of the project to add to the rule", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("projectUuid") @ValidUuid String projectUuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Policy updatedPolicy = qm.callInTransaction(() -> {
                final Policy policy = qm.getObjectByUuid(Policy.class, policyUuid);
                if (policy == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The policy could not be found.")
                            .build());
                }
                final Project project = qm.getObjectByUuid(Project.class, projectUuid);
                if (project == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The project could not be found.")
                            .build());
                }
                requireAccess(qm, project);
                final List<Project> projects = policy.getProjects();
                if (projects == null || projects.contains(project)) {
                    return null;
                }
                policy.getProjects().add(project);
                return policy;
            });
            if (updatedPolicy == null) {
                return Response.status(Response.Status.NOT_MODIFIED).build();
            }

            qm.makeTransient(updatedPolicy);
            updatedPolicy.setProjects(filterAccessibleProjects(updatedPolicy.getProjects()));
            return Response.ok(updatedPolicy).build();
        }
    }

    @DELETE
    @Path("/{policyUuid}/project/{projectUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Removes a project from a policy",
            description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong> or <strong>POLICY_MANAGEMENT_DELETE</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated policy",
                    content = @Content(schema = @Schema(implementation = Policy.class))
            ),
            @ApiResponse(responseCode = "304", description = "The policy does not have the specified project assigned"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The policy or project could not be found")
    })
    @PermissionRequired({Permissions.Constants.POLICY_MANAGEMENT, Permissions.Constants.POLICY_MANAGEMENT_DELETE})
    public Response removeProjectFromPolicy(
            @Parameter(description = "The UUID of the policy to remove the project from", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("policyUuid") @ValidUuid String policyUuid,
            @Parameter(description = "The UUID of the project to remove from the policy", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("projectUuid") @ValidUuid String projectUuid) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Policy updatedPolicy = qm.callInTransaction(() -> {
                final Policy policy = qm.getObjectByUuid(Policy.class, policyUuid);
                if (policy == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The policy could not be found.")
                            .build());
                }
                final Project project = qm.getObjectByUuid(Project.class, projectUuid);
                if (project == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The project could not be found.")
                            .build());
                }
                requireAccess(qm, project);
                final List<Project> projects = policy.getProjects();
                if (projects == null || !projects.contains(project)) {
                    return null;
                }
                policy.getProjects().remove(project);
                return policy;
            });
            if (updatedPolicy == null) {
                return Response.status(Response.Status.NOT_MODIFIED).build();
            }

            qm.makeTransient(updatedPolicy);
            updatedPolicy.setProjects(filterAccessibleProjects(updatedPolicy.getProjects()));
            return Response.ok(updatedPolicy).build();
        }
    }
}
