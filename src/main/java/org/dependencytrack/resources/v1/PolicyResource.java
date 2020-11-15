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

import alpine.auth.PermissionRequired;
import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import io.swagger.annotations.ResponseHeader;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;

import javax.validation.Validator;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.List;

/**
 * JAX-RS resources for processing policies.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
@Path("/v1/policy")
@Api(value = "policy", authorizations = @Authorization(value = "X-Api-Key"))
public class PolicyResource extends AlpineResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a list of all policies",
            response = Policy.class,
            responseContainer = "List",
            responseHeaders = @ResponseHeader(name = TOTAL_COUNT_HEADER, response = Long.class, description = "The total number of policies")
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response getPolicies() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getPolicies();
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @GET
    @Path("/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Returns a specific policy",
            response = Policy.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The policy could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response getPolicy(
            @ApiParam(value = "The UUID of the policy to retrieve", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Policy policy = qm.getObjectByUuid(Policy.class, uuid);
            if (policy != null) {
                return Response.ok(policy).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The policy could not be found.").build();
            }
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Creates a new policy",
            response = Policy.class,
            code = 201
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 409, message = "A policy with the specified name already exists")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response createPolicy(Policy jsonPolicy) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonPolicy, "name")
        );

        try (QueryManager qm = new QueryManager()) {
            Policy policy = qm.getPolicy(StringUtils.trimToNull(jsonPolicy.getName()));
            if (policy == null) {
                policy = qm.createPolicy(
                        StringUtils.trimToNull(jsonPolicy.getName()),
                        Policy.Operator.ANY, Policy.ViolationState.INFO);
                return Response.status(Response.Status.CREATED).entity(policy).build();
            } else {
                return Response.status(Response.Status.CONFLICT).entity("A policy with the specified name already exists.").build();
            }
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Updates a policy",
            response = Policy.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The policy could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response updatePolicy(Policy jsonPolicy) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonPolicy, "name")
        );
        try (QueryManager qm = new QueryManager()) {
            Policy policy = qm.getObjectByUuid(Policy.class, jsonPolicy.getUuid());
            if (policy != null) {
                policy.setName(StringUtils.trimToNull(jsonPolicy.getName()));
                policy.setOperator(jsonPolicy.getOperator());
                policy.setViolationState(jsonPolicy.getViolationState());
                policy = qm.persist(policy);
                return Response.ok(policy).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The policy could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Deletes a policy",
            code = 204
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the policy could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response deletePolicy(
            @ApiParam(value = "The UUID of the policy to delete", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final Policy policy = qm.getObjectByUuid(Policy.class, uuid);
            if (policy != null) {
                qm.deletePolicy(policy);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the policy could not be found.").build();
            }
        }
    }

    @POST
    @Path("/{policyUuid}/project/{projectUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Adds a project to a policy",
            response = Policy.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 304, message = "The policy already has the specified project assigned"),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The policy or project could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response addProjectToPolicy(
            @ApiParam(value = "The UUID of the policy to add a project to", required = true)
            @PathParam("policyUuid") String policyUuid,
            @ApiParam(value = "The UUID of the project to add to the rule", required = true)
            @PathParam("projectUuid") String projectUuid) {
        try (QueryManager qm = new QueryManager()) {
            final Policy policy = qm.getObjectByUuid(Policy.class, policyUuid);
            if (policy == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The policy could not be found.").build();
            }
            final Project project = qm.getObjectByUuid(Project.class, projectUuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            final List<Project> projects = policy.getProjects();
            if (projects != null && !projects.contains(project)) {
                policy.getProjects().add(project);
                qm.persist(policy);
                return Response.ok(policy).build();
            }
            return Response.status(Response.Status.NOT_MODIFIED).build();
        }
    }

    @DELETE
    @Path("/{policyUuid}/project/{projectUuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Removes a project from a policy",
            response = Policy.class
    )
    @ApiResponses(value = {
            @ApiResponse(code = 304, message = "The policy does not have the specified project assigned"),
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The policy or project could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response removeProjectFromPolicy(
            @ApiParam(value = "The UUID of the policy to remove the project from", required = true)
            @PathParam("policyUuid") String policyUuid,
            @ApiParam(value = "The UUID of the project to remove from the policy", required = true)
            @PathParam("projectUuid") String projectUuid) {
        try (QueryManager qm = new QueryManager()) {
            final Policy policy = qm.getObjectByUuid(Policy.class, policyUuid);
            if (policy == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The policy could not be found.").build();
            }
            final Project project = qm.getObjectByUuid(Project.class, projectUuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            final List<Project> projects = policy.getProjects();
            if (projects != null && projects.contains(project)) {
                policy.getProjects().remove(project);
                qm.persist(policy);
                return Response.ok(policy).build();
            }
            return Response.status(Response.Status.NOT_MODIFIED).build();
        }
    }
}
