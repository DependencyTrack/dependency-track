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
import alpine.resources.AlpineResource;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.persistence.QueryManager;
import javax.validation.Validator;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * JAX-RS resources for processing policies.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
@Path("/v1/policy")
@Api(value = "policyCondition", authorizations = @Authorization(value = "X-Api-Key"))
public class PolicyConditionResource extends AlpineResource {

    @PUT
    @Path("/{uuid}/condition")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Creates a new policy condition",
            response = PolicyCondition.class,
            code = 201
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the policy could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response createPolicyCondition(
            @ApiParam(value = "The UUID of the policy", required = true)
            @PathParam("uuid") String uuid,
            PolicyCondition jsonPolicyCondition) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonPolicyCondition, "value")
        );
        try (QueryManager qm = new QueryManager()) {
            Policy policy = qm.getObjectByUuid(Policy.class, uuid);
            if (policy != null) {
                final PolicyCondition pc = qm.createPolicyCondition(policy, jsonPolicyCondition.getSubject(),
                        jsonPolicyCondition.getOperator(), StringUtils.trimToNull(jsonPolicyCondition.getValue()));
                return Response.status(Response.Status.CREATED).entity(pc).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the policy could not be found.").build();
            }
        }
    }

    @POST
    @Path("/condition")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Updates a policy condition",
            response = PolicyCondition.class,
            code = 200
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the policy condition could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response updatePolicyCondition(PolicyCondition jsonPolicyCondition) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(jsonPolicyCondition, "value")
        );
        try (QueryManager qm = new QueryManager()) {
            PolicyCondition pc = qm.getObjectByUuid(PolicyCondition.class, jsonPolicyCondition.getUuid());
            if (pc != null) {
                pc = qm.updatePolicyCondition(jsonPolicyCondition);
                return Response.status(Response.Status.CREATED).entity(pc).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the policy condition could not be found.").build();
            }
        }
    }

    @DELETE
    @Path("/condition/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Deletes a policy condition",
            code = 204
    )
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "Unauthorized"),
            @ApiResponse(code = 404, message = "The UUID of the policy condition could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response deletePolicyCondition(
            @ApiParam(value = "The UUID of the policy condition to delete", required = true)
            @PathParam("uuid") String uuid) {
        try (QueryManager qm = new QueryManager()) {
            final PolicyCondition pc = qm.getObjectByUuid(PolicyCondition.class, uuid);
            if (pc != null) {
                qm.deletePolicyCondition(pc);
                return Response.status(Response.Status.NO_CONTENT).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The UUID of the policy condition could not be found.").build();
            }
        }
    }
}
