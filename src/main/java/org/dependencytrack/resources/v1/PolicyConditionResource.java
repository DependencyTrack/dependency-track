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
import alpine.server.resources.AlpineResource;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;

import jakarta.validation.Validator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * JAX-RS resources for processing policies.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
@Path("/v1/policy")
@Tag(name = "policyCondition")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class PolicyConditionResource extends AlpineResource {

    @PUT
    @Path("/{uuid}/condition")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new policy condition",
            description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created policy condition",
                    content = @Content(schema = @Schema(implementation = PolicyCondition.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the policy could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response createPolicyCondition(
            @Parameter(description = "The UUID of the policy", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid,
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
    @Operation(
            summary = "Updates a policy condition",
            description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated policy condition",
                    content = @Content(schema = @Schema(implementation = PolicyCondition.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the policy condition could not be found")
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
    @Operation(
            summary = "Deletes a policy condition",
            description = "<p>Requires permission <strong>POLICY_MANAGEMENT</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Policy condition removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the policy condition could not be found")
    })
    @PermissionRequired(Permissions.Constants.POLICY_MANAGEMENT)
    public Response deletePolicyCondition(
            @Parameter(description = "The UUID of the policy condition to delete", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
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
