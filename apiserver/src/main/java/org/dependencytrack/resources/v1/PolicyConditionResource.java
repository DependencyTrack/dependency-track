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
import dev.cel.common.CelIssue;
import dev.cel.common.CelValidationException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Validator;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
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
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.policy.cel.CelPolicyCompiler;
import org.dependencytrack.policy.cel.CelPolicyCompiler.CacheMode;
import org.dependencytrack.policy.cel.CelPolicyType;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.vo.CelExpressionError;
import org.dependencytrack.resources.v1.vo.CreatePolicyConditionRequest;
import org.dependencytrack.resources.v1.vo.PolicyConditionResponse;
import org.dependencytrack.resources.v1.vo.UpdatePolicyConditionRequest;

import java.util.ArrayList;
import java.util.Map;

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
public class PolicyConditionResource extends AbstractApiResource {

    @PUT
    @Path("/{uuid}/condition")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new policy condition for an existing policy",
            description = """
                    <p>
                      Requires permission <strong>POLICY_MANAGEMENT</strong>
                      or <strong>POLICY_MANAGEMENT_UPDATE</strong>
                    </p>
                    """
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "The created policy condition",
                    content = @Content(schema = @Schema(implementation = PolicyConditionResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the policy could not be found")
    })
    @PermissionRequired({
            Permissions.Constants.POLICY_MANAGEMENT,
            Permissions.Constants.POLICY_MANAGEMENT_UPDATE
    })
    public Response createPolicyCondition(
            @Parameter(
                    description = "The UUID of the policy",
                    schema = @Schema(type = "string", format = "uuid"),
                    required = true)
            @PathParam("uuid") @ValidUuid String uuid,
            CreatePolicyConditionRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(request, "value")
        );
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final PolicyCondition createdCondition = qm.callInTransaction(() -> {
                final Policy policy = qm.getObjectByUuid(Policy.class, uuid);
                if (policy == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The UUID of the policy could not be found.")
                            .build());
                }

                maybeValidateExpression(request.subject(), request.violationType(), request.value());

                return qm.createPolicyCondition(
                        policy,
                        request.subject(),
                        request.operator(),
                        StringUtils.trimToNull(request.value()),
                        request.violationType());
            });

            return Response
                    .status(Response.Status.CREATED)
                    .entity(PolicyConditionResponse.of(createdCondition))
                    .build();
        }
    }

    @POST
    @Path("/condition")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates a policy condition",
            description = """
                    <p>
                      Requires permission <strong>POLICY_MANAGEMENT</strong>
                      or <strong>POLICY_MANAGEMENT_UPDATE</strong>
                    </p>
                    """
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "The updated policy condition",
                    content = @Content(schema = @Schema(implementation = PolicyConditionResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the policy condition could not be found")
    })
    @PermissionRequired({
            Permissions.Constants.POLICY_MANAGEMENT,
            Permissions.Constants.POLICY_MANAGEMENT_UPDATE
    })
    public Response updatePolicyCondition(UpdatePolicyConditionRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(request, "value")
        );
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final PolicyCondition updatedCondition = qm.callInTransaction(() -> {
                final PolicyCondition existing = qm.getObjectByUuid(PolicyCondition.class, request.uuid());
                if (existing == null) {
                    throw new ClientErrorException(Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The UUID of the policy condition could not be found.")
                            .build());
                }

                maybeValidateExpression(request.subject(), request.violationType(), request.value());

                return qm.updatePolicyCondition(convert(request));
            });

            return Response
                    .ok(PolicyConditionResponse.of(updatedCondition))
                    .build();
        }
    }

    @DELETE
    @Path("/condition/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Deletes a policy condition from an existing policy",
            description = """
                    <p>
                      Requires permission <strong>POLICY_MANAGEMENT</strong>
                      or <strong>POLICY_MANAGEMENT_UPDATE</strong>
                    </p>
                    """
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Policy condition removed successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "The UUID of the policy condition could not be found")
    })
    @PermissionRequired({
            Permissions.Constants.POLICY_MANAGEMENT,
            Permissions.Constants.POLICY_MANAGEMENT_UPDATE
    })
    public Response deletePolicyCondition(
            @Parameter(description = "The UUID of the policy condition to delete", schema = @Schema(type = "string", format = "uuid"), required = true)
            @PathParam("uuid") @ValidUuid String uuid) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                final PolicyCondition pc = qm.getObjectByUuid(PolicyCondition.class, uuid);
                if (pc != null) {
                    qm.delete(pc);
                    return Response
                            .status(Response.Status.NO_CONTENT)
                            .build();
                } else {
                    return Response
                            .status(Response.Status.NOT_FOUND)
                            .entity("The UUID of the policy condition could not be found.")
                            .build();
                }
            });
        }
    }

    private static PolicyCondition convert(UpdatePolicyConditionRequest request) {
        final var pc = new PolicyCondition();
        pc.setUuid(request.uuid());
        pc.setSubject(request.subject());
        pc.setOperator(request.operator());
        pc.setValue(request.value());
        pc.setViolationType(request.violationType());
        return pc;
    }

    private void maybeValidateExpression(
            PolicyCondition.Subject subject,
            PolicyViolation.Type violationType,
            String value) {
        if (subject != PolicyCondition.Subject.EXPRESSION) {
            return;
        }

        if (violationType == null) {
            throw new BadRequestException(Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity("Expression conditions must define a violation type")
                    .build());
        }

        try {
            CelPolicyCompiler.getInstance(CelPolicyType.COMPONENT).compile(value, CacheMode.NO_CACHE);
        } catch (CelValidationException e) {
            final var celErrors = new ArrayList<CelExpressionError>();
            for (final CelIssue issue : e.getErrors()) {
                celErrors.add(new CelExpressionError(
                        issue.getSourceLocation().getLine(),
                        issue.getSourceLocation().getColumn(),
                        issue.getMessage()));
            }

            throw new BadRequestException(Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("celErrors", celErrors))
                    .build());
        }
    }

}
