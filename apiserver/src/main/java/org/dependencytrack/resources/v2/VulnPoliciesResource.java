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
package org.dependencytrack.resources.v2;

import alpine.server.auth.PermissionRequired;
import dev.cel.common.CelIssue;
import dev.cel.common.CelValidationException;
import jakarta.inject.Inject;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.api.v2.VulnPoliciesApi;
import org.dependencytrack.api.v2.model.CreateVulnPolicy201Response;
import org.dependencytrack.api.v2.model.CreateVulnPolicyRequest;
import org.dependencytrack.api.v2.model.GetVulnPolicyResponse;
import org.dependencytrack.api.v2.model.InvalidVulnPolicyConditionProblemDetails;
import org.dependencytrack.api.v2.model.ListVulnPoliciesResponse;
import org.dependencytrack.api.v2.model.ListVulnPoliciesResponseItem;
import org.dependencytrack.api.v2.model.ListVulnPolicyBundlesResponse;
import org.dependencytrack.api.v2.model.ListVulnPolicyBundlesResponseItem;
import org.dependencytrack.api.v2.model.ProblemDetails;
import org.dependencytrack.api.v2.model.TotalCount;
import org.dependencytrack.api.v2.model.TotalCountType;
import org.dependencytrack.api.v2.model.UpdateVulnPolicyRequest;
import org.dependencytrack.api.v2.model.VulnPolicyAnalysis;
import org.dependencytrack.api.v2.model.VulnPolicyBundleSyncStatus;
import org.dependencytrack.api.v2.model.VulnPolicyConditionError;
import org.dependencytrack.api.v2.model.VulnPolicyOperationMode;
import org.dependencytrack.api.v2.model.VulnPolicyRating;
import org.dependencytrack.api.v2.model.VulnPolicySource;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.SortDirection;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRun;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.exception.AlreadyExistsException;
import org.dependencytrack.persistence.jdbi.VulnerabilityPolicyDao;
import org.dependencytrack.persistence.jdbi.VulnerabilityPolicyDao.ListVulnPoliciesRow;
import org.dependencytrack.persistence.jdbi.VulnerabilityPolicyDao.VulnPolicyBundleRow;
import org.dependencytrack.persistence.jdbi.VulnerabilityPolicyDao.VulnPolicyDetailRow;
import org.dependencytrack.persistence.jdbi.VulnerabilityPolicyDao.VulnPolicyIdentityRow;
import org.dependencytrack.policy.cel.CelPolicyCompiler;
import org.dependencytrack.policy.cel.CelPolicyCompiler.CacheMode;
import org.dependencytrack.policy.cel.CelPolicyType;
import org.dependencytrack.policy.vulnerability.SyncVulnPolicyBundleWorkflow;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicy;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyAnalysis;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyOperation;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyRating;
import org.dependencytrack.proto.internal.workflow.v1.SyncVulnPolicyBundleArg;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v2.exception.ProblemDetailsException;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_TRIGGERED_BY;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.util.PersistenceUtil.isUniqueConstraintViolation;

/**
 * @since 5.0.0
 */
@Provider
public final class VulnPoliciesResource extends AbstractApiResource implements VulnPoliciesApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(VulnPoliciesResource.class);

    private final DexEngine dexEngine;

    @Inject
    VulnPoliciesResource(DexEngine dexEngine) {
        this.dexEngine = dexEngine;
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.POLICY_MANAGEMENT,
            Permissions.Constants.POLICY_MANAGEMENT_READ
    })
    public Response listVulnPolicies(
            Integer limit,
            String pageToken,
            String name) {
        final Page<ListVulnPoliciesRow> page = inJdbiTransaction(
                handle -> handle.attach(VulnerabilityPolicyDao.class)
                        .listVulnPolicies(limit, pageToken, name));

        final var response = ListVulnPoliciesResponse.builder()
                .items(page.items().stream()
                        .<ListVulnPoliciesResponseItem>map(row -> ListVulnPoliciesResponseItem.builder()
                                .uuid(row.uuid())
                                .name(row.name())
                                .description(row.description())
                                .author(row.author())
                                .priority(row.priority())
                                .operationMode(VulnPolicyOperationMode.fromValue(row.operationMode()))
                                .source(VulnPolicySource.fromValue(row.source()))
                                .build())
                        .toList())
                .nextPageToken(page.nextPageToken())
                .total(convertTotalCount(page.totalCount()))
                .build();

        return Response.ok(response).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.POLICY_MANAGEMENT,
            Permissions.Constants.POLICY_MANAGEMENT_READ
    })
    public Response getVulnPolicy(UUID uuid) {
        final VulnPolicyDetailRow policy = withJdbiHandle(
                handle -> handle.attach(VulnerabilityPolicyDao.class).getByUuid(uuid));
        if (policy == null) {
            throw new NotFoundException();
        }

        return Response.ok(convert(policy)).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.POLICY_MANAGEMENT,
            Permissions.Constants.POLICY_MANAGEMENT_CREATE
    })
    public Response createVulnPolicy(CreateVulnPolicyRequest request) {
        validateCelCondition(request.getCondition());

        final VulnerabilityPolicy policy = convert(request);

        final VulnPolicyIdentityRow created = inJdbiTransaction(handle -> {
            final var dao = handle.attach(VulnerabilityPolicyDao.class);
            final VulnPolicyIdentityRow createdIdentity = dao.create(policy);
            if (createdIdentity == null) {
                throw new AlreadyExistsException("A vulnerability policy with this name already exists");
            }

            return createdIdentity;
        });

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Created vulnerability policy {}", created.uuid());
        return Response.status(Response.Status.CREATED)
                .header("Location", getUriInfo()
                        .getBaseUriBuilder()
                        .path("/vuln-policies/{uuid}")
                        .resolveTemplate("uuid", created.uuid())
                        .build())
                .entity(CreateVulnPolicy201Response.builder().uuid(created.uuid()).build())
                .build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.POLICY_MANAGEMENT,
            Permissions.Constants.POLICY_MANAGEMENT_UPDATE
    })
    public Response updateVulnPolicy(UUID uuid, UpdateVulnPolicyRequest request) {
        validateCelCondition(request.getCondition());

        final VulnerabilityPolicy policy = convert(request);

        try {
            useJdbiTransaction(handle -> {
                final var dao = handle.attach(VulnerabilityPolicyDao.class);
                final boolean wasUpdated = dao.updateUserManagedByUuid(uuid, policy);
                if (!wasUpdated) {
                    final VulnPolicyDetailRow existing = dao.getByUuid(uuid);
                    if (existing == null) {
                        throw new NotFoundException();
                    }

                    throw new ForbiddenException("Bundle-managed policies cannot be modified");
                }
            });
        } catch (RuntimeException e) {
            if (isUniqueConstraintViolation(e)) {
                throw new AlreadyExistsException("A vulnerability policy with this name already exists", e);
            }
            throw e;
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Updated vulnerability policy {}", uuid);
        return Response.noContent().build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.POLICY_MANAGEMENT,
            Permissions.Constants.POLICY_MANAGEMENT_DELETE
    })
    public Response deleteVulnPolicy(UUID uuid) {
        final VulnerabilityPolicyDao.DeleteResult result = inJdbiTransaction(
                handle -> handle.attach(VulnerabilityPolicyDao.class).unassignAndDeleteByUuid(uuid));

        return switch (result) {
            case NOT_FOUND -> throw new NotFoundException();
            case BUNDLE_MANAGED -> throw new ForbiddenException(
                    "Bundle-managed policies cannot be deleted");
            case DELETED -> {
                LOGGER.info(
                        SecurityMarkers.SECURITY_AUDIT,
                        "Deleted vulnerability policy {}", uuid);
                yield Response.noContent().build();
            }
        };
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.POLICY_MANAGEMENT,
            Permissions.Constants.POLICY_MANAGEMENT_READ
    })
    public Response listVulnPolicyBundles() {
        final List<VulnPolicyBundleRow> bundles = inJdbiTransaction(
                handle -> handle.attach(VulnerabilityPolicyDao.class).listAllBundles());

        final List<ListVulnPolicyBundlesResponseItem> items = bundles.stream()
                .<ListVulnPolicyBundlesResponseItem>map(
                        bundle -> ListVulnPolicyBundlesResponseItem.builder()
                                .uuid(bundle.uuid())
                                .url(bundle.url())
                                .hash(bundle.hash())
                                .lastSuccessfulSync(bundle.lastSuccessfulSync() != null
                                        ? bundle.lastSuccessfulSync().toEpochMilli()
                                        : null)
                                .created(bundle.created() != null
                                        ? bundle.created().toEpochMilli()
                                        : null)
                                .updated(bundle.updated() != null
                                        ? bundle.updated().toEpochMilli()
                                        : null)
                                .build())
                .toList();

        return Response.ok(
                        ListVulnPolicyBundlesResponse.builder()
                                .items(items)
                                .total(TotalCount.builder()
                                        .count((long) items.size())
                                        .type(TotalCountType.EXACT)
                                        .build())
                                .build())
                .build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.POLICY_MANAGEMENT,
            Permissions.Constants.POLICY_MANAGEMENT_DELETE
    })
    public Response deleteVulnPolicyBundle(UUID uuid) {
        final VulnPolicyBundleRow deletedBundle = inJdbiTransaction(handle -> {
            final var dao = handle.attach(VulnerabilityPolicyDao.class);
            final VulnPolicyBundleRow bundle = dao.getBundleByUuid(uuid);
            if (bundle == null) {
                throw new NotFoundException();
            }

            dao.unassignAndDeleteByBundleId(bundle.id());
            return bundle;
        });

        LOGGER.info(
                SecurityMarkers.SECURITY_AUDIT,
                "Deleted vulnerability policy bundle {}",
                deletedBundle.uuid());
        return Response.noContent().build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.POLICY_MANAGEMENT,
            Permissions.Constants.POLICY_MANAGEMENT_READ
    })
    public Response getVulnPolicyBundleSyncStatus(UUID uuid) {
        if (!VulnerabilityPolicyDao.DEFAULT_BUNDLE_UUID.equals(uuid)) {
            final VulnPolicyBundleRow bundle = withJdbiHandle(
                    handle -> handle.attach(VulnerabilityPolicyDao.class).getBundleByUuid(uuid));
            if (bundle == null) {
                throw new NotFoundException();
            }
        }

        final String instanceId = "sync-vuln-policy-bundle:" + uuid;
        final Page<WorkflowRunMetadata> runsPage = dexEngine.listRuns(
                new ListWorkflowRunsRequest()
                        .withWorkflowInstanceId(instanceId)
                        .withSortBy(ListWorkflowRunsRequest.SortBy.CREATED_AT)
                        .withSortDirection(SortDirection.DESC)
                        .withLimit(1));

        if (runsPage.items().isEmpty()) {
            throw new NotFoundException();
        }

        final WorkflowRunMetadata runMetadata = runsPage.items().getFirst();
        String failureMessage = null;

        if (runMetadata.status() == WorkflowRunStatus.FAILED) {
            final WorkflowRun run = dexEngine.getRunById(runsPage.items().getFirst().id());
            if (run != null && run.failure() != null) {
                failureMessage = switch (run.failure().getFailureDetailsCase()) {
                    case ACTIVITY_FAILURE_DETAILS,
                         CHILD_WORKFLOW_FAILURE_DETAILS -> run.failure().getCause().getMessage();
                    default -> run.failure().getMessage();
                };
            }
        }

        final var syncStatus = VulnPolicyBundleSyncStatus.builder()
                .status(convertSyncStatus(runMetadata.status()))
                .startedAt(runMetadata.startedAt() != null
                        ? runMetadata.startedAt().toEpochMilli()
                        : null)
                .completedAt(runMetadata.completedAt() != null
                        ? runMetadata.completedAt().toEpochMilli()
                        : null)
                .failureReason(failureMessage)
                .build();

        return Response.ok(syncStatus).build();
    }

    private static VulnPolicyBundleSyncStatus.StatusEnum convertSyncStatus(WorkflowRunStatus status) {
        return switch (status) {
            case CREATED, SUSPENDED -> VulnPolicyBundleSyncStatus.StatusEnum.PENDING;
            case RUNNING -> VulnPolicyBundleSyncStatus.StatusEnum.RUNNING;
            case COMPLETED -> VulnPolicyBundleSyncStatus.StatusEnum.COMPLETED;
            case CANCELLED, FAILED -> VulnPolicyBundleSyncStatus.StatusEnum.FAILED;
        };
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.POLICY_MANAGEMENT,
            Permissions.Constants.POLICY_MANAGEMENT_UPDATE
    })
    public Response triggerVulnPolicyBundleSync(UUID uuid) {
        if (!VulnerabilityPolicyDao.DEFAULT_BUNDLE_UUID.equals(uuid)) {
            final VulnPolicyBundleRow bundle = withJdbiHandle(
                    handle -> handle.attach(VulnerabilityPolicyDao.class).getBundleByUuid(uuid));
            if (bundle == null) {
                throw new NotFoundException();
            }
        }

        final UUID runId = dexEngine.createRun(
                new CreateWorkflowRunRequest<>(SyncVulnPolicyBundleWorkflow.class)
                        .withWorkflowInstanceId("sync-vuln-policy-bundle:" + uuid)
                        .withLabels(Map.of(WF_LABEL_TRIGGERED_BY, getPrincipal().getName()))
                        .withArgument(
                                SyncVulnPolicyBundleArg.newBuilder()
                                        .setBundleUuid(uuid.toString())
                                        .build()));
        if (runId == null) {
            throw new ProblemDetailsException(
                    ProblemDetails.builder()
                            .status(Response.Status.CONFLICT.getStatusCode())
                            .title("Conflict")
                            .detail("Bundle synchronization is already in progress")
                            .build());
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Triggered vulnerability policy bundle sync");
        return Response
                .accepted()
                .header("Location", getUriInfo()
                        .getBaseUriBuilder()
                        .path("/vuln-policy-bundles/{uuid}/sync")
                        .resolveTemplate("uuid", uuid)
                        .build())
                .build();
    }

    private static void validateCelCondition(String condition) {
        final var policyCompiler = CelPolicyCompiler.getInstance(CelPolicyType.VULNERABILITY);
        try {
            policyCompiler.compile(condition, CacheMode.NO_CACHE);
        } catch (CelValidationException e) {
            final var errors = new ArrayList<VulnPolicyConditionError>();
            for (final CelIssue issue : e.getErrors()) {
                errors.add(VulnPolicyConditionError.builder()
                        .line(issue.getSourceLocation().getLine())
                        .column(issue.getSourceLocation().getColumn())
                        .message(issue.getMessage())
                        .build());
            }

            throw new ProblemDetailsException(
                    InvalidVulnPolicyConditionProblemDetails.builder()
                            .status(Response.Status.BAD_REQUEST.getStatusCode())
                            .title("Bad Request")
                            .detail("Condition is invalid.")
                            .errors(errors)
                            .build());
        }
    }

    private static VulnerabilityPolicy convert(CreateVulnPolicyRequest request) {
        return toVulnerabilityPolicy(
                request.getName(),
                request.getDescription(),
                request.getAuthor(),
                request.getCondition(),
                request.getAnalysis(),
                request.getRatings(),
                request.getOperationMode(),
                request.getPriority(),
                request.getValidFrom(),
                request.getValidUntil());
    }

    private static VulnerabilityPolicy convert(UpdateVulnPolicyRequest request) {
        return toVulnerabilityPolicy(
                request.getName(),
                request.getDescription(),
                request.getAuthor(),
                request.getCondition(),
                request.getAnalysis(),
                request.getRatings(),
                request.getOperationMode(),
                request.getPriority(),
                request.getValidFrom(),
                request.getValidUntil());
    }

    private static VulnerabilityPolicy toVulnerabilityPolicy(
            String name,
            String description,
            String author,
            String condition,
            VulnPolicyAnalysis analysis,
            List<VulnPolicyRating> ratings,
            VulnPolicyOperationMode operationMode,
            Integer priority,
            Long validFrom,
            Long validUntil) {
        final var policy = new VulnerabilityPolicy();
        policy.setName(name);
        policy.setDescription(description);
        policy.setAuthor(author);
        policy.setCondition(condition);
        policy.setAnalysis(convert(analysis));
        policy.setRatings(convertRatings(ratings));
        policy.setOperationMode(operationMode != null
                ? convert(operationMode)
                : VulnerabilityPolicyOperation.APPLY);
        policy.setPriority(priority != null ? priority : 0);
        policy.setValidFrom(convertTimestamp(validFrom));
        policy.setValidUntil(convertTimestamp(validUntil));
        return policy;
    }

    private static GetVulnPolicyResponse convert(VulnPolicyDetailRow policy) {
        final var builder = GetVulnPolicyResponse.builder()
                .uuid(policy.uuid())
                .name(policy.name())
                .description(policy.description())
                .author(policy.author())
                .condition(policy.condition())
                .operationMode(convert(policy.operationMode()))
                .priority(policy.priority())
                .source(policy.bundleId() != null
                        ? VulnPolicySource.BUNDLE
                        : VulnPolicySource.USER)
                .created(policy.created() != null
                        ? policy.created().toEpochMilli()
                        : null)
                .updated(policy.updated() != null
                        ? policy.updated().toEpochMilli()
                        : null)
                .validFrom(policy.validFrom() != null
                        ? policy.validFrom().toEpochMilli()
                        : null)
                .validUntil(policy.validUntil() != null
                        ? policy.validUntil().toEpochMilli()
                        : null);

        if (policy.analysis() != null) {
            final var analysis = policy.analysis();
            final var analysisBuilder = VulnPolicyAnalysis.builder()
                    .state(convert(analysis.getState()))
                    .details(analysis.getDetails())
                    .suppress(analysis.isSuppress());
            if (analysis.getJustification() != null) {
                analysisBuilder.justification(convert(analysis.getJustification()));
            }
            if (analysis.getVendorResponse() != null) {
                analysisBuilder.vendorResponse(convert(analysis.getVendorResponse()));
            }
            builder.analysis(analysisBuilder.build());
        }

        if (policy.ratings() != null) {
            builder.ratings(policy.ratings().stream()
                    .<VulnPolicyRating>map(
                            r -> VulnPolicyRating.builder()
                                    .method(convert(r.getMethod()))
                                    .severity(convert(r.getSeverity()))
                                    .vector(r.getVector())
                                    .score(r.getScore())
                                    .build())
                    .toList());
        }

        return builder.build();
    }

    private static VulnerabilityPolicyAnalysis convert(VulnPolicyAnalysis apiAnalysis) {
        if (apiAnalysis == null) {
            return null;
        }

        final var result = new VulnerabilityPolicyAnalysis();
        result.setState(convert(apiAnalysis.getState()));
        if (apiAnalysis.getJustification() != null) {
            result.setJustification(convert(apiAnalysis.getJustification()));
        }
        if (apiAnalysis.getVendorResponse() != null) {
            result.setVendorResponse(convert(apiAnalysis.getVendorResponse()));
        }
        result.setDetails(apiAnalysis.getDetails());
        result.setSuppress(apiAnalysis.getSuppress() != null && apiAnalysis.getSuppress());
        return result;
    }

    private static List<VulnerabilityPolicyRating> convertRatings(List<VulnPolicyRating> apiRatings) {
        if (apiRatings == null || apiRatings.isEmpty()) {
            return List.of();
        }

        return apiRatings.stream()
                .map(VulnPoliciesResource::convert)
                .toList();
    }

    private static VulnerabilityPolicyRating convert(VulnPolicyRating apiRating) {
        final var rating = new VulnerabilityPolicyRating();
        rating.setMethod(convert(apiRating.getMethod()));
        rating.setSeverity(convert(apiRating.getSeverity()));
        rating.setVector(apiRating.getVector());
        rating.setScore(apiRating.getScore() != null
                ? apiRating.getScore().doubleValue()
                : null);
        return rating;
    }

    private static VulnerabilityPolicyOperation convert(VulnPolicyOperationMode operationMode) {
        return switch (operationMode) {
            case DISABLED -> VulnerabilityPolicyOperation.DISABLED;
            case APPLY -> VulnerabilityPolicyOperation.APPLY;
            case LOG -> VulnerabilityPolicyOperation.LOG;
        };
    }

    private static VulnPolicyOperationMode convert(VulnerabilityPolicyOperation apiOperationMode) {
        return switch (apiOperationMode) {
            case DISABLED -> VulnPolicyOperationMode.DISABLED;
            case APPLY -> VulnPolicyOperationMode.APPLY;
            case LOG -> VulnPolicyOperationMode.LOG;
        };
    }

    private static VulnPolicyAnalysis.StateEnum convert(VulnerabilityPolicyAnalysis.State state) {
        return switch (state) {
            case EXPLOITABLE -> VulnPolicyAnalysis.StateEnum.EXPLOITABLE;
            case IN_TRIAGE -> VulnPolicyAnalysis.StateEnum.IN_TRIAGE;
            case FALSE_POSITIVE -> VulnPolicyAnalysis.StateEnum.FALSE_POSITIVE;
            case NOT_AFFECTED -> VulnPolicyAnalysis.StateEnum.NOT_AFFECTED;
            case RESOLVED -> VulnPolicyAnalysis.StateEnum.RESOLVED;
        };
    }

    private static VulnerabilityPolicyAnalysis.State convert(VulnPolicyAnalysis.StateEnum apiState) {
        return switch (apiState) {
            case EXPLOITABLE -> VulnerabilityPolicyAnalysis.State.EXPLOITABLE;
            case IN_TRIAGE -> VulnerabilityPolicyAnalysis.State.IN_TRIAGE;
            case FALSE_POSITIVE -> VulnerabilityPolicyAnalysis.State.FALSE_POSITIVE;
            case NOT_AFFECTED -> VulnerabilityPolicyAnalysis.State.NOT_AFFECTED;
            case RESOLVED -> VulnerabilityPolicyAnalysis.State.RESOLVED;
        };
    }

    private static VulnPolicyAnalysis.JustificationEnum convert(VulnerabilityPolicyAnalysis.Justification justification) {
        return switch (justification) {
            case CODE_NOT_PRESENT -> VulnPolicyAnalysis.JustificationEnum.CODE_NOT_PRESENT;
            case CODE_NOT_REACHABLE -> VulnPolicyAnalysis.JustificationEnum.CODE_NOT_REACHABLE;
            case REQUIRES_CONFIGURATION -> VulnPolicyAnalysis.JustificationEnum.REQUIRES_CONFIGURATION;
            case REQUIRES_DEPENDENCY -> VulnPolicyAnalysis.JustificationEnum.REQUIRES_DEPENDENCY;
            case REQUIRES_ENVIRONMENT -> VulnPolicyAnalysis.JustificationEnum.REQUIRES_ENVIRONMENT;
            case PROTECTED_BY_COMPILER -> VulnPolicyAnalysis.JustificationEnum.PROTECTED_BY_COMPILER;
            case PROTECTED_AT_RUNTIME -> VulnPolicyAnalysis.JustificationEnum.PROTECTED_AT_RUNTIME;
            case PROTECTED_AT_PERIMETER -> VulnPolicyAnalysis.JustificationEnum.PROTECTED_AT_PERIMETER;
            case PROTECTED_BY_MITIGATING_CONTROL ->
                    VulnPolicyAnalysis.JustificationEnum.PROTECTED_BY_MITIGATING_CONTROL;
        };
    }

    private static VulnerabilityPolicyAnalysis.Justification convert(VulnPolicyAnalysis.JustificationEnum apiJustification) {
        return switch (apiJustification) {
            case CODE_NOT_PRESENT -> VulnerabilityPolicyAnalysis.Justification.CODE_NOT_PRESENT;
            case CODE_NOT_REACHABLE -> VulnerabilityPolicyAnalysis.Justification.CODE_NOT_REACHABLE;
            case REQUIRES_CONFIGURATION -> VulnerabilityPolicyAnalysis.Justification.REQUIRES_CONFIGURATION;
            case REQUIRES_DEPENDENCY -> VulnerabilityPolicyAnalysis.Justification.REQUIRES_DEPENDENCY;
            case REQUIRES_ENVIRONMENT -> VulnerabilityPolicyAnalysis.Justification.REQUIRES_ENVIRONMENT;
            case PROTECTED_BY_COMPILER -> VulnerabilityPolicyAnalysis.Justification.PROTECTED_BY_COMPILER;
            case PROTECTED_AT_RUNTIME -> VulnerabilityPolicyAnalysis.Justification.PROTECTED_AT_RUNTIME;
            case PROTECTED_AT_PERIMETER -> VulnerabilityPolicyAnalysis.Justification.PROTECTED_AT_PERIMETER;
            case PROTECTED_BY_MITIGATING_CONTROL ->
                    VulnerabilityPolicyAnalysis.Justification.PROTECTED_BY_MITIGATING_CONTROL;
        };
    }

    private static VulnPolicyAnalysis.VendorResponseEnum convert(VulnerabilityPolicyAnalysis.Response response) {
        return switch (response) {
            case CAN_NOT_FIX -> VulnPolicyAnalysis.VendorResponseEnum.CAN_NOT_FIX;
            case WILL_NOT_FIX -> VulnPolicyAnalysis.VendorResponseEnum.WILL_NOT_FIX;
            case UPDATE -> VulnPolicyAnalysis.VendorResponseEnum.UPDATE;
            case ROLLBACK -> VulnPolicyAnalysis.VendorResponseEnum.ROLLBACK;
            case WORKAROUND_AVAILABLE -> VulnPolicyAnalysis.VendorResponseEnum.WORKAROUND_AVAILABLE;
        };
    }

    private static VulnerabilityPolicyAnalysis.Response convert(VulnPolicyAnalysis.VendorResponseEnum apiResponse) {
        return switch (apiResponse) {
            case CAN_NOT_FIX -> VulnerabilityPolicyAnalysis.Response.CAN_NOT_FIX;
            case WILL_NOT_FIX -> VulnerabilityPolicyAnalysis.Response.WILL_NOT_FIX;
            case UPDATE -> VulnerabilityPolicyAnalysis.Response.UPDATE;
            case ROLLBACK -> VulnerabilityPolicyAnalysis.Response.ROLLBACK;
            case WORKAROUND_AVAILABLE -> VulnerabilityPolicyAnalysis.Response.WORKAROUND_AVAILABLE;
        };
    }

    private static VulnPolicyRating.MethodEnum convert(VulnerabilityPolicyRating.Method method) {
        return switch (method) {
            case CVSSV2 -> VulnPolicyRating.MethodEnum.CVSSV2;
            case CVSSV3 -> VulnPolicyRating.MethodEnum.CVSSV3;
            case CVSSV4 -> VulnPolicyRating.MethodEnum.CVSSV4;
            case OWASP -> VulnPolicyRating.MethodEnum.OWASP;
        };
    }

    private static VulnerabilityPolicyRating.Method convert(VulnPolicyRating.MethodEnum apiMethod) {
        return switch (apiMethod) {
            case CVSSV2 -> VulnerabilityPolicyRating.Method.CVSSV2;
            case CVSSV3 -> VulnerabilityPolicyRating.Method.CVSSV3;
            case CVSSV4 -> VulnerabilityPolicyRating.Method.CVSSV4;
            case OWASP -> VulnerabilityPolicyRating.Method.OWASP;
        };
    }

    private static VulnPolicyRating.SeverityEnum convert(VulnerabilityPolicyRating.Severity severity) {
        return switch (severity) {
            case CRITICAL -> VulnPolicyRating.SeverityEnum.CRITICAL;
            case HIGH -> VulnPolicyRating.SeverityEnum.HIGH;
            case MEDIUM -> VulnPolicyRating.SeverityEnum.MEDIUM;
            case LOW -> VulnPolicyRating.SeverityEnum.LOW;
            case INFO -> VulnPolicyRating.SeverityEnum.INFO;
        };
    }

    private static VulnerabilityPolicyRating.Severity convert(VulnPolicyRating.SeverityEnum apiSeverity) {
        return switch (apiSeverity) {
            case CRITICAL -> VulnerabilityPolicyRating.Severity.CRITICAL;
            case HIGH -> VulnerabilityPolicyRating.Severity.HIGH;
            case MEDIUM -> VulnerabilityPolicyRating.Severity.MEDIUM;
            case LOW -> VulnerabilityPolicyRating.Severity.LOW;
            case INFO -> VulnerabilityPolicyRating.Severity.INFO;
        };
    }

    private static ZonedDateTime convertTimestamp(Long timestamp) {
        if (timestamp == null) {
            return null;
        }

        return ZonedDateTime.ofInstant(Instant.ofEpochMilli(timestamp), ZoneOffset.UTC);
    }

}
