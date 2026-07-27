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

import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRun;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.dex.proto.failure.v1.ActivityFailureDetails;
import org.dependencytrack.dex.proto.failure.v1.Failure;
import org.dependencytrack.persistence.jdbi.VulnerabilityPolicyDao;
import org.dependencytrack.persistence.jdbi.VulnerabilityPolicyDao.VulnPolicyBundleRow;
import org.dependencytrack.persistence.jdbi.VulnerabilityPolicyDao.VulnPolicyDetailRow;
import org.dependencytrack.persistence.jdbi.VulnerabilityPolicyDao.VulnPolicyIdentityRow;
import org.dependencytrack.model.PolicyAnnotation;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicy;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyAnalysis;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyOperation;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyRating;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentMatchers;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

class VulnPoliciesResourceTest extends ResourceTest {

    private static final DexEngine DEX_ENGINE_MOCK = mock(DexEngine.class);

    @BeforeEach
    void beforeEach() {
        reset(DEX_ENGINE_MOCK);
    }

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig()
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bind(DEX_ENGINE_MOCK).to(DexEngine.class);
                        }
                    }));

    @Test
    void shouldListVulnPolicies() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_READ);

        final var vulnPolicy = createVulnPolicyInstance(0);
        useJdbiHandle(handle -> handle.attach(VulnerabilityPolicyDao.class).create(vulnPolicy));

        final Response response = jersey
                .target("/vuln-policies")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "items": [
                    {
                      "uuid": "${json-unit.any-string}",
                      "name": "name 0",
                      "priority": 0,
                      "operation_mode": "APPLY",
                      "source": "USER"
                    }
                  ],
                  "total": {
                    "count": 1,
                    "type": "EXACT"
                  }
                }
                """);
    }

    @Test
    void shouldListVulnPoliciesWithPagination() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_READ);

        for (int i = 0; i < 3; i++) {
            final var vulnPolicy = createVulnPolicyInstance(i);
            useJdbiHandle(handle -> handle.attach(VulnerabilityPolicyDao.class).create(vulnPolicy));
        }

        final Response response = jersey
                .target("/vuln-policies")
                .queryParam("limit", 2)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject responseJson = parseJsonObject(response);
        assertThat(responseJson.getJsonArray("items")).hasSize(2);
        assertThat(responseJson.getString("next_page_token")).isNotEmpty();
        assertThat(responseJson.getJsonObject("total").getInt("count")).isEqualTo(3);

        final String nextPageToken = responseJson.getString("next_page_token");
        final Response nextResponse = jersey
                .target("/vuln-policies")
                .queryParam("limit", 2)
                .queryParam("page_token", nextPageToken)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(nextResponse.getStatus()).isEqualTo(200);
        final JsonObject nextJson = parseJsonObject(nextResponse);
        assertThat(nextJson.getJsonArray("items")).hasSize(1);
        assertThat(nextJson.containsKey("next_page_token")).isFalse();
    }

    @Test
    void shouldCreateVulnPolicy() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_CREATE);

        final Response response = jersey
                .target("/vuln-policies")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "test-policy",
                          "description": "A test policy",
                          "author": "test-author",
                          "condition": "vuln.id == \\"CVE-2024-1234\\"",
                          "analysis": {
                            "state": "NOT_AFFECTED",
                            "justification": "CODE_NOT_REACHABLE",
                            "suppress": true,
                            "annotations": [
                              { "key": "compliance", "value": "gem" },
                              { "key": "source", "value": "test" }
                            ]
                          },
                          "priority": 10
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(201);
        assertThat(response.getHeaderString("Location")).contains("/vuln-policies/");
        final JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "uuid": "${json-unit.any-string}"
                }
                """);

        final UUID createdUuid = UUID.fromString(responseJson.getString("uuid"));
        final VulnPolicyDetailRow created = withJdbiHandle(
                handle -> handle.attach(VulnerabilityPolicyDao.class).getByUuid(createdUuid));
        assertThat(created).isNotNull();
        assertThat(created.name()).isEqualTo("test-policy");
        assertThat(created.description()).isEqualTo("A test policy");
        assertThat(created.author()).isEqualTo("test-author");
        assertThat(created.condition()).isEqualTo("vuln.id == \"CVE-2024-1234\"");
        assertThat(created.analysis().getState()).isEqualTo(VulnerabilityPolicyAnalysis.State.NOT_AFFECTED);
        assertThat(created.analysis().getJustification()).isEqualTo(VulnerabilityPolicyAnalysis.Justification.CODE_NOT_REACHABLE);
        assertThat(created.analysis().isSuppress()).isTrue();
        assertThat(created.analysis().getAnnotations())
                .containsExactly(
                        new PolicyAnnotation("compliance", "gem"),
                        new PolicyAnnotation("source", "test"));
        assertThat(created.priority()).isEqualTo(10);
        assertThat(created.operationMode()).isEqualTo(VulnerabilityPolicyOperation.APPLY);
    }

    @Test
    void shouldGetVulnPolicyWithAnalysisAnnotations() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_READ);

        final var vulnPolicy = createVulnPolicyInstance(0);
        vulnPolicy.getAnalysis().setAnnotations(List.of(
                new PolicyAnnotation("compliance", "gem"),
                new PolicyAnnotation("owner", "security")));
        final VulnPolicyIdentityRow created = inJdbiTransaction(
                handle -> handle.attach(VulnerabilityPolicyDao.class).create(vulnPolicy));

        final Response response = jersey
                .target("/vuln-policies/%s".formatted(created.uuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .node("analysis.annotations")
                .isEqualTo(/* language=JSON */ """
                        [
                          { "key": "compliance", "value": "gem" },
                          { "key": "owner", "value": "security" }
                        ]
                        """);
    }

    @Test
    void shouldGetVulnPolicyByUuid() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_READ);

        final var vulnPolicy = createVulnPolicyInstance(0);
        final VulnPolicyIdentityRow created = inJdbiTransaction(
                handle -> handle.attach(VulnerabilityPolicyDao.class).create(vulnPolicy));

        final Response response = jersey
                .target("/vuln-policies/%s".formatted(created.uuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        final String body = getPlainTextBody(response);
        assertThatJson(body).node("uuid").isEqualTo(created.uuid().toString());
        assertThatJson(body).node("name").isEqualTo("name 0");
    }

    @Test
    void shouldReturn404WhenGettingNonExistentPolicy() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_READ);

        final Response response = jersey
                .target("/vuln-policies/00000000-0000-0000-0000-000000000001")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void shouldUpdateVulnPolicy() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT, Permissions.POLICY_MANAGEMENT_UPDATE);

        final var vulnPolicy = createVulnPolicyInstance(0);
        final VulnPolicyIdentityRow created = inJdbiTransaction(
                handle -> handle.attach(VulnerabilityPolicyDao.class).create(vulnPolicy));

        final Response response = jersey
                .target("/vuln-policies/%s".formatted(created.uuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "updated-name",
                          "description": "updated description",
                          "condition": "vuln.id == \\"CVE-2024-1234\\"",
                          "analysis": {
                            "state": "NOT_AFFECTED",
                            "suppress": true
                          },
                          "priority": 42
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(204);

        final VulnPolicyDetailRow updated = withJdbiHandle(
                handle -> handle.attach(VulnerabilityPolicyDao.class).getByUuid(created.uuid()));
        assertThat(updated).isNotNull();
        assertThat(updated.name()).isEqualTo("updated-name");
        assertThat(updated.description()).isEqualTo("updated description");
        assertThat(updated.condition()).isEqualTo("vuln.id == \"CVE-2024-1234\"");
        assertThat(updated.analysis().getState()).isEqualTo(VulnerabilityPolicyAnalysis.State.NOT_AFFECTED);
        assertThat(updated.analysis().getJustification()).isNull();
        assertThat(updated.analysis().isSuppress()).isTrue();
        assertThat(updated.priority()).isEqualTo(42);
        assertThat(updated.operationMode()).isEqualTo(VulnerabilityPolicyOperation.APPLY);
    }

    @Test
    void shouldReturn404WhenUpdatingNonExistentPolicy() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT, Permissions.POLICY_MANAGEMENT_UPDATE);

        final Response response = jersey
                .target("/vuln-policies/00000000-0000-0000-0000-000000000001")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "updated-name",
                          "condition": "vuln.id == \\"CVE-2024-1234\\"",
                          "analysis": {
                            "state": "NOT_AFFECTED",
                            "suppress": true
                          }
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void shouldReturn403WhenUpdatingBundleManagedPolicy() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT, Permissions.POLICY_MANAGEMENT_UPDATE);

        final VulnPolicyIdentityRow created = inJdbiTransaction(handle -> {
            final var dao = handle.attach(VulnerabilityPolicyDao.class);
            final VulnPolicyBundleRow bundle = dao.createBundle(
                    UUID.fromString("00000000-0000-0000-0000-000000000002"),
                    URI.create("https://example.com/bundle.zip"));
            final var policy = createVulnPolicyInstance(0);
            return dao.createAll(bundle.id(), List.of(policy)).getFirst();
        });

        final Response response = jersey
                .target("/vuln-policies/%s".formatted(created.uuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "updated-name",
                          "condition": "vuln.id == \\"CVE-2024-1234\\"",
                          "analysis": {
                            "state": "NOT_AFFECTED",
                            "suppress": true
                          }
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void shouldDeleteVulnPolicy() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT, Permissions.POLICY_MANAGEMENT_DELETE);

        final var vulnPolicy = createVulnPolicyInstance(0);
        final VulnPolicyIdentityRow created = inJdbiTransaction(
                handle -> handle.attach(VulnerabilityPolicyDao.class).create(vulnPolicy));

        final Response response = jersey
                .target("/vuln-policies/%s".formatted(created.uuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(204);

        final VulnPolicyDetailRow after = withJdbiHandle(
                handle -> handle.attach(VulnerabilityPolicyDao.class).getByUuid(created.uuid()));
        assertThat(after).isNull();
    }

    @Test
    void shouldReturn404WhenDeletingNonExistentPolicy() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT, Permissions.POLICY_MANAGEMENT_DELETE);

        final Response response = jersey
                .target("/vuln-policies/00000000-0000-0000-0000-000000000001")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void shouldReturn403WhenDeletingBundleManagedPolicy() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT, Permissions.POLICY_MANAGEMENT_DELETE);

        final VulnPolicyIdentityRow created = inJdbiTransaction(handle -> {
            final var dao = handle.attach(VulnerabilityPolicyDao.class);
            final VulnPolicyBundleRow bundle = dao.createBundle(
                    UUID.fromString("00000000-0000-0000-0000-000000000002"),
                    URI.create("https://example.com/bundle.zip"));
            final var policy = createVulnPolicyInstance(0);
            return dao.createAll(bundle.id(), List.of(policy)).getFirst();
        });

        final Response response = jersey
                .target("/vuln-policies/%s".formatted(created.uuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void shouldListVulnPolicyBundles() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_READ);

        final var bundleUuid = UUID.fromString("00000000-0000-0000-0000-000000000003");
        useJdbiTransaction(handle -> {
            final var dao = handle.attach(VulnerabilityPolicyDao.class);
            dao.createBundle(bundleUuid, URI.create("https://example.com/bundle.zip"));
        });

        final Response response = jersey
                .target("/vuln-policy-bundles")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "items": [
                    {
                      "uuid": "00000000-0000-0000-0000-000000000003",
                      "url": "https://example.com/bundle.zip",
                      "created": "${json-unit.any-number}"
                    }
                  ],
                  "total": {
                    "count": 1,
                    "type": "EXACT"
                  }
                }
                """);
    }

    @Test
    void shouldListVulnPolicyBundlesEmpty() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_READ);

        final Response response = jersey
                .target("/vuln-policy-bundles")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .node("items").isArray().isEmpty();
    }

    @Test
    void shouldDeleteVulnPolicyBundle() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT, Permissions.POLICY_MANAGEMENT_DELETE);

        final var bundleUuid = UUID.fromString("00000000-0000-0000-0000-000000000004");
        useJdbiTransaction(handle -> {
            final var dao = handle.attach(VulnerabilityPolicyDao.class);
            final VulnPolicyBundleRow bundle = dao.createBundle(bundleUuid, URI.create("https://example.com/bundle.zip"));
            final var policy = createVulnPolicyInstance(0);
            dao.createAll(bundle.id(), List.of(policy));
        });

        final Response response = jersey.target("/vuln-policy-bundles/%s".formatted(bundleUuid))
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(204);
    }

    @Test
    void shouldReturn404WhenDeletingNonExistentBundle() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT, Permissions.POLICY_MANAGEMENT_DELETE);

        final Response response = jersey
                .target("/vuln-policy-bundles/00000000-0000-0000-0000-000000000005")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void shouldReturn401WhenNotAuthenticated() {
        final Response response = jersey
                .target("/vuln-policies")
                .request()
                .get();

        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void shouldReturn403WhenMissingPermission() {
        initializeWithPermissions();

        final Response response = jersey
                .target("/vuln-policies")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void shouldTriggerBundleSync() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final var runId = UUID.fromString("00000000-0000-0000-0000-000000000006");
        when(DEX_ENGINE_MOCK.createRun(ArgumentMatchers.<CreateWorkflowRunRequest<?>>any()))
                .thenReturn(runId)
                .thenReturn(null)
                .thenReturn(runId);

        Response response = jersey
                .target("/vuln-policy-bundles/bc106cf4-3993-4e38-952d-d2f5f11412ed/sync-runs")
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);
        assertThat(response.getStatus()).isEqualTo(202);
        assertThat(getPlainTextBody(response)).isEmpty();

        response = jersey
                .target("/vuln-policy-bundles/bc106cf4-3993-4e38-952d-d2f5f11412ed/sync-runs")
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);
        assertThat(response.getStatus()).isEqualTo(409);

        response = jersey
                .target("/vuln-policy-bundles/bc106cf4-3993-4e38-952d-d2f5f11412ed/sync-runs")
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);
        assertThat(response.getStatus()).isEqualTo(202);
    }

    @Test
    void shouldRejectBundleSyncWhenAlreadyInProgress() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        when(DEX_ENGINE_MOCK.createRun(ArgumentMatchers.<CreateWorkflowRunRequest<?>>any()))
                .thenReturn(UUID.fromString("00000000-0000-0000-0000-000000000007"))
                .thenReturn(null);

        final Response firstResponse = jersey
                .target("/vuln-policy-bundles/bc106cf4-3993-4e38-952d-d2f5f11412ed/sync-runs")
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);
        assertThat(firstResponse.getStatus()).isEqualTo(202);

        final Response secondResponse = jersey
                .target("/vuln-policy-bundles/bc106cf4-3993-4e38-952d-d2f5f11412ed/sync-runs")
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);
        assertThat(secondResponse.getStatus()).isEqualTo(409);
    }

    @Test
    void shouldReturnCelErrorsWhenCreateConditionIsInvalid() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_CREATE);

        final Response response = jersey
                .target("/vuln-policies")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "name": "test-policy",
                          "condition": "doesNotExist == true",
                          "analysis": {
                            "state": "NOT_AFFECTED",
                            "suppress": true
                          }
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 400,
                  "title": "Bad Request",
                  "detail": "Condition is invalid.",
                  "errors": [
                    {
                      "line": 1,
                      "column": 0,
                      "message": "${json-unit.any-string}"
                    }
                  ]
                }
                """);
    }

    @Test
    void shouldReturnCelErrorsWhenUpdateConditionIsInvalid() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT, Permissions.POLICY_MANAGEMENT_UPDATE);

        final var vulnPolicy = createVulnPolicyInstance(0);
        final VulnPolicyIdentityRow created = inJdbiTransaction(
                handle -> handle.attach(VulnerabilityPolicyDao.class).create(vulnPolicy));

        final Response response = jersey
                .target("/vuln-policies/%s".formatted(created.uuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "name 0",
                          "condition": "doesNotExist == true",
                          "analysis": {
                            "state": "NOT_AFFECTED",
                            "suppress": true
                          }
                        }
                        """));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 400,
                  "title": "Bad Request",
                  "detail": "Condition is invalid.",
                  "errors": [
                    {
                      "line": 1,
                      "column": 0,
                      "message": "${json-unit.any-string}"
                    }
                  ]
                }
                """);
    }

    @Test
    void shouldReturnSyncStatusWithErrorWhenRunFailed() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_READ);

        final var runId = UUID.fromString("00000000-0000-0000-0000-000000000010");
        final var startedAt = Instant.parse("2026-04-15T10:00:00Z");
        final var completedAt = Instant.parse("2026-04-15T10:01:00Z");

        final var runMetadata = new WorkflowRunMetadata(
                runId, null, "SyncVulnPolicyBundleWorkflow", 1,
                "sync-vuln-policy-bundle:bc106cf4-3993-4e38-952d-d2f5f11412ed",
                "default", WorkflowRunStatus.FAILED, null, 0, null, null,
                startedAt, completedAt, startedAt, completedAt);

        when(DEX_ENGINE_MOCK.listRuns(any(ListWorkflowRunsRequest.class)))
                .thenReturn(new Page<>(List.of(runMetadata), null, null));

        final var failure = Failure.newBuilder()
                .setMessage("activity failed")
                .setActivityFailureDetails(ActivityFailureDetails.newBuilder()
                        .setActivityName("SyncVulnPolicyBundleActivity")
                        .build())
                .setCause(Failure.newBuilder()
                        .setMessage("connection refused")
                        .build())
                .build();

        final var run = new WorkflowRun(
                runId, null, "SyncVulnPolicyBundleWorkflow", 1,
                "sync-vuln-policy-bundle:bc106cf4-3993-4e38-952d-d2f5f11412ed",
                WorkflowRunStatus.FAILED, null, 0, null, null,
                startedAt, completedAt, startedAt, completedAt,
                null, null, failure, List.of());

        when(DEX_ENGINE_MOCK.getRunById(runId)).thenReturn(run);

        final Response response = jersey
                .target("/vuln-policy-bundles/bc106cf4-3993-4e38-952d-d2f5f11412ed/sync-runs/latest")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": "FAILED",
                  "started_at": %d,
                  "completed_at": %d,
                  "failure_reason": "connection refused"
                }
                """.formatted(startedAt.toEpochMilli(), completedAt.toEpochMilli()));
    }

    private static VulnerabilityPolicy createVulnPolicyInstance(int i) {
        final var vulnPolicy = new VulnerabilityPolicy();
        vulnPolicy.setCondition("vuln.id == \"CVE-123\" || vuln.aliases.exists(alias, alias.id == \"CVE-123\")");
        vulnPolicy.setName("name " + i);
        final var analysis = new VulnerabilityPolicyAnalysis();
        analysis.setState(VulnerabilityPolicyAnalysis.State.NOT_AFFECTED);
        analysis.setJustification(VulnerabilityPolicyAnalysis.Justification.CODE_NOT_REACHABLE);
        analysis.setDetails("something");
        analysis.setSuppress(true);
        vulnPolicy.setAnalysis(analysis);
        final var rating = new VulnerabilityPolicyRating();
        rating.setSeverity(VulnerabilityPolicyRating.Severity.HIGH);
        rating.setMethod(VulnerabilityPolicyRating.Method.CVSSV3);
        rating.setScore(6.3);
        rating.setVector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
        vulnPolicy.setRatings(List.of(rating));
        vulnPolicy.setOperationMode(VulnerabilityPolicyOperation.APPLY);
        return vulnPolicy;
    }

}
