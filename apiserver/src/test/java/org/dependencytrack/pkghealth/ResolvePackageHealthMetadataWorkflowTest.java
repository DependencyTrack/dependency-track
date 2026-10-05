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
package org.dependencytrack.pkghealth;

import com.github.packageurl.PackageURL;
import io.github.resilience4j.core.IntervalFunction;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.testing.WorkflowTestExtension;
import org.dependencytrack.metrics.UpdateProjectMetricsActivity;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.jdbi.PackageHealthMetadataDao;
import org.dependencytrack.pkghealth.analyzer.PackageHealthAnalyzer;
import org.dependencytrack.pkghealth.client.ApiRateLimitException;
import org.dependencytrack.pkghealth.model.AnalyzedPackageHealth;
import org.dependencytrack.pkgmetadata.PackageArtifactMetadata;
import org.dependencytrack.pkgmetadata.PackageArtifactMetadataDao;
import org.dependencytrack.pkgmetadata.PackageMetadata;
import org.dependencytrack.pkgmetadata.PackageMetadataDao;
import org.dependencytrack.policy.EvalProjectPoliciesActivity;
import org.dependencytrack.policy.EvalProjectPoliciesWorkflow;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.dependencytrack.proto.internal.workflow.v1.EvalProjectPoliciesArg;
import org.dependencytrack.proto.internal.workflow.v1.FetchPackageHealthMetadataCandidatesArg;
import org.dependencytrack.proto.internal.workflow.v1.FetchPackageHealthMetadataCandidatesRes;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataActivityArg;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataActivityRes;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataWorkflowArg;
import org.dependencytrack.proto.internal.workflow.v1.ScheduleHealthPolicyEvaluationsArg;
import org.dependencytrack.proto.internal.workflow.v1.UpdateProjectMetricsArg;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.model.ConfigPropertyConstants.PACKAGE_HEALTH_RESOLUTION_ENABLED;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ResolvePackageHealthMetadataWorkflowTest extends PersistenceCapableTest {

    private static final Instant NOW = Instant.parse("2026-09-24T12:00:00Z");

    @RegisterExtension
    private final WorkflowTestExtension workflowTest =
            new WorkflowTestExtension(DataSourceRegistry.getInstance().getDefault());

    private PackageHealthAnalyzer analyzer;

    @BeforeEach
    void beforeEach() {
        analyzer = mock(PackageHealthAnalyzer.class);
        when(analyzer.supportedPurlTypes()).thenReturn(Set.of("npm"));

        final DexEngine engine = workflowTest.getEngine();

        engine.registerWorkflow(
                new ResolvePackageHealthMetadataWorkflow(),
                protoConverter(ResolvePackageHealthMetadataWorkflowArg.class),
                voidConverter(),
                Duration.ofSeconds(10));

        engine.registerActivity(
                new FetchPackageHealthMetadataCandidatesActivity(analyzer, 2),
                protoConverter(FetchPackageHealthMetadataCandidatesArg.class),
                protoConverter(FetchPackageHealthMetadataCandidatesRes.class));

        engine.registerActivity(
                new ResolvePackageHealthMetadataActivity(analyzer, Clock.fixed(NOW, ZoneOffset.UTC)),
                protoConverter(ResolvePackageHealthMetadataActivityArg.class),
                protoConverter(ResolvePackageHealthMetadataActivityRes.class));
        engine.registerActivity(
                new ScheduleHealthPolicyEvaluationsActivity(engine),
                protoConverter(ScheduleHealthPolicyEvaluationsArg.class),
                voidConverter());
        engine.registerWorkflow(
                new EvalProjectPoliciesWorkflow(),
                protoConverter(EvalProjectPoliciesArg.class),
                voidConverter(),
                Duration.ofSeconds(10));
        engine.registerActivity(
                new EvalProjectPoliciesActivity(new CelPolicyEngine()),
                protoConverter(EvalProjectPoliciesArg.class),
                voidConverter());
        engine.registerActivity(
                new UpdateProjectMetricsActivity(), protoConverter(UpdateProjectMetricsArg.class), voidConverter());

        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "package-health-metadata-resolutions", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "policy-evaluations", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "metrics-updates", 1));

        engine.registerTaskWorker(new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 1)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.registerTaskWorker(new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-default", "default", 1)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.registerTaskWorker(new TaskWorkerOptions(
                        TaskType.ACTIVITY, "activity-worker-package-health", "package-health-metadata-resolutions", 1)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-policy-evaluations", "policy-evaluations", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-metrics-updates", "metrics-updates", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.start();
    }

    @Test
    void shouldCompleteWhenNoCandidates() throws Exception {
        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ResolvePackageHealthMetadataWorkflow.class));

        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        verify(analyzer, never()).analyze(any());
    }

    @Test
    void shouldResolveAllCandidatesAcrossMultiplePages() throws Exception {
        final var firstPurl = new PackageURL("pkg:npm/a");
        final var secondPurl = new PackageURL("pkg:npm/b");
        final var thirdPurl = new PackageURL("pkg:npm/c");

        createPackageMetadata(firstPurl, secondPurl, thirdPurl);

        final var firstModel = new AnalyzedPackageHealth(firstPurl);
        firstModel.setStars(10L);

        final var secondModel = new AnalyzedPackageHealth(secondPurl);
        secondModel.setStars(20L);

        final var thirdModel = new AnalyzedPackageHealth(thirdPurl);
        thirdModel.setStars(30L);

        when(analyzer.analyze(firstPurl)).thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(firstModel));
        when(analyzer.analyze(secondPurl)).thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(secondModel));
        when(analyzer.analyze(thirdPurl)).thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(thirdModel));

        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ResolvePackageHealthMetadataWorkflow.class));

        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final var persisted = withJdbiHandle(handle -> {
            final var dao = new PackageHealthMetadataDao(handle);

            return List.of(dao.get(firstPurl), dao.get(secondPurl), dao.get(thirdPurl));
        });

        assertThat(persisted)
                .satisfiesExactly(
                        metadata -> {
                            assertThat(metadata).isNotNull();
                            assertThat(metadata.stars()).isEqualTo(10L);
                            assertThat(metadata.lastFetch()).isEqualTo(NOW);
                        },
                        metadata -> {
                            assertThat(metadata).isNotNull();
                            assertThat(metadata.stars()).isEqualTo(20L);
                            assertThat(metadata.lastFetch()).isEqualTo(NOW);
                        },
                        metadata -> {
                            assertThat(metadata).isNotNull();
                            assertThat(metadata.stars()).isEqualTo(30L);
                            assertThat(metadata.lastFetch()).isEqualTo(NOW);
                        });
    }

    @Test
    void shouldWaitForRateLimitResetWithoutUsingUpRetryAttempts() throws Exception {
        final var purl = new PackageURL("pkg:npm/a");
        createPackageMetadata(purl);

        final var model = new AnalyzedPackageHealth(purl);
        model.setStars(10L);
        // One more rate limit than the activity retry policy has attempts.
        final var rateLimited = new PackageHealthAnalyzer.AnalysisException(
                "GitHub request failed", new ApiRateLimitException(Instant.now()));
        when(analyzer.analyze(purl))
                .thenThrow(rateLimited, rateLimited, rateLimited)
                .thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(model));

        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ResolvePackageHealthMetadataWorkflow.class));

        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED, Duration.ofSeconds(90));

        verify(analyzer, times(4)).analyze(purl);
        final var persisted = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(purl));
        assertThat(persisted).isNotNull();
        assertThat(persisted.stars()).isEqualTo(10L);
    }

    @Test
    void shouldSkipPackagesThatStayRateLimited() throws Exception {
        final var purl = new PackageURL("pkg:npm/a");
        createPackageMetadata(purl);

        when(analyzer.analyze(purl))
                .thenThrow(new PackageHealthAnalyzer.AnalysisException(
                        "GitHub request failed", new ApiRateLimitException(Instant.now())));

        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ResolvePackageHealthMetadataWorkflow.class));

        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED, Duration.ofSeconds(90));

        // The first attempt plus one attempt after each of the three waits.
        verify(analyzer, times(4)).analyze(purl);
        final var persisted = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(purl));
        assertThat(persisted).isNull();
    }

    @Test
    void shouldFetchOnlyGitHubAgainAfterGitHubRateLimit() throws Exception {
        final var purl = new PackageURL("pkg:npm/a");
        final var repository = "github.com/acme/a";
        createPackageMetadata(purl);

        final var depsDevPart = new AnalyzedPackageHealth(purl);
        depsDevPart.setStars(10L);
        when(analyzer.analyze(purl))
                .thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(depsDevPart, repository));
        final var gitHubPart = new AnalyzedPackageHealth(purl);
        gitHubPart.setContributors(3L);
        when(analyzer.analyzeGitHubRepository(purl, repository))
                .thenThrow(new PackageHealthAnalyzer.AnalysisException(
                        "GitHub request failed", new ApiRateLimitException(Instant.now())))
                .thenReturn(Optional.of(gitHubPart));

        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ResolvePackageHealthMetadataWorkflow.class));

        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED, Duration.ofSeconds(90));

        verify(analyzer, times(1)).analyze(purl);
        verify(analyzer, times(2)).analyzeGitHubRepository(purl, repository);
        final var persisted = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(purl));
        assertThat(persisted).isNotNull();
        assertThat(persisted.stars()).isEqualTo(10L);
        assertThat(persisted.contributors()).isEqualTo(3L);
    }

    @Test
    void shouldStopWhenDisabled() throws Exception {
        createPackageMetadata(new PackageURL("pkg:npm/a"));
        qm.createConfigProperty(
                PACKAGE_HEALTH_RESOLUTION_ENABLED.getGroupName(),
                PACKAGE_HEALTH_RESOLUTION_ENABLED.getPropertyName(),
                "false",
                PACKAGE_HEALTH_RESOLUTION_ENABLED.getPropertyType(),
                PACKAGE_HEALTH_RESOLUTION_ENABLED.getDescription());

        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ResolvePackageHealthMetadataWorkflow.class));

        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        verify(analyzer, never()).analyze(any());
    }

    @Test
    void shouldEvaluatePoliciesWhenHealthFieldsChange() throws Exception {
        final var packagePurl = new PackageURL("pkg:npm/react");
        createPackageMetadata(packagePurl);

        final var policy = qm.createPolicy("health-policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(
                policy,
                PolicyCondition.Subject.EXPRESSION,
                PolicyCondition.Operator.MATCHES,
                "has(health.stars) && health.stars < 5",
                PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("react");
        component.setPurl("pkg:npm/react@18.3.1");
        component.setPurlCoordinates("pkg:npm/react@18.3.1");
        qm.persist(component);
        withJdbiHandle(handle -> new PackageArtifactMetadataDao(handle)
                .upsertAll(List.of(new PackageArtifactMetadata(
                        new PackageURL("pkg:npm/react@18.3.1"),
                        packagePurl,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        "test",
                        NOW))));

        final var model = new AnalyzedPackageHealth(packagePurl);
        model.setStars(10L);
        when(analyzer.analyze(packagePurl)).thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(model));

        final DexEngine engine = workflowTest.getEngine();
        final UUID firstRunId =
                engine.createRun(new CreateWorkflowRunRequest<>(ResolvePackageHealthMetadataWorkflow.class));
        workflowTest.awaitRunStatus(firstRunId, WorkflowRunStatus.COMPLETED);
        await().atMost(Duration.ofSeconds(30)).until(() -> policyEvaluationCount(engine), count -> count == 1);

        final UUID secondRunId =
                engine.createRun(new CreateWorkflowRunRequest<>(ResolvePackageHealthMetadataWorkflow.class));
        workflowTest.awaitRunStatus(secondRunId, WorkflowRunStatus.COMPLETED);

        assertThat(policyEvaluationCount(engine)).isEqualTo(1);
    }

    private static long policyEvaluationCount(final DexEngine engine) {
        return engine.countRuns(new org.dependencytrack.dex.engine.api.request.CountWorkflowRunsRequest(
                EvalProjectPoliciesWorkflow.class, null, null, 10));
    }

    private static void createPackageMetadata(final PackageURL... purls) {
        final var metadata = List.of(purls).stream()
                .map(purl -> new PackageMetadata(purl, "1.0.0", null, NOW, "test", "test"))
                .toList();

        withJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(metadata));
    }
}
