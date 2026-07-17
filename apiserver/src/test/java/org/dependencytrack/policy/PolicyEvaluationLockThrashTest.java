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
package org.dependencytrack.policy;

import io.github.resilience4j.core.IntervalFunction;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.testing.WorkflowTestExtension;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.dependencytrack.proto.internal.workflow.v1.EvalProjectPoliciesArg;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

/**
 * Multi-worker thrash coverage for the production {@link EvalProjectPoliciesActivity} path.
 * <p>
 * Dex lock timeout is shortened at registration time. Per-component cost and whether the
 * heartbeat {@link Runnable} from the activity is honored are controlled via a
 * {@link CelPolicyEngine} test double — the real activity always passes
 * {@code ctx::maybeHeartbeat} and has no switch to disable heartbeats.
 */
class PolicyEvaluationLockThrashTest extends PersistenceCapableTest {

    /** Short enough that per-component work without heartbeats outlives the claim. */
    private static final Duration ACTIVITY_LOCK_TIMEOUT = Duration.ofSeconds(2);
    /** Per-component simulated cost; 4 components ≈ 3.2s &gt; lock timeout. */
    private static final Duration WORK_PER_COMPONENT = Duration.ofMillis(800);

    @RegisterExtension
    private final WorkflowTestExtension workflowTest =
            new WorkflowTestExtension(DataSourceRegistry.getInstance().getDefault());

    @Test
    void withoutDexHeartbeatSecondWorkerReclaimsPolicyEvaluation() throws Exception {
        final var invocations = new AtomicInteger();
        final var successorStarted = new CountDownLatch(1);
        final Project project = createProjectWithComponentsAndPolicy(4);

        startEngine(new EvalProjectPoliciesActivity(
                policyEngineIgnoringHeartbeatUntilSuccessor(invocations, successorStarted)));

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(EvalProjectPoliciesWorkflow.class)
                        .withArgument(EvalProjectPoliciesArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));

        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED, Duration.ofSeconds(60));

        assertThat(invocations.get()).isGreaterThanOrEqualTo(2);
        assertThat(successorStarted.await(0, TimeUnit.SECONDS)).isTrue();
        assertThat(qm.getAllPolicyViolations(project)).hasSize(4);
    }

    @Test
    void withDexHeartbeatPolicyEvaluationStaysOnSingleWorker() {
        final var invocations = new AtomicInteger();
        final Project project = createProjectWithComponentsAndPolicy(4);

        startEngine(new EvalProjectPoliciesActivity(
                policyEngineHonoringHeartbeat(invocations)));

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(EvalProjectPoliciesWorkflow.class)
                        .withArgument(EvalProjectPoliciesArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));

        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED, Duration.ofSeconds(60));

        assertThat(invocations.get()).isEqualTo(1);
        assertThat(qm.getAllPolicyViolations(project)).hasSize(4);
    }

    private void startEngine(EvalProjectPoliciesActivity activity) {
        final DexEngine engine = workflowTest.getEngine();

        engine.registerWorkflow(
                new EvalProjectPoliciesWorkflow(),
                protoConverter(EvalProjectPoliciesArg.class),
                voidConverter(),
                Duration.ofSeconds(10));
        // Production registers the same activity class; only the lock timeout is shortened here.
        engine.registerActivity(
                activity,
                protoConverter(EvalProjectPoliciesArg.class),
                voidConverter(),
                ACTIVITY_LOCK_TIMEOUT);

        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "policy-evaluations", 2));

        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "policy-eval-workers", "policy-evaluations", 2)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.start();
    }

    /**
     * Simulates the pre-fix failure mode: real policy evaluation runs, but the heartbeat
     * {@link Runnable} supplied by {@link EvalProjectPoliciesActivity} is never invoked, so the
     * Dex lock expires. The first call is slow; later calls finish quickly so the run can complete.
     */
    private static CelPolicyEngine policyEngineIgnoringHeartbeatUntilSuccessor(
            AtomicInteger invocations,
            CountDownLatch successorStarted) {
        final var realEngine = new CelPolicyEngine();
        final var policyEngine = mock(CelPolicyEngine.class);
        doAnswer(invocation -> {
            final UUID projectUuid = invocation.getArgument(0);
            final int n = invocations.incrementAndGet();
            if (n == 1) {
                realEngine.evaluateProject(projectUuid, () -> spendTime(/* heartbeat */ null));
                assertThat(successorStarted.await(30, TimeUnit.SECONDS)).isTrue();
                return null;
            }
            successorStarted.countDown();
            realEngine.evaluateProject(projectUuid, () -> {});
            return null;
        }).when(policyEngine).evaluateProject(any(), any());
        return policyEngine;
    }

    /**
     * Honors the heartbeat {@link Runnable} from {@link EvalProjectPoliciesActivity}
     * ({@code ctx::maybeHeartbeat}) while spending enough wall time per component to outlive
     * the lock if renewals were skipped.
     */
    private static CelPolicyEngine policyEngineHonoringHeartbeat(AtomicInteger invocations) {
        final var realEngine = new CelPolicyEngine();
        final var policyEngine = mock(CelPolicyEngine.class);
        doAnswer(invocation -> {
            invocations.incrementAndGet();
            final UUID projectUuid = invocation.getArgument(0);
            final Runnable heartbeat = invocation.getArgument(1);

            // maybeHeartbeat is debounced until ≤1/3 of the lock remains. We cannot read
            // the boolean from the activity's Runnable, so call it until past the
            // debounce window so CelPolicyEngine setup starts on a freshly renewed claim.
            final Instant pastDebounce = Instant.now()
                    .plus(ACTIVITY_LOCK_TIMEOUT.multipliedBy(2).dividedBy(3))
                    .plusMillis(200);
            while (Instant.now().isBefore(pastDebounce)) {
                heartbeat.run();
                Thread.sleep(100);
            }

            realEngine.evaluateProject(projectUuid, () -> spendTime(heartbeat));
            return null;
        }).when(policyEngine).evaluateProject(any(), any());
        return policyEngine;
    }

    private static void spendTime(@Nullable Runnable heartbeat) {
        final Instant end = Instant.now().plus(WORK_PER_COMPONENT);
        while (Instant.now().isBefore(end)) {
            if (heartbeat != null) {
                heartbeat.run();
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }
    }

    private Project createProjectWithComponentsAndPolicy(int componentCount) {
        final var policy = qm.createPolicy("thrash-policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(
                policy,
                PolicyCondition.Subject.EXPRESSION,
                PolicyCondition.Operator.MATCHES,
                """
                        component.name.startsWith("acme-lib")
                        """,
                PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("thrash-app");
        qm.persist(project);

        for (int i = 0; i < componentCount; i++) {
            final var component = new Component();
            component.setProject(project);
            component.setName("acme-lib-" + i);
            qm.persist(component);
        }

        return project;
    }

    /** Minimal workflow that only schedules the production policy activity. */
    @WorkflowSpec(name = "eval-project-policies-thrash")
    private static final class EvalProjectPoliciesWorkflow
            implements Workflow<EvalProjectPoliciesArg, Void> {

        @Override
        public @Nullable Void execute(
                WorkflowContext<EvalProjectPoliciesArg> ctx,
                @Nullable EvalProjectPoliciesArg argument){
            ctx.activity(EvalProjectPoliciesActivity.class).call(argument).await();
            return null;
        }
    }

}
