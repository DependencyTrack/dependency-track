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
package org.dependencytrack.notification;

import com.google.protobuf.util.Timestamps;
import com.sun.net.httpserver.HttpServer;
import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.dex.activity.DeleteFilesActivity;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.dex.testing.WorkflowTestExtension;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.memory.MemoryFileStorage;
import org.dependencytrack.kevdatasource.api.KevAssertion;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.NotificationTriggerType;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityKey;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.proto.v1.Group;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.PolicyViolationUpdatedSubject;
import org.dependencytrack.notification.publishing.DefaultNotificationPublishersPlugin;
import org.dependencytrack.notification.templating.pebble.PebbleNotificationTemplateRendererFactory;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.command.MakeViolationAnalysisCommand;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.persistence.jdbi.KevDao;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.dependencytrack.proto.internal.workflow.v1.DeleteFilesArgument;
import org.dependencytrack.proto.internal.workflow.v1.PublishNotificationActivityArg;
import org.dependencytrack.proto.internal.workflow.v1.PublishNotificationWorkflowArg;
import org.dependencytrack.support.net.OutboundConnectionPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.notification.NotificationTestUtil.getNotificationOutbox;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

/** Exercises the production CEL, PostgreSQL outbox, router, workflow and HTTP publisher together. */
class PolicyViolationUpdatedIntegrationTest extends PersistenceCapableTest {

    private static final String KEV_A = "CVE-2021-44228";
    private static final String KEV_B = "CVE-2021-45046";
    private static final String KEV_C = "CVE-2099-00001";
    private static final String EXPRESSION = """
            vulns.filter(v, v.is_kev).map(v, v.id).join(",")
            """;

    @RegisterExtension
    private final WorkflowTestExtension workflowTest =
            new WorkflowTestExtension(DataSourceRegistry.getInstance().getDefault());

    private final List<Notification> received = new CopyOnWriteArrayList<>();
    private final AtomicInteger failuresRemaining = new AtomicInteger();
    private final AtomicInteger receiverStatus = new AtomicInteger(204);
    private PluginManager pluginManager;
    private FileStorage fileStorage;
    private HttpServer receiver;
    private Project project;
    private Component component;
    private PolicyCondition condition;
    private NotificationRule rule;

    @BeforeEach
    void setUpPipeline() throws Exception {
        // Bind only to loopback. Every HTTP request in this test remains on this machine.
        receiver = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        receiver.createContext("/notifications", exchange -> {
            try (exchange) {
                final Notification notification = Notification.parseFrom(exchange.getRequestBody());
                received.add(notification);
                final int status = failuresRemaining.getAndUpdate(value -> Math.max(0, value - 1)) > 0
                        ? 503
                        : receiverStatus.get();
                exchange.sendResponseHeaders(status, -1);
            }
        });
        receiver.start();

        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder().build(),
                new NoopCacheManager(),
                secretName -> null,
                JdbiFactory.createJdbi(),
                HttpClient.newHttpClient(),
                OutboundConnectionPolicy.of(List.of("127.0.0.1")),
                List.of(NotificationPublisher.class));
        pluginManager.loadPlugins(List.of(new DefaultNotificationPublishersPlugin()));
        fileStorage = new MemoryFileStorage();

        final DexEngine engine = workflowTest.getEngine();
        engine.registerWorkflow(
                new PublishNotificationWorkflow(),
                protoConverter(PublishNotificationWorkflowArg.class),
                voidConverter(),
                Duration.ofSeconds(30));
        engine.registerActivity(
                new PublishNotificationActivity(
                        pluginManager,
                        fileStorage,
                        secretName -> null,
                        new PebbleNotificationTemplateRendererFactory(Collections.emptyMap())),
                protoConverter(PublishNotificationActivityArg.class),
                voidConverter());
        engine.registerActivity(
                new DeleteFilesActivity(fileStorage), protoConverter(DeleteFilesArgument.class), voidConverter());
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "notifications", 1));
        engine.registerTaskWorker(new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 1)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker", "notifications", 1)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.start();

        project = new Project();
        project.setName("isolated-kev-project");
        qm.persist(project);
        component = new Component();
        component.setProject(project);
        component.setName("log4j-core");
        component.setVersion("2.14.1");
        qm.persist(component);
        for (final String id : List.of(KEV_A, KEV_B, KEV_C)) {
            final var vulnerability = new Vulnerability();
            vulnerability.setSource(Vulnerability.Source.NVD);
            vulnerability.setVulnId(id);
            vulnerability.setSeverity(Severity.CRITICAL);
            qm.persist(vulnerability);
            qm.addVulnerability(vulnerability, component, "local-test");
        }
        final Policy policy = qm.createPolicy("KEV policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        condition = qm.createPolicyCondition(
                policy,
                PolicyCondition.Subject.EXPRESSION,
                PolicyCondition.Operator.MATCHES,
                EXPRESSION,
                PolicyViolation.Type.SECURITY);
        final var publisher = new org.dependencytrack.model.NotificationPublisher();
        publisher.setName("Loopback webhook");
        publisher.setExtensionName("webhook");
        qm.persist(publisher);
        rule = new NotificationRule();
        rule.setName("Local opt-in updates");
        rule.setEnabled(true);
        rule.setTriggerType(NotificationTriggerType.EVENT);
        rule.setScope(NotificationScope.PORTFOLIO);
        rule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        rule.setNotifyOn(Set.of(NotificationGroup.POLICY_VIOLATION, NotificationGroup.POLICY_VIOLATION_UPDATED));
        rule.setPublisher(publisher);
        rule.setPublisherConfig("""
                {"destinationUrl":"http://127.0.0.1:%d/notifications","publishProtobuf":true}
                """.formatted(receiver.getAddress().getPort()));
        qm.persist(rule);
    }

    @AfterEach
    void tearDownPipeline() throws Exception {
        // Stop workers before closing their dependencies.
        try {
            workflowTest.getEngine().close();
        } finally {
            try {
                if (pluginManager != null) {
                    pluginManager.close();
                }
            } finally {
                if (receiver != null) {
                    receiver.stop(0);
                }
            }
        }
    }

    @Test
    void shouldDeliverCreationAndExactlyOneUpdateForSecondKev() throws Exception {
        setKevs(KEV_A);
        evaluateAndDeliver(1);
        final PolicyViolation initial = violation();
        final UUID violationUuid = initial.getUuid();
        assertThat(received).extracting(Notification::getGroup).containsExactly(Group.GROUP_POLICY_VIOLATION);

        evaluateAndDeliver(0);
        assertThat(received).hasSize(1);
        assertThat(violation().getUuid()).isEqualTo(violationUuid);

        setKevs(KEV_A, KEV_B);
        final var beforeChange = java.time.Instant.now();
        evaluateAndDeliver(1);
        assertThat(received).hasSize(2);
        final Notification update = received.getLast();
        assertThat(update.getGroup()).isEqualTo(Group.GROUP_POLICY_VIOLATION_UPDATED);
        final PolicyViolationUpdatedSubject subject = update.getSubject().unpack(PolicyViolationUpdatedSubject.class);
        assertThat(subject.getPreviousMessage()).isEqualTo(KEV_A);
        assertThat(subject.getCurrentMessage()).isEqualTo(KEV_A + "," + KEV_B);
        assertThat(subject.getPolicyViolation().getUuid()).isEqualTo(violationUuid.toString());
        assertThat(subject.getPolicyViolation().getMessage()).isEqualTo(subject.getCurrentMessage());
        assertThat(subject.getProject().getUuid()).isEqualTo(project.getUuid().toString());
        assertThat(subject.getComponent().getUuid())
                .isEqualTo(component.getUuid().toString());
        assertThat(Timestamps.toMillis(subject.getChangedAt())).isGreaterThanOrEqualTo(beforeChange.toEpochMilli());
        assertThat(violation().getUuid()).isEqualTo(violationUuid);
        assertThat(violation().getText()).isEqualTo(subject.getCurrentMessage());

        evaluateAndDeliver(0);
        assertThat(received).hasSize(2);
        // An analysis write which leaves the active KEV set unchanged must not create a new event.
        qm.makeAnalysis(new MakeAnalysisCommand(component, qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, KEV_B))
                .withSuppress(false)
                .withOptions(Set.of(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        evaluateAndDeliver(0);
        assertThat(received).hasSize(2);
    }

    @Test
    void shouldPublishNullSafeMessageTransitionsFromBooleanAndStringConditions() throws Exception {
        setKevs(KEV_A);
        condition.setValue("true");
        qm.persist(condition);
        evaluateAndDeliver(1);
        final UUID originalUuid = violation().getUuid();
        assertThat(violation().getText()).isNull();
        assertThat(received.getFirst()
                        .getSubject()
                        .unpack(org.dependencytrack.notification.proto.v1.PolicyViolationSubject.class)
                        .getPolicyViolation()
                        .hasMessage())
                .isFalse();
        evaluateAndDeliver(0);

        condition.setValue(EXPRESSION);
        qm.persist(condition);
        evaluateAndDeliver(1);
        final var populated = received.getLast().getSubject().unpack(PolicyViolationUpdatedSubject.class);
        assertThat(received.getLast().getGroup()).isEqualTo(Group.GROUP_POLICY_VIOLATION_UPDATED);
        assertThat(populated.getPolicyViolation().getUuid()).isEqualTo(originalUuid.toString());
        assertThat(populated.hasPreviousMessage()).isFalse();
        assertThat(populated.hasCurrentMessage()).isTrue();
        assertThat(populated.getCurrentMessage()).isEqualTo(KEV_A);
        assertThat(populated.getPolicyViolation().hasMessage()).isTrue();
        assertThat(populated.getPolicyViolation().getMessage()).isEqualTo(populated.getCurrentMessage());
        assertThat(violation().getText()).isEqualTo(KEV_A);
        evaluateAndDeliver(0);

        condition.setValue("true");
        qm.persist(condition);
        evaluateAndDeliver(1);
        final var cleared = received.getLast().getSubject().unpack(PolicyViolationUpdatedSubject.class);
        assertThat(received.getLast().getGroup()).isEqualTo(Group.GROUP_POLICY_VIOLATION_UPDATED);
        assertThat(cleared.getPolicyViolation().getUuid()).isEqualTo(originalUuid.toString());
        assertThat(cleared.hasPreviousMessage()).isTrue();
        assertThat(cleared.getPreviousMessage()).isEqualTo(KEV_A);
        assertThat(cleared.hasCurrentMessage()).isFalse();
        assertThat(cleared.getPolicyViolation().hasMessage()).isFalse();
        assertThat(violation().getUuid()).isEqualTo(originalUuid);
        assertThat(violation().getText()).isNull();
        evaluateAndDeliver(0);
        assertThat(received).hasSize(3);
    }

    @Test
    void shouldDetectRemovalAndEqualSizeMatchReplacementAndRecreation() throws Exception {
        setKevs(KEV_A, KEV_B);
        evaluateAndDeliver(1);
        final UUID originalUuid = violation().getUuid();
        setKevs(KEV_B);
        evaluateAndDeliver(1);
        assertUpdate(received.getLast(), KEV_A + "," + KEV_B, KEV_B, originalUuid);
        setKevs(KEV_C);
        evaluateAndDeliver(1);
        assertUpdate(received.getLast(), KEV_B, KEV_C, originalUuid);
        setKevs();
        evaluateAndDeliver(0);
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
        setKevs(KEV_A);
        evaluateAndDeliver(1);
        assertThat(received.getLast().getGroup()).isEqualTo(Group.GROUP_POLICY_VIOLATION);
        assertThat(violation().getUuid()).isNotEqualTo(originalUuid);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void shouldRespectExistingApprovedAndSuppressedDecisions(boolean suppressed) throws Exception {
        setKevs(KEV_A);
        evaluateAndDeliver(1);
        final PolicyViolation initial = violation();
        final var state = suppressed ? ViolationAnalysisState.REJECTED : ViolationAnalysisState.APPROVED;
        qm.makeViolationAnalysis(new MakeViolationAnalysisCommand(component, initial)
                .withState(state)
                .withSuppress(suppressed)
                .withOptions(Set.of(MakeViolationAnalysisCommand.Option.OMIT_NOTIFICATION)));
        setKevs(KEV_A, KEV_B);
        evaluateAndDeliver(0);
        assertThat(received).hasSize(1);
        final PolicyViolation updated = violation();
        assertThat(updated.getUuid()).isEqualTo(initial.getUuid());
        assertThat(updated.getText()).isEqualTo(KEV_A + "," + KEV_B);
        final var analysis = qm.getViolationAnalysis(component, updated);
        assertThat(analysis.getAnalysisState()).isEqualTo(state);
        assertThat(analysis.isSuppressed()).isEqualTo(suppressed);

        // Clearing a decision is not a message transition; do not replay previously filtered updates.
        qm.makeViolationAnalysis(new MakeViolationAnalysisCommand(component, updated)
                .withState(ViolationAnalysisState.NOT_SET)
                .withSuppress(false)
                .withOptions(Set.of(MakeViolationAnalysisCommand.Option.OMIT_NOTIFICATION)));
        evaluateAndDeliver(0);
        assertThat(received).hasSize(1);
        setKevs(KEV_C);
        evaluateAndDeliver(1);
        assertUpdate(received.getLast(), KEV_A + "," + KEV_B, KEV_C, initial.getUuid());
        assertThat(received).hasSize(2);
    }

    private static Stream<Arguments> reviewedDecisions() {
        return Stream.of(
                Arguments.of(ViolationAnalysisState.APPROVED, false),
                Arguments.of(ViolationAnalysisState.REJECTED, true),
                Arguments.of(ViolationAnalysisState.APPROVED, true));
    }

    @ParameterizedTest
    @MethodSource("reviewedDecisions")
    void shouldDeliverReviewedChangesOnlyToExplicitSubscribersWithoutResettingDecisions(
            ViolationAnalysisState state, boolean suppressed) throws Exception {
        rule.setNotifyOn(Set.of(
                NotificationGroup.POLICY_VIOLATION,
                NotificationGroup.POLICY_VIOLATION_UPDATED,
                NotificationGroup.POLICY_VIOLATION_UPDATED_REVIEWED));
        qm.persist(rule);
        final List<Notification> ordinaryUpdates = addOrdinaryUpdateReceiver();
        setKevs(KEV_A);
        evaluateAndDeliver(1);
        final UUID originalUuid = violation().getUuid();
        review(state, suppressed);
        evaluateAndDeliver(0); // A review decision alone is not a message transition.
        setKevs(KEV_A, KEV_B);
        evaluateAndDeliver(1);
        assertThat(received).hasSize(2);
        assertThat(ordinaryUpdates).isEmpty();
        assertReviewedUpdate(received.getLast(), KEV_A, KEV_A + "," + KEV_B, originalUuid, state, suppressed);
        final var analysis = qm.getViolationAnalysis(component, violation());
        assertThat(analysis.getAnalysisState()).isEqualTo(state);
        assertThat(analysis.isSuppressed()).isEqualTo(suppressed);
        evaluateAndDeliver(0);
        assertThat(received).hasSize(2);

        review(ViolationAnalysisState.NOT_SET, false);
        evaluateAndDeliver(0); // Do not replay a reviewed transition after clearing the decision.
        assertThat(received).hasSize(2);
        setKevs(KEV_A, KEV_B, KEV_C);
        evaluateAndDeliver(1);
        assertThat(received).hasSize(3);
        assertUpdate(received.getLast(), KEV_A + "," + KEV_B, KEV_A + "," + KEV_B + "," + KEV_C, originalUuid);
        assertThat(ordinaryUpdates).containsExactly(received.getLast());
        assertThat(received).extracting(Notification::getId).doesNotHaveDuplicates();
    }

    @Test
    void rejectedUnsuppressedDecisionShouldStillUseTheOrdinaryUpdateGroup() throws Exception {
        rule.setNotifyOn(Set.of(
                NotificationGroup.POLICY_VIOLATION,
                NotificationGroup.POLICY_VIOLATION_UPDATED,
                NotificationGroup.POLICY_VIOLATION_UPDATED_REVIEWED));
        qm.persist(rule);
        setKevs(KEV_A);
        evaluateAndDeliver(1);
        final UUID originalUuid = violation().getUuid();
        review(ViolationAnalysisState.REJECTED, false);
        evaluateAndDeliver(0);
        setKevs(KEV_A, KEV_B);
        evaluateAndDeliver(1);
        assertThat(received).hasSize(2);
        assertUpdate(received.getLast(), KEV_A, KEV_A + "," + KEV_B, originalUuid);
        final var subject = received.getLast().getSubject().unpack(PolicyViolationUpdatedSubject.class);
        // Ordinary subscribers retain the previous payload shape; review metadata is opt-in.
        assertThat(subject.hasAnalysisState()).isFalse();
        assertThat(subject.hasSuppressed()).isFalse();
        final var analysis = qm.getViolationAnalysis(component, violation());
        assertThat(analysis.getAnalysisState()).isEqualTo(ViolationAnalysisState.REJECTED);
        assertThat(analysis.isSuppressed()).isFalse();
        evaluateAndDeliver(0);
        assertThat(received).hasSize(2);
    }

    @Test
    void reviewedOnlySubscriberShouldNotReceiveActiveChangesOrHistoricalTransitions() throws Exception {
        rule.setNotifyOn(Set.of(NotificationGroup.POLICY_VIOLATION_UPDATED_REVIEWED));
        qm.persist(rule);
        setKevs(KEV_A);
        evaluateAndDeliver(0); // No creation subscriber is configured.
        final UUID originalUuid = violation().getUuid();
        setKevs(KEV_A, KEV_B);
        evaluateAndDeliver(0); // Active updates remain in the ordinary group.
        review(ViolationAnalysisState.APPROVED, false);
        evaluateAndDeliver(0); // A decision change does not replay the previous active change.
        rule.setNotifyOn(Set.of(NotificationGroup.POLICY_VIOLATION_UPDATED));
        qm.persist(rule);
        setKevs(KEV_B);
        evaluateAndDeliver(0); // Without the reviewed opt-in, this reviewed transition is consumed quietly.
        rule.setNotifyOn(Set.of(NotificationGroup.POLICY_VIOLATION_UPDATED_REVIEWED));
        qm.persist(rule);
        evaluateAndDeliver(0); // Enabling the opt-in does not replay that historical reviewed change.
        setKevs(KEV_A, KEV_B, KEV_C);
        evaluateAndDeliver(1);
        assertThat(received).hasSize(1);
        assertReviewedUpdate(
                received.getFirst(),
                KEV_B,
                KEV_A + "," + KEV_B + "," + KEV_C,
                originalUuid,
                ViolationAnalysisState.APPROVED,
                false);
        evaluateAndDeliver(0);
        assertThat(received).hasSize(1);
    }

    @Test
    void shouldRetryReviewedChangeWithTheSameEventAndCapturedDecision() throws Exception {
        rule.setNotifyOn(
                Set.of(NotificationGroup.POLICY_VIOLATION, NotificationGroup.POLICY_VIOLATION_UPDATED_REVIEWED));
        qm.persist(rule);
        setKevs(KEV_A);
        evaluateAndDeliver(1);
        final UUID originalUuid = violation().getUuid();
        review(ViolationAnalysisState.APPROVED, true);
        failuresRemaining.set(1);
        setKevs(KEV_A, KEV_B);
        evaluateAndDeliver(1);
        assertThat(received).hasSize(3);
        assertThat(received.get(1)).isEqualTo(received.get(2));
        assertReviewedUpdate(
                received.getLast(), KEV_A, KEV_A + "," + KEV_B, originalUuid, ViolationAnalysisState.APPROVED, true);
        evaluateAndDeliver(0);
        assertThat(received).hasSize(3);
    }

    @Test
    void shouldNotPublishUpdatesToCreationOnlySubscriber() throws Exception {
        rule.setNotifyOn(Set.of(NotificationGroup.POLICY_VIOLATION));
        qm.persist(rule);
        setKevs(KEV_A);
        evaluateAndDeliver(1);
        setKevs(KEV_A, KEV_B);
        evaluateAndDeliver(0);
        assertThat(received).hasSize(1);
        assertThat(violation().getText()).isEqualTo(KEV_A + "," + KEV_B);
    }

    @Test
    void shouldApplyProjectAndExpressionFiltersToUpdateSubject() throws Exception {
        setKevs(KEV_A);
        evaluateAndDeliver(1);
        final var unrelatedProject = new Project();
        unrelatedProject.setName("unrelated-project");
        qm.persist(unrelatedProject);
        rule.setProjects(List.of(unrelatedProject));
        qm.persist(rule);
        setKevs(KEV_A, KEV_B);
        evaluateAndDeliver(1, false);
        assertThat(received).hasSize(1);

        rule.setProjects(List.of(project));
        rule.setFilterExpression("subject.current_message == '" + KEV_C + "'");
        qm.persist(rule);
        setKevs(KEV_C);
        evaluateAndDeliver(1);
        assertThat(received).hasSize(2);
        assertThat(received.getLast().getGroup()).isEqualTo(Group.GROUP_POLICY_VIOLATION_UPDATED);
    }

    @Test
    void shouldRetryTransientWebhookFailureWithSameEventIdentity() throws Exception {
        setKevs(KEV_A);
        evaluateAndDeliver(1);
        failuresRemaining.set(1);
        setKevs(KEV_A, KEV_B);
        evaluateAndDeliver(1);
        assertThat(received).hasSize(3);
        assertThat(received.get(1).getGroup()).isEqualTo(Group.GROUP_POLICY_VIOLATION_UPDATED);
        assertThat(received.get(1)).isEqualTo(received.get(2));
        // Retries redeliver the same durable event, rather than inventing another policy transition.
        evaluateAndDeliver(0);
        assertThat(received).hasSize(3);
    }

    @Test
    void shouldPersistPermanentWebhookFailureWithoutRegeneratingTheEvent() throws Exception {
        setKevs(KEV_A);
        evaluateAndDeliver(1);
        receiverStatus.set(400);
        setKevs(KEV_A, KEV_B);
        final List<Notification> events = evaluateAndDeliver(1, true, WorkflowRunStatus.FAILED);
        assertThat(received).hasSize(2);
        assertThat(received.getLast()).isEqualTo(events.getFirst());
        final var metadata = workflowTest
                .getEngine()
                .listRuns(new ListWorkflowRunsRequest()
                        .withWorkflowInstanceId(
                                "publish-notification:" + events.getFirst().getId()))
                .items()
                .getFirst();
        final var run = workflowTest.getEngine().getRunById(metadata.id());
        assertThat(run).isNotNull();
        assertThat(run.status()).isEqualTo(WorkflowRunStatus.FAILED);
        assertThat(run.failure()).isNotNull();
        assertThat(run.failure().getMessage()).isEqualTo("Publishing failed for all applicable rules");
        assertThat(run.eventHistory()).anySatisfy(event -> {
            assertThat(event.hasActivityTaskFailed()).isTrue();
            assertThat(event.getActivityTaskFailed().getFailure().getCause().getMessage())
                    .contains("unexpected response code: 400");
        });
        assertThat(getNotificationOutbox()).isEmpty();
        evaluateAndDeliver(0);
        assertThat(received).hasSize(2);
    }

    @Test
    void shouldDeliverIndependentUpdatesForMultipleComponentsAndConditions() throws Exception {
        final var secondComponent = new Component();
        secondComponent.setProject(project);
        secondComponent.setName("second-library");
        qm.persist(secondComponent);
        for (final String id : List.of(KEV_A, KEV_B, KEV_C)) {
            qm.addVulnerability(
                    qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, id), secondComponent, "local-test");
        }
        final Policy secondPolicy =
                qm.createPolicy("Second KEV policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(
                secondPolicy,
                PolicyCondition.Subject.EXPRESSION,
                PolicyCondition.Operator.MATCHES,
                EXPRESSION,
                PolicyViolation.Type.SECURITY);
        // There are two policy conditions for each of the two components.
        setKevs(KEV_A);
        evaluateAndDeliver(4);
        final Set<String> originalViolationUuids = received.stream()
                .map(notification -> {
                    try {
                        return notification
                                .getSubject()
                                .unpack(org.dependencytrack.notification.proto.v1.PolicyViolationSubject.class)
                                .getPolicyViolation()
                                .getUuid();
                    } catch (com.google.protobuf.InvalidProtocolBufferException e) {
                        throw new IllegalStateException(e);
                    }
                })
                .collect(java.util.stream.Collectors.toSet());
        assertThat(originalViolationUuids).hasSize(4);
        setKevs(KEV_A, KEV_B);
        evaluateAndDeliver(4);
        assertThat(received).hasSize(8);
        for (final Notification update : received.subList(4, 8)) {
            final var subject = update.getSubject().unpack(PolicyViolationUpdatedSubject.class);
            assertThat(update.getGroup()).isEqualTo(Group.GROUP_POLICY_VIOLATION_UPDATED);
            assertThat(subject.getPolicyViolation().getUuid()).isIn(originalViolationUuids);
            assertThat(subject.getPreviousMessage()).isEqualTo(KEV_A);
            assertThat(subject.getCurrentMessage()).isEqualTo(KEV_A + "," + KEV_B);
        }
        evaluateAndDeliver(0);
        assertThat(received).hasSize(8);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void shouldRollBackViolationAndOutboxTogetherWhenEmissionFails(boolean reviewed) throws Exception {
        setKevs(KEV_A);
        evaluateAndDeliver(1);
        final UUID initialUuid = violation().getUuid();
        if (reviewed) {
            rule.setNotifyOn(
                    Set.of(NotificationGroup.POLICY_VIOLATION, NotificationGroup.POLICY_VIOLATION_UPDATED_REVIEWED));
            qm.persist(rule);
            review(ViolationAnalysisState.APPROVED, true);
        }
        setKevs(KEV_A, KEV_B);
        useJdbiTransaction(handle -> {
            handle.execute("""
                    CREATE FUNCTION issue7649_test_reject_outbox() RETURNS trigger LANGUAGE plpgsql AS $$
                    BEGIN
                      RAISE EXCEPTION 'issue7649 injected outbox failure';
                    END;
                    $$
                    """);
            handle.execute("""
                    CREATE TRIGGER issue7649_test_reject_outbox
                    BEFORE INSERT ON "NOTIFICATION_OUTBOX"
                    FOR EACH ROW EXECUTE FUNCTION issue7649_test_reject_outbox()
                    """);
        });
        try {
            assertThatThrownBy(() -> new CelPolicyEngine().evaluateProject(project.getUuid()))
                    .hasStackTraceContaining("issue7649 injected outbox failure");
            assertThat(violation().getText()).isEqualTo(KEV_A);
            assertThat(violation().getUuid()).isEqualTo(initialUuid);
            assertThat(getNotificationOutbox()).isEmpty();
            assertThat(received).hasSize(1);
        } finally {
            useJdbiTransaction(handle -> {
                handle.execute("DROP TRIGGER issue7649_test_reject_outbox ON \"NOTIFICATION_OUTBOX\"");
                handle.execute("DROP FUNCTION issue7649_test_reject_outbox()");
            });
        }
        evaluateAndDeliver(1);
        if (reviewed) {
            assertReviewedUpdate(
                    received.getLast(), KEV_A, KEV_A + "," + KEV_B, initialUuid, ViolationAnalysisState.APPROVED, true);
            final var analysis = qm.getViolationAnalysis(component, violation());
            assertThat(analysis.getAnalysisState()).isEqualTo(ViolationAnalysisState.APPROVED);
            assertThat(analysis.isSuppressed()).isTrue();
        } else {
            assertUpdate(received.getLast(), KEV_A, KEV_A + "," + KEV_B, initialUuid);
        }
        evaluateAndDeliver(0);
        assertThat(received).hasSize(2);
    }

    private void review(ViolationAnalysisState state, boolean suppressed) {
        qm.makeViolationAnalysis(new MakeViolationAnalysisCommand(component, violation())
                .withState(state)
                .withSuppress(suppressed)
                .withOptions(Set.of(MakeViolationAnalysisCommand.Option.OMIT_NOTIFICATION)));
    }

    private List<Notification> addOrdinaryUpdateReceiver() {
        final List<Notification> notifications = new CopyOnWriteArrayList<>();
        receiver.createContext("/ordinary-updates", exchange -> {
            try (exchange) {
                notifications.add(Notification.parseFrom(exchange.getRequestBody()));
                exchange.sendResponseHeaders(204, -1);
            }
        });
        final var ordinaryRule = new NotificationRule();
        ordinaryRule.setName("Ordinary updates only");
        ordinaryRule.setEnabled(true);
        ordinaryRule.setTriggerType(NotificationTriggerType.EVENT);
        ordinaryRule.setScope(NotificationScope.PORTFOLIO);
        ordinaryRule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        ordinaryRule.setNotifyOn(Set.of(NotificationGroup.POLICY_VIOLATION_UPDATED));
        ordinaryRule.setPublisher(rule.getPublisher());
        ordinaryRule.setPublisherConfig("""
                {"destinationUrl":"http://127.0.0.1:%d/ordinary-updates","publishProtobuf":true}
                """.formatted(receiver.getAddress().getPort()));
        qm.persist(ordinaryRule);
        return notifications;
    }

    private void assertReviewedUpdate(
            Notification notification,
            String previous,
            String current,
            UUID uuid,
            ViolationAnalysisState state,
            boolean suppressed)
            throws Exception {
        assertThat(notification.getGroup()).isEqualTo(Group.GROUP_POLICY_VIOLATION_UPDATED_REVIEWED);
        final var subject = notification.getSubject().unpack(PolicyViolationUpdatedSubject.class);
        assertThat(subject.getPolicyViolation().getUuid()).isEqualTo(uuid.toString());
        assertThat(subject.getPreviousMessage()).isEqualTo(previous);
        assertThat(subject.getCurrentMessage()).isEqualTo(current);
        assertThat(subject.getPolicyViolation().getMessage()).isEqualTo(current);
        assertThat(subject.hasAnalysisState()).isTrue();
        assertThat(subject.getAnalysisState()).isEqualTo(state.name());
        assertThat(subject.hasSuppressed()).isTrue();
        assertThat(subject.getSuppressed()).isEqualTo(suppressed);
    }

    private void setKevs(String... ids) {
        useJdbiTransaction(handle -> {
            final var dao = handle.attach(KevDao.class);
            dao.upsertBatch(
                    "local-test",
                    java.util.Arrays.stream(ids)
                            .map(id -> new KevAssertion("NVD", id, null, null, null, null, null))
                            .toList());
            dao.deleteStale(
                    "local-test",
                    java.util.Arrays.stream(ids)
                            .map(id -> new VulnerabilityKey(id, Vulnerability.Source.NVD))
                            .toList());
        });
    }

    private PolicyViolation violation() {
        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
        return qm.getAllPolicyViolations(component).getFirst();
    }

    private void assertUpdate(Notification notification, String previous, String current, UUID uuid) throws Exception {
        assertThat(notification.getGroup()).isEqualTo(Group.GROUP_POLICY_VIOLATION_UPDATED);
        final var subject = notification.getSubject().unpack(PolicyViolationUpdatedSubject.class);
        assertThat(subject.getPreviousMessage()).isEqualTo(previous);
        assertThat(subject.getCurrentMessage()).isEqualTo(current);
        assertThat(subject.getPolicyViolation().getUuid()).isEqualTo(uuid.toString());
    }

    private List<Notification> evaluateAndDeliver(int expectedEvents) throws Exception {
        return evaluateAndDeliver(expectedEvents, true);
    }

    private List<Notification> evaluateAndDeliver(int expectedEvents, boolean expectedRoute) throws Exception {
        return evaluateAndDeliver(expectedEvents, expectedRoute, WorkflowRunStatus.COMPLETED);
    }

    private List<Notification> evaluateAndDeliver(
            int expectedEvents, boolean expectedRoute, WorkflowRunStatus expectedStatus) throws Exception {
        new CelPolicyEngine().evaluateProject(project.getUuid());
        final List<Notification> outbox = getNotificationOutbox();
        assertThat(outbox).hasSize(expectedEvents);
        if (outbox.isEmpty()) {
            return outbox;
        }
        final var engine = workflowTest.getEngine();
        final var registry = new SimpleMeterRegistry();
        try (var relay = new NotificationOutboxRelay(
                engine,
                fileStorage,
                handle -> new NotificationRouter(handle, registry),
                registry,
                10,
                10,
                128 * 1024)) {
            relay.start();
            await().atMost(Duration.ofSeconds(10))
                    .untilAsserted(() -> assertThat(getNotificationOutbox()).isEmpty());
            for (final Notification notification : outbox) {
                final var request = new ListWorkflowRunsRequest()
                        .withWorkflowInstanceId("publish-notification:" + notification.getId());
                if (!expectedRoute) {
                    assertThat(engine.listRuns(request).items()).isEmpty();
                    continue;
                }
                await().atMost(Duration.ofSeconds(10))
                        .untilAsserted(() ->
                                assertThat(engine.listRuns(request).items()).hasSize(1));
                final UUID runId = engine.listRuns(request).items().getFirst().id();
                workflowTest.awaitRunStatus(runId, expectedStatus);
            }
        } finally {
            registry.close();
        }
        return outbox;
    }
}
