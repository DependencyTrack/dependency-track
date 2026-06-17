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

import io.github.resilience4j.core.IntervalFunction;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRun;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.testing.WorkflowTestExtension;
import org.dependencytrack.filestorage.memory.MemoryFileStorage;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.proto.internal.workflow.v1.ProcessScheduledNotificationRuleArg;
import org.dependencytrack.proto.internal.workflow.v1.ProcessScheduledNotificationsWorkflowArg;
import org.dependencytrack.proto.internal.workflow.v1.PublishNotificationWorkflowArg;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;

class ProcessScheduledNotificationsWorkflowTest extends PersistenceCapableTest {

    @RegisterExtension
    private final WorkflowTestExtension workflowTest =
            new WorkflowTestExtension(DataSourceRegistry.getInstance().getDefault());

    @BeforeEach
    void beforeEach() {
        final DexEngine engine = workflowTest.getEngine();

        engine.registerWorkflow(
                new ProcessScheduledNotificationsWorkflow(),
                protoConverter(ProcessScheduledNotificationsWorkflowArg.class),
                voidConverter(),
                Duration.ofSeconds(15));
        engine.registerWorkflow(
                new PublishNotificationWorkflow(),
                protoConverter(PublishNotificationWorkflowArg.class),
                voidConverter(),
                Duration.ofSeconds(15));
        engine.registerActivity(
                new ProcessScheduledNotificationRuleActivity(
                        engine,
                        new MemoryFileStorage(),
                        Integer.MAX_VALUE),
                protoConverter(ProcessScheduledNotificationRuleArg.class),
                voidConverter(),
                Duration.ofSeconds(15));

        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "notifications", 1));

        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker", "notifications", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.start();
    }

    @Test
    void shouldFailWhenArgumentIsNull() {
        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(ProcessScheduledNotificationsWorkflow.class));

        final WorkflowRun run = workflowTest.awaitRunStatus(runId, WorkflowRunStatus.FAILED);
        assertThat(run).isNotNull();
        assertThat(run.failure()).isNotNull();
        assertThat(run.failure().getMessage()).isEqualTo("No rule names provided");
    }

    @Test
    void shouldFailWhenAllActivitiesFailed() {
        final var arg = ProcessScheduledNotificationsWorkflowArg.newBuilder()
                .addRuleNames(UUID.randomUUID().toString())
                .addRuleNames(UUID.randomUUID().toString())
                .build();

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(ProcessScheduledNotificationsWorkflow.class)
                        .withArgument(arg));

        final WorkflowRun run = workflowTest.awaitRunStatus(runId, WorkflowRunStatus.FAILED);
        assertThat(run).isNotNull();
        assertThat(run.failure()).isNotNull();
        assertThat(run.failure().getMessage()).isEqualTo("All 2 scheduled notification rules failed");
    }

    @Test
    void shouldSucceedWhenAtLeastOneActivitySucceeded() {
        final NotificationRule rule = createRuleWithFindings();

        final var arg = ProcessScheduledNotificationsWorkflowArg.newBuilder()
                .addRuleNames(UUID.randomUUID().toString())
                .addRuleNames(rule.getName())
                .build();

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(ProcessScheduledNotificationsWorkflow.class)
                        .withArgument(arg));

        final WorkflowRun run = workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);
        assertThat(run).isNotNull();
        assertThat(run.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
    }

    private NotificationRule createRuleWithFindings() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("INT-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        qm.persist(vuln);
        qm.addVulnerability(vuln, component, "internal", null, null, new Date());

        final var publisher = qm.createNotificationPublisher(
                "test-publisher", null, "webhook", "template", "text/plain", false);
        final NotificationRule rule = qm.createScheduledNotificationRule(
                "test-rule", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setNotifyOn(Set.of(NotificationGroup.NEW_VULNERABILITIES_SUMMARY));
        rule.setProjects(List.of(project));
        rule.setNotifyChildren(true);
        rule.setScheduleCron("* * * * *");
        rule.setScheduleLastTriggeredAt(Date.from(Instant.now().minus(1, ChronoUnit.HOURS)));
        rule.updateScheduleNextTriggerAt();
        rule.setScheduleSkipUnchanged(false);
        rule.setEnabled(true);
        return rule;
    }
}