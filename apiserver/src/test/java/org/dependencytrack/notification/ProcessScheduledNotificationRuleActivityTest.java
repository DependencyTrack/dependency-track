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

import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.util.JsonFormat;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.proto.v1.NewPolicyViolationsSummarySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerabilitiesSummarySubject;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.command.MakeViolationAnalysisCommand;
import org.dependencytrack.proto.internal.workflow.v1.ProcessScheduledNotificationRuleArg;
import org.dependencytrack.proto.internal.workflow.v1.PublishNotificationWorkflowArg;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_NEW_POLICY_VIOLATIONS_SUMMARY;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_NEW_VULNERABILITIES_SUMMARY;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.notification.proto.v1.Scope.SCOPE_PORTFOLIO;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class ProcessScheduledNotificationRuleActivityTest extends PersistenceCapableTest {

    @Test
    void shouldDispatchNewVulnNotification() throws InvalidProtocolBufferException {
        final Instant ruleLastFiredAt = Instant.now().minus(10, ChronoUnit.MINUTES);
        final Instant beforeRuleLastFiredAt = ruleLastFiredAt.minus(5, ChronoUnit.MINUTES);
        final Instant afterRuleLastFiredAt = ruleLastFiredAt.plus(5, ChronoUnit.MINUTES);

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("INT-001");
        vulnA.setSource(Vulnerability.Source.INTERNAL);
        vulnA.setSeverity(Severity.HIGH);
        qm.persist(vulnA);

        final var vulnB = new Vulnerability();
        vulnB.setVulnId("INT-002");
        vulnB.setSource(Vulnerability.Source.INTERNAL);
        vulnB.setSeverity(Severity.LOW);
        qm.persist(vulnB);

        // Parent project affected by vulnA and vulnB, both attributed AFTER rule's last firing.
        // vulnB is suppressed.
        final var parentProject = new Project();
        parentProject.setName("acme-app-parent");
        qm.persist(parentProject);
        final var parentProjectComponent = new Component();
        parentProjectComponent.setProject(parentProject);
        parentProjectComponent.setName("acme-lib-parent");
        qm.persist(parentProjectComponent);
        qm.addVulnerability(vulnA, parentProjectComponent, "internal",
                null, null, Date.from(afterRuleLastFiredAt));
        qm.addVulnerability(vulnB, parentProjectComponent, "internal",
                null, null, Date.from(afterRuleLastFiredAt));
        qm.makeAnalysis(new MakeAnalysisCommand(
                parentProjectComponent, vulnB, AnalysisState.FALSE_POSITIVE,
                null, null, null, true, null, null, Set.of()));

        // Child project affected by vulnA (BEFORE) and vulnB (AFTER).
        final var childProject = new Project();
        childProject.setParent(parentProject);
        childProject.setName("acme-app-child");
        qm.persist(childProject);
        final var childProjectComponent = new Component();
        childProjectComponent.setProject(childProject);
        childProjectComponent.setName("acme-lib-child");
        qm.persist(childProjectComponent);
        qm.addVulnerability(vulnA, childProjectComponent, "internal",
                null, null, Date.from(beforeRuleLastFiredAt));
        qm.addVulnerability(vulnB, childProjectComponent, "internal",
                null, null, Date.from(afterRuleLastFiredAt));

        // Inactive project — should be excluded.
        final var inactiveProject = new Project();
        inactiveProject.setName("acme-app-inactive");
        inactiveProject.setActive(false);
        qm.persist(inactiveProject);
        final var inactiveProjectComponent = new Component();
        inactiveProjectComponent.setProject(inactiveProject);
        inactiveProjectComponent.setName("acme-lib-inactive");
        qm.persist(inactiveProjectComponent);
        qm.addVulnerability(vulnA, inactiveProjectComponent, "internal",
                null, null, Date.from(afterRuleLastFiredAt));

        final var publisher = qm.createNotificationPublisher(
                "foo", null, "webhook", "template", "templateMimeType", false);
        final NotificationRule rule = qm.createScheduledNotificationRule(
                "foo", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setNotifyOn(Set.of(NotificationGroup.NEW_VULNERABILITIES_SUMMARY));
        rule.setProjects(List.of(parentProject, inactiveProject));
        rule.setNotifyChildren(true);
        rule.setScheduleCron("* * * * *");
        rule.setScheduleLastTriggeredAt(Date.from(ruleLastFiredAt));
        rule.updateScheduleNextTriggerAt();
        rule.setScheduleSkipUnchanged(true);
        rule.setEnabled(true);

        final var dexEngine = mock(DexEngine.class);
        doReturn(UUID.randomUUID()).when(dexEngine).createRun(ArgumentMatchers.<CreateWorkflowRunRequest<?>>any());

        final var activity = new ProcessScheduledNotificationRuleActivity(
                dexEngine, mock(FileStorage.class), Integer.MAX_VALUE);
        activity.execute(
                mock(ActivityContext.class),
                ProcessScheduledNotificationRuleArg.newBuilder()
                        .setRuleName(rule.getName())
                        .build());

        @SuppressWarnings("unchecked") final ArgumentCaptor<CreateWorkflowRunRequest<?>> captor =
                ArgumentCaptor.forClass(CreateWorkflowRunRequest.class);
        verify(dexEngine).createRun(captor.capture());

        final CreateWorkflowRunRequest<?> request = captor.getValue();
        final var workflowArg = (PublishNotificationWorkflowArg) request.argument();
        final Notification notification = workflowArg.getNotification();

        assertThat(notification.getGroup()).isEqualTo(GROUP_NEW_VULNERABILITIES_SUMMARY);
        assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);

        final NewVulnerabilitiesSummarySubject subject =
                notification.getSubject().unpack(NewVulnerabilitiesSummarySubject.class);

        assertThatJson(JsonFormat.printer().alwaysPrintFieldsWithNoPresence().print(subject))
                .withOptions(Option.IGNORING_EXTRA_FIELDS, Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "overview": {
                            "affectedProjectsCount": 2,
                            "affectedComponentsCount": 2,
                            "newVulnerabilitiesCount": 2,
                            "newVulnerabilitiesCountBySeverity": {
                              "HIGH": 1,
                              "LOW": 1
                            },
                            "suppressedNewVulnerabilitiesCount": 1,
                            "totalNewVulnerabilitiesCount": 3
                          },
                          "projectSummaries": [
                            {
                              "project": { "name": "acme-app-parent", "uuid": "${json-unit.any-string}" },
                              "newVulnerabilitiesCountBySeverity": { "HIGH": 1 },
                              "suppressedNewVulnerabilitiesCountBySeverity": { "LOW": 1 },
                              "totalNewVulnerabilitiesCountBySeverity": { "HIGH": 1, "LOW": 1 }
                            },
                            {
                              "project": { "name": "acme-app-child", "uuid": "${json-unit.any-string}" },
                              "newVulnerabilitiesCountBySeverity": { "LOW": 1 },
                              "suppressedNewVulnerabilitiesCountBySeverity": {},
                              "totalNewVulnerabilitiesCountBySeverity": { "LOW": 1 }
                            }
                          ],
                          "findingsByProject": [
                            {
                              "project": { "name": "acme-app-parent", "uuid": "${json-unit.any-string}" },
                              "findings": [
                                {
                                  "component": { "name": "acme-lib-parent", "uuid": "${json-unit.any-string}" },
                                  "vulnerability": { "vulnId": "INT-001", "source": "INTERNAL", "severity": "HIGH", "uuid": "${json-unit.any-string}" },
                                  "analyzerIdentity": "internal",
                                  "suppressed": false
                                },
                                {
                                  "component": { "name": "acme-lib-parent", "uuid": "${json-unit.any-string}" },
                                  "vulnerability": { "vulnId": "INT-002", "source": "INTERNAL", "severity": "LOW", "uuid": "${json-unit.any-string}" },
                                  "analyzerIdentity": "internal",
                                  "analysisState": "FALSE_POSITIVE",
                                  "suppressed": true
                                }
                              ]
                            },
                            {
                              "project": { "name": "acme-app-child", "uuid": "${json-unit.any-string}" },
                              "findings": [
                                {
                                  "component": { "name": "acme-lib-child", "uuid": "${json-unit.any-string}" },
                                  "vulnerability": { "vulnId": "INT-002", "source": "INTERNAL", "severity": "LOW", "uuid": "${json-unit.any-string}" },
                                  "analyzerIdentity": "internal",
                                  "suppressed": false
                                }
                              ]
                            }
                          ]
                        }
                        """);

        qm.getPersistenceManager().evictAll();
        final NotificationRule updatedRule = qm.getObjectByUuid(NotificationRule.class, rule.getUuid());
        // DB timestamps may be stored with second precision; tolerate truncated milliseconds.
        assertThat(updatedRule.getScheduleLastTriggeredAt())
                .isAfterOrEqualTo(Date.from(ruleLastFiredAt.truncatedTo(ChronoUnit.SECONDS)));
        assertThat(updatedRule.getScheduleNextTriggerAt()).isAfter(new Date());
    }

    @Test
    void shouldDispatchPolicyViolationNotification() throws InvalidProtocolBufferException {
        final Instant ruleLastFiredAt = Instant.now().minus(10, ChronoUnit.MINUTES);
        final Instant beforeRuleLastFiredAt = ruleLastFiredAt.minus(5, ChronoUnit.MINUTES);
        final Instant afterRuleLastFiredAt = ruleLastFiredAt.plus(5, ChronoUnit.MINUTES);

        final var policyA = new Policy();
        policyA.setName("policy-a");
        policyA.setOperator(Policy.Operator.ALL);
        policyA.setViolationState(Policy.ViolationState.WARN);
        qm.persist(policyA);
        final var policyConditionA = new PolicyCondition();
        policyConditionA.setPolicy(policyA);
        policyConditionA.setSubject(PolicyCondition.Subject.VERSION);
        policyConditionA.setOperator(PolicyCondition.Operator.IS);
        policyConditionA.setValue("1.0.0");
        qm.persist(policyConditionA);

        final var policyB = new Policy();
        policyB.setName("policy-b");
        policyB.setOperator(Policy.Operator.ALL);
        policyB.setViolationState(Policy.ViolationState.WARN);
        qm.persist(policyB);
        final var policyConditionB = new PolicyCondition();
        policyConditionB.setPolicy(policyB);
        policyConditionB.setSubject(PolicyCondition.Subject.SEVERITY);
        policyConditionB.setOperator(PolicyCondition.Operator.IS);
        policyConditionB.setValue("HIGH");
        qm.persist(policyConditionB);

        // Parent project with violations for policyA and policyB (both AFTER), policyB suppressed.
        final var parentProject = new Project();
        parentProject.setName("acme-app-parent");
        qm.persist(parentProject);
        final var parentProjectComponent = new Component();
        parentProjectComponent.setProject(parentProject);
        parentProjectComponent.setName("acme-lib-parent");
        parentProjectComponent.setVersion("1.0.0");
        qm.persist(parentProjectComponent);
        final var pvA_parent = new PolicyViolation();
        pvA_parent.setPolicyCondition(policyConditionA);
        pvA_parent.setComponent(parentProjectComponent);

        pvA_parent.setType(PolicyViolation.Type.OPERATIONAL);
        pvA_parent.setTimestamp(Date.from(afterRuleLastFiredAt));
        qm.persist(pvA_parent);
        final var pvB_parent = new PolicyViolation();
        pvB_parent.setPolicyCondition(policyConditionB);
        pvB_parent.setComponent(parentProjectComponent);

        pvB_parent.setType(PolicyViolation.Type.SECURITY);
        pvB_parent.setTimestamp(Date.from(afterRuleLastFiredAt));
        qm.persist(pvB_parent);
        qm.makeViolationAnalysis(new MakeViolationAnalysisCommand(
                parentProjectComponent, pvB_parent, ViolationAnalysisState.APPROVED,
                true, null, null, Set.of()));

        // Child project with violations for policyA (BEFORE) and policyB (AFTER).
        final var childProject = new Project();
        childProject.setParent(parentProject);
        childProject.setName("acme-app-child");
        qm.persist(childProject);
        final var childProjectComponent = new Component();
        childProjectComponent.setProject(childProject);
        childProjectComponent.setName("acme-lib-child");
        childProjectComponent.setVersion("1.0.0");
        qm.persist(childProjectComponent);
        final var pvA_child = new PolicyViolation();
        pvA_child.setPolicyCondition(policyConditionA);
        pvA_child.setComponent(childProjectComponent);

        pvA_child.setType(PolicyViolation.Type.OPERATIONAL);
        pvA_child.setTimestamp(Date.from(beforeRuleLastFiredAt));
        qm.persist(pvA_child);
        final var pvB_child = new PolicyViolation();
        pvB_child.setPolicyCondition(policyConditionB);
        pvB_child.setComponent(childProjectComponent);

        pvB_child.setType(PolicyViolation.Type.SECURITY);
        pvB_child.setTimestamp(Date.from(afterRuleLastFiredAt));
        qm.persist(pvB_child);

        // Inactive project — should be excluded.
        final var inactiveProject = new Project();
        inactiveProject.setName("acme-app-inactive");
        inactiveProject.setActive(false);
        qm.persist(inactiveProject);
        final var inactiveProjectComponent = new Component();
        inactiveProjectComponent.setProject(inactiveProject);
        inactiveProjectComponent.setName("acme-lib-inactive");
        qm.persist(inactiveProjectComponent);
        final var pvA_inactive = new PolicyViolation();
        pvA_inactive.setPolicyCondition(policyConditionA);
        pvA_inactive.setComponent(inactiveProjectComponent);

        pvA_inactive.setType(PolicyViolation.Type.OPERATIONAL);
        pvA_inactive.setTimestamp(Date.from(beforeRuleLastFiredAt));
        qm.persist(pvA_inactive);

        final var publisher = qm.createNotificationPublisher(
                "foo", null, "webhook", "template", "templateMimeType", false);
        final NotificationRule rule = qm.createScheduledNotificationRule(
                "foo", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setNotifyOn(Set.of(NotificationGroup.NEW_POLICY_VIOLATIONS_SUMMARY));
        rule.setProjects(List.of(parentProject, inactiveProject));
        rule.setNotifyChildren(true);
        rule.setScheduleCron("* * * * *");
        rule.setScheduleLastTriggeredAt(Date.from(ruleLastFiredAt));
        rule.updateScheduleNextTriggerAt();
        rule.setScheduleSkipUnchanged(true);
        rule.setEnabled(true);

        final var dexEngine = mock(DexEngine.class);
        doReturn(UUID.randomUUID()).when(dexEngine).createRun(ArgumentMatchers.<CreateWorkflowRunRequest<?>>any());

        final var activity = new ProcessScheduledNotificationRuleActivity(
                dexEngine, mock(FileStorage.class), Integer.MAX_VALUE);
        activity.execute(
                mock(ActivityContext.class),
                ProcessScheduledNotificationRuleArg.newBuilder()
                        .setRuleName(rule.getName())
                        .build());

        @SuppressWarnings("unchecked") final ArgumentCaptor<CreateWorkflowRunRequest<?>> captor =
                ArgumentCaptor.forClass(CreateWorkflowRunRequest.class);
        verify(dexEngine).createRun(captor.capture());

        final CreateWorkflowRunRequest<?> request = captor.getValue();
        final var workflowArg = (PublishNotificationWorkflowArg) request.argument();
        final Notification notification = workflowArg.getNotification();

        assertThat(notification.getGroup()).isEqualTo(GROUP_NEW_POLICY_VIOLATIONS_SUMMARY);
        assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);

        final NewPolicyViolationsSummarySubject subject =
                notification.getSubject().unpack(NewPolicyViolationsSummarySubject.class);

        assertThatJson(JsonFormat.printer().alwaysPrintFieldsWithNoPresence().print(subject))
                .withOptions(Option.IGNORING_EXTRA_FIELDS, Option.IGNORING_ARRAY_ORDER)
                .isEqualTo(/* language=JSON */ """
                        {
                          "overview": {
                            "affectedProjectsCount": 2,
                            "affectedComponentsCount": 2,
                            "newViolationsCount": 2,
                            "newViolationsCountByType": {
                              "SECURITY": 1,
                              "OPERATIONAL": 1
                            },
                            "suppressedNewViolationsCount": 1,
                            "totalNewViolationsCount": 3
                          },
                          "projectSummaries": [
                            {
                              "project": { "name": "acme-app-parent", "uuid": "${json-unit.any-string}" },
                              "newViolationsCountByType": { "OPERATIONAL": 1 },
                              "suppressedNewViolationsCountByType": { "SECURITY": 1 },
                              "totalNewViolationsCountByType": { "SECURITY": 1, "OPERATIONAL": 1 }
                            },
                            {
                              "project": { "name": "acme-app-child", "uuid": "${json-unit.any-string}" },
                              "newViolationsCountByType": { "SECURITY": 1 },
                              "suppressedNewViolationsCountByType": {},
                              "totalNewViolationsCountByType": { "SECURITY": 1 }
                            }
                          ],
                          "violationsByProject": [
                            {
                              "project": { "name": "acme-app-parent", "uuid": "${json-unit.any-string}" },
                              "violations": [
                                {
                                  "component": { "name": "acme-lib-parent", "version": "1.0.0", "uuid": "${json-unit.any-string}" },
                                  "policyCondition": {
                                    "policy": { "name": "policy-a", "violationState": "WARN", "uuid": "${json-unit.any-string}" },
                                    "operator": "IS", "subject": "VERSION", "value": "1.0.0", "uuid": "${json-unit.any-string}"
                                  },
                                  "type": "OPERATIONAL",
                                  "suppressed": false
                                },
                                {
                                  "component": { "name": "acme-lib-parent", "version": "1.0.0", "uuid": "${json-unit.any-string}" },
                                  "policyCondition": {
                                    "policy": { "name": "policy-b", "violationState": "WARN", "uuid": "${json-unit.any-string}" },
                                    "operator": "IS", "subject": "SEVERITY", "value": "HIGH", "uuid": "${json-unit.any-string}"
                                  },
                                  "type": "SECURITY",
                                  "suppressed": true
                                }
                              ]
                            },
                            {
                              "project": { "name": "acme-app-child", "uuid": "${json-unit.any-string}" },
                              "violations": [
                                {
                                  "component": { "name": "acme-lib-child", "version": "1.0.0", "uuid": "${json-unit.any-string}" },
                                  "policyCondition": {
                                    "policy": { "name": "policy-b", "violationState": "WARN", "uuid": "${json-unit.any-string}" },
                                    "operator": "IS", "subject": "SEVERITY", "value": "HIGH", "uuid": "${json-unit.any-string}"
                                  },
                                  "type": "SECURITY",
                                  "suppressed": false
                                }
                              ]
                            }
                          ]
                        }
                        """);
    }

    @Test
    void shouldNotDispatchNotificationWhenNoNewFindingsAndSkipUnchangedEnabled() {
        final Instant ruleLastFiredAt = Instant.now().minus(10, ChronoUnit.MINUTES);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var publisher = qm.createNotificationPublisher(
                "foo", null, "webhook", "template", "templateMimeType", false);
        final NotificationRule rule = qm.createScheduledNotificationRule(
                "foo", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setNotifyOn(Set.of(
                NotificationGroup.NEW_VULNERABILITIES_SUMMARY,
                NotificationGroup.NEW_POLICY_VIOLATIONS_SUMMARY));
        rule.setProjects(List.of(project));
        rule.setNotifyChildren(true);
        rule.setScheduleCron("* * * * *");
        rule.setScheduleLastTriggeredAt(Date.from(ruleLastFiredAt));
        rule.updateScheduleNextTriggerAt();
        rule.setScheduleSkipUnchanged(true);
        rule.setEnabled(true);

        final var dexEngine = mock(DexEngine.class);
        doReturn(UUID.randomUUID()).when(dexEngine).createRun(ArgumentMatchers.<CreateWorkflowRunRequest<?>>any());

        final var activity = new ProcessScheduledNotificationRuleActivity(
                dexEngine, mock(FileStorage.class), Integer.MAX_VALUE);
        activity.execute(
                mock(ActivityContext.class),
                ProcessScheduledNotificationRuleArg.newBuilder()
                        .setRuleName(rule.getName())
                        .build());

        verifyNoInteractions(dexEngine);
    }

    @Test
    void shouldDispatchNotificationWhenNoNewFindingsAndSkipUnchangedDisabled() {
        final Instant ruleLastFiredAt = Instant.now().minus(10, ChronoUnit.MINUTES);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var publisher = qm.createNotificationPublisher(
                "foo", null, "webhook", "template", "templateMimeType", false);
        final NotificationRule rule = qm.createScheduledNotificationRule(
                "foo", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setNotifyOn(Set.of(
                NotificationGroup.NEW_VULNERABILITIES_SUMMARY,
                NotificationGroup.NEW_POLICY_VIOLATIONS_SUMMARY));
        rule.setProjects(List.of(project));
        rule.setNotifyChildren(true);
        rule.setScheduleCron("* * * * *");
        rule.setScheduleLastTriggeredAt(Date.from(ruleLastFiredAt));
        rule.updateScheduleNextTriggerAt();
        rule.setScheduleSkipUnchanged(false);
        rule.setEnabled(true);

        final var dexEngine = mock(DexEngine.class);
        doReturn(UUID.randomUUID()).when(dexEngine).createRun(ArgumentMatchers.<CreateWorkflowRunRequest<?>>any());

        final var activity = new ProcessScheduledNotificationRuleActivity(
                dexEngine, mock(FileStorage.class), Integer.MAX_VALUE);
        activity.execute(
                mock(ActivityContext.class),
                ProcessScheduledNotificationRuleArg.newBuilder()
                        .setRuleName(rule.getName())
                        .build());

        verify(dexEngine, times(2)).createRun(org.mockito.ArgumentMatchers.any());
    }

    @Nested
    class FilterExpressionTest {

        @Test
        void shouldDispatchWhenFilterExpressionMatchesNewVulnSummary() {
            final Instant ruleLastFiredAt = Instant.now().minus(10, ChronoUnit.MINUTES);
            final Instant afterRuleLastFiredAt = ruleLastFiredAt.plus(5, ChronoUnit.MINUTES);

            final var vuln = new Vulnerability();
            vuln.setVulnId("INT-001");
            vuln.setSource(Vulnerability.Source.INTERNAL);
            vuln.setSeverity(Severity.CRITICAL);
            qm.persist(vuln);

            final var project = new Project();
            project.setName("acme-app");
            qm.persist(project);
            final var component = new Component();
            component.setProject(project);
            component.setName("acme-lib");
            qm.persist(component);
            qm.addVulnerability(vuln, component, "internal",
                    null, null, Date.from(afterRuleLastFiredAt));

            final var publisher = qm.createNotificationPublisher(
                    "foo", null, "webhook", "template", "templateMimeType", false);
            final NotificationRule rule = qm.createScheduledNotificationRule(
                    "foo", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
            rule.setNotifyOn(Set.of(NotificationGroup.NEW_VULNERABILITIES_SUMMARY));
            rule.setProjects(List.of(project));
            rule.setScheduleCron("* * * * *");
            rule.setScheduleLastTriggeredAt(Date.from(ruleLastFiredAt));
            rule.updateScheduleNextTriggerAt();
            rule.setEnabled(true);
            rule.setFilterExpression("\"CRITICAL\" in subject.overview.new_vulnerabilities_count_by_severity");

            final var dexEngine = mock(DexEngine.class);
            doReturn(UUID.randomUUID()).when(dexEngine).createRun(ArgumentMatchers.<CreateWorkflowRunRequest<?>>any());

            final var activity = new ProcessScheduledNotificationRuleActivity(
                    dexEngine, mock(FileStorage.class), Integer.MAX_VALUE);
            activity.execute(
                    mock(ActivityContext.class),
                    ProcessScheduledNotificationRuleArg.newBuilder()
                            .setRuleName(rule.getName())
                            .build());

            verify(dexEngine).createRun(ArgumentMatchers.<CreateWorkflowRunRequest<?>>any());
        }

        @Test
        void shouldNotDispatchWhenFilterExpressionDoesNotMatch() {
            final Instant ruleLastFiredAt = Instant.now().minus(10, ChronoUnit.MINUTES);
            final Instant afterRuleLastFiredAt = ruleLastFiredAt.plus(5, ChronoUnit.MINUTES);

            final var vuln = new Vulnerability();
            vuln.setVulnId("INT-001");
            vuln.setSource(Vulnerability.Source.INTERNAL);
            vuln.setSeverity(Severity.LOW);
            qm.persist(vuln);

            final var project = new Project();
            project.setName("acme-app");
            qm.persist(project);
            final var component = new Component();
            component.setProject(project);
            component.setName("acme-lib");
            qm.persist(component);
            qm.addVulnerability(vuln, component, "internal",
                    null, null, Date.from(afterRuleLastFiredAt));

            final var publisher = qm.createNotificationPublisher(
                    "foo", null, "webhook", "template", "templateMimeType", false);
            final NotificationRule rule = qm.createScheduledNotificationRule(
                    "foo", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
            rule.setNotifyOn(Set.of(NotificationGroup.NEW_VULNERABILITIES_SUMMARY));
            rule.setProjects(List.of(project));
            rule.setScheduleCron("* * * * *");
            rule.setScheduleLastTriggeredAt(Date.from(ruleLastFiredAt));
            rule.updateScheduleNextTriggerAt();
            rule.setEnabled(true);
            rule.setFilterExpression("\"CRITICAL\" in subject.overview.new_vulnerabilities_count_by_severity");

            final var dexEngine = mock(DexEngine.class);

            final var activity = new ProcessScheduledNotificationRuleActivity(
                    dexEngine, mock(FileStorage.class), Integer.MAX_VALUE);
            activity.execute(
                    mock(ActivityContext.class),
                    ProcessScheduledNotificationRuleArg.newBuilder()
                            .setRuleName(rule.getName())
                            .build());

            verifyNoInteractions(dexEngine);

            // Schedule should still be advanced.
            qm.getPersistenceManager().evictAll();
            final NotificationRule updatedRule = qm.getObjectByUuid(NotificationRule.class, rule.getUuid());
            assertThat(updatedRule.getScheduleLastTriggeredAt())
                    .isAfterOrEqualTo(Date.from(ruleLastFiredAt.truncatedTo(ChronoUnit.SECONDS)));
        }

        @Test
        void shouldFailOpenOnInvalidFilterExpression() {
            final Instant ruleLastFiredAt = Instant.now().minus(10, ChronoUnit.MINUTES);
            final Instant afterRuleLastFiredAt = ruleLastFiredAt.plus(5, ChronoUnit.MINUTES);

            final var vuln = new Vulnerability();
            vuln.setVulnId("INT-001");
            vuln.setSource(Vulnerability.Source.INTERNAL);
            vuln.setSeverity(Severity.LOW);
            qm.persist(vuln);

            final var project = new Project();
            project.setName("acme-app");
            qm.persist(project);
            final var component = new Component();
            component.setProject(project);
            component.setName("acme-lib");
            qm.persist(component);
            qm.addVulnerability(vuln, component, "internal",
                    null, null, Date.from(afterRuleLastFiredAt));

            final var publisher = qm.createNotificationPublisher(
                    "foo", null, "webhook", "template", "templateMimeType", false);
            final NotificationRule rule = qm.createScheduledNotificationRule(
                    "foo", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
            rule.setNotifyOn(Set.of(NotificationGroup.NEW_VULNERABILITIES_SUMMARY));
            rule.setProjects(List.of(project));
            rule.setScheduleCron("* * * * *");
            rule.setScheduleLastTriggeredAt(Date.from(ruleLastFiredAt));
            rule.updateScheduleNextTriggerAt();
            rule.setEnabled(true);
            rule.setFilterExpression("this is not valid CEL");

            final var dexEngine = mock(DexEngine.class);
            doReturn(UUID.randomUUID()).when(dexEngine).createRun(ArgumentMatchers.<CreateWorkflowRunRequest<?>>any());

            final var activity = new ProcessScheduledNotificationRuleActivity(
                    dexEngine, mock(FileStorage.class), Integer.MAX_VALUE);
            activity.execute(
                    mock(ActivityContext.class),
                    ProcessScheduledNotificationRuleArg.newBuilder()
                            .setRuleName(rule.getName())
                            .build());

            verify(dexEngine).createRun(ArgumentMatchers.<CreateWorkflowRunRequest<?>>any());
        }

    }

}
