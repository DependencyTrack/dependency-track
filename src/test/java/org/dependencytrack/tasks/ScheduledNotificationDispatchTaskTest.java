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
package org.dependencytrack.tasks;

import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.notification.NotificationService;
import alpine.notification.Subscriber;
import alpine.notification.Subscription;
import net.javacrumbs.jsonunit.core.Option;
import org.datanucleus.store.types.wrappers.Date;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.ScheduledNotificationDispatchEvent;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.WebhookPublisher;
import org.dependencytrack.notification.vo.NewPolicyViolationsSummary;
import org.dependencytrack.notification.vo.NewVulnerabilitiesSummary;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.Matchers.equalTo;

public class ScheduledNotificationDispatchTaskTest extends PersistenceCapableTest {

    public static class NotificationSubscriber implements Subscriber {

        @Override
        public void inform(final Notification notification) {
            NOTIFICATIONS.add(notification);
        }

    }

    private static final Queue<Notification> NOTIFICATIONS = new ConcurrentLinkedQueue<>();
    private static final Subscription SUBSCRIPTION = new Subscription(NotificationSubscriber.class);

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        NotificationService.getInstance().subscribe(SUBSCRIPTION);
    }

    @After
    @Override
    public void after() {
        NotificationService.getInstance().unsubscribe(SUBSCRIPTION);
        NOTIFICATIONS.clear();

        super.after();
    }

    @Test
    public void shouldDispatchNewVulnNotification() {
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

        // Create a parent project affected by vulnA and vulnB, where
        //   * both vulns were attributed AFTER the rule's last firing
        //   * vulnB is suppressed
        final var parentProject = new Project();
        parentProject.setName("acme-app-parent");
        qm.persist(parentProject);
        final var parentProjectComponent = new Component();
        parentProjectComponent.setProject(parentProject);
        parentProjectComponent.setName("acme-lib-parent");
        qm.persist(parentProjectComponent);
        qm.addVulnerability(
                vulnA,
                parentProjectComponent,
                AnalyzerIdentity.INTERNAL_ANALYZER,
                null,
                null,
                Date.from(afterRuleLastFiredAt));
        qm.addVulnerability(
                vulnB,
                parentProjectComponent,
                AnalyzerIdentity.INTERNAL_ANALYZER,
                null,
                null,
                Date.from(afterRuleLastFiredAt));
        qm.makeAnalysis(parentProjectComponent, vulnB, AnalysisState.FALSE_POSITIVE, null, null, null, true);

        // Create a child project affected by vulnA and vulnB, where:
        //   * vulnA was attributed BEFORE the rule's last firing
        //   * vulnB was attributed AFTER the rule's last firing
        final var childProject = new Project();
        childProject.setParent(parentProject);
        childProject.setName("acme-app-child");
        qm.persist(childProject);
        final var childProjectComponent = new Component();
        childProjectComponent.setProject(childProject);
        childProjectComponent.setName("acme-lib-child");
        qm.persist(childProjectComponent);
        qm.addVulnerability(
                vulnA,
                childProjectComponent,
                AnalyzerIdentity.INTERNAL_ANALYZER,
                null,
                null,
                Date.from(beforeRuleLastFiredAt));
        qm.addVulnerability(
                vulnB,
                childProjectComponent,
                AnalyzerIdentity.INTERNAL_ANALYZER,
                null,
                null,
                Date.from(afterRuleLastFiredAt));

        // Create an inactive project affected by vulnA.
        final var inactiveProject = new Project();
        inactiveProject.setName("acme-app-inactive");
        inactiveProject.setActive(false);
        qm.persist(inactiveProject);
        final var inactiveProjectComponent = new Component();
        inactiveProjectComponent.setProject(inactiveProject);
        inactiveProjectComponent.setName("acme-lib-inactive");
        qm.persist(inactiveProjectComponent);
        qm.addVulnerability(
                vulnA,
                parentProjectComponent,
                AnalyzerIdentity.INTERNAL_ANALYZER,
                null,
                null,
                Date.from(afterRuleLastFiredAt));

        final var publisher = qm.createNotificationPublisher(
                "foo", null, WebhookPublisher.class, "template", "templateMimeType", false);
        final var rule = qm.createScheduledNotificationRule(
                "foo", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setNotifyOn(Set.of(NotificationGroup.NEW_VULNERABILITIES_SUMMARY));
        rule.setProjects(List.of(parentProject, inactiveProject));
        rule.setNotifyChildren(true);
        rule.setScheduleCron("* * * * *"); // Every minute.
        rule.setScheduleLastTriggeredAt(Date.from(ruleLastFiredAt));
        rule.updateScheduleNextTriggerAt();
        rule.setScheduleSkipUnchanged(true);
        rule.setEnabled(true);

        new ScheduledNotificationDispatchTask().inform(new ScheduledNotificationDispatchEvent());

        final Notification notification = await("Notification Dispatch")
                .atMost(3, TimeUnit.SECONDS)
                .until(NOTIFICATIONS::poll, Objects::nonNull);
        assertThat(notification).isNotNull();

        assertThat(notification.getGroup()).isEqualTo(NotificationGroup.NEW_VULNERABILITIES_SUMMARY.name());
        assertThat(notification.getScope()).isEqualTo(NotificationScope.PORTFOLIO.name());
        assertThat(notification.getLevel()).isEqualTo(NotificationLevel.INFORMATIONAL);
        assertThat(notification.getSubject()).isInstanceOf(NewVulnerabilitiesSummary.class);

        assertThatJson(notification.getSubject())
                .withMatcher("ruleId", equalTo(BigDecimal.valueOf(rule.getId())))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
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
                            "suppressedNewVulnerabilitiesCount": 1
                          },
                          "summary": {
                            "projectSummaries": {
                              "acme-app-child": {
                                "newVulnerabilitiesCountBySeverity": {
                                  "LOW": 1
                                },
                                "suppressedNewVulnerabilitiesCountBySeverity": {},
                                "totalNewVulnerabilitiesCountBySeverity": {
                                  "LOW": 1
                                }
                              },
                              "acme-app-parent": {
                                "newVulnerabilitiesCountBySeverity": {
                                  "HIGH": 1
                                },
                                "suppressedNewVulnerabilitiesCountBySeverity": {
                                  "LOW": 1
                                },
                                "totalNewVulnerabilitiesCountBySeverity": {
                                  "HIGH": 1,
                                  "LOW": 1
                                }
                              }
                            }
                          },
                          "details": {
                            "findingsByProject": {
                              "acme-app-child": [
                                {
                                  "component": {
                                    "name": "acme-lib-child",
                                    "uuid": "${json-unit.any-string}"
                                  },
                                  "vulnerability": {
                                    "vulnId": "INT-002",
                                    "source": "INTERNAL",
                                    "severity": "LOW",
                                    "uuid": "${json-unit.any-string}"
                                  },
                                  "analyzerIdentity": "INTERNAL_ANALYZER",
                                  "attributedOn": "${json-unit.any-number}",
                                  "suppressed": false
                                }
                              ],
                              "acme-app-parent": [
                                {
                                  "component": {
                                    "name": "acme-lib-parent",
                                    "uuid": "${json-unit.any-string}"
                                  },
                                  "vulnerability": {
                                    "vulnId": "INT-001",
                                    "source": "INTERNAL",
                                    "severity": "HIGH",
                                    "uuid": "${json-unit.any-string}"
                                  },
                                  "analyzerIdentity": "INTERNAL_ANALYZER",
                                  "attributedOn": "${json-unit.any-number}",
                                  "suppressed": false
                                },
                                {
                                  "component": {
                                    "name": "acme-lib-parent",
                                    "uuid": "${json-unit.any-string}"
                                  },
                                  "vulnerability": {
                                    "vulnId": "INT-002",
                                    "source": "INTERNAL",
                                    "severity": "LOW",
                                    "uuid": "${json-unit.any-string}"
                                  },
                                  "analyzerIdentity": "INTERNAL_ANALYZER",
                                  "attributedOn": "${json-unit.any-number}",
                                  "analysisState": "FALSE_POSITIVE",
                                  "suppressed": true
                                }
                              ]
                            }
                          },
                          "ruleId": "${json-unit.matches:ruleId}"
                        }
                        """);

        qm.getPersistenceManager().evictAll();
        assertThat(rule.getScheduleLastTriggeredAt()).isAfter(ruleLastFiredAt);
        assertThat(rule.getScheduleNextTriggerAt()).isInTheFuture();
    }

    @Test
    public void shouldDispatchPolicyViolationNotificationWhenNotLimitedToProjects() {
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

        // Create a parent project with violations for policyA and policyB, where
        //   * both violations were attributed AFTER the rule's last firing
        //   * the violation for policyB is suppressed
        final var parentProject = new Project();
        parentProject.setName("acme-app-parent");
        qm.persist(parentProject);
        final var parentProjectComponent = new Component();
        parentProjectComponent.setProject(parentProject);
        parentProjectComponent.setName("acme-lib-parent");
        parentProjectComponent.setVersion("1.0.0");
        qm.persist(parentProjectComponent);
        {
            final var policyViolationA = new PolicyViolation();
            policyViolationA.setPolicyCondition(policyConditionA);
            policyViolationA.setComponent(parentProjectComponent);
            policyViolationA.setType(PolicyViolation.Type.OPERATIONAL);
            policyViolationA.setTimestamp(Date.from(afterRuleLastFiredAt));
            qm.persist(policyViolationA);
            final var policyViolationB = new PolicyViolation();
            policyViolationB.setPolicyCondition(policyConditionB);
            policyViolationB.setComponent(parentProjectComponent);
            policyViolationB.setType(PolicyViolation.Type.SECURITY);
            policyViolationB.setTimestamp(Date.from(afterRuleLastFiredAt));
            qm.persist(policyViolationB);
            qm.makeViolationAnalysis(parentProjectComponent, policyViolationB, ViolationAnalysisState.APPROVED, true);
        }

        // Create a child project with violations for policyA and policyB, where:
        //   * the violation for policyA was attributed BEFORE the rule's last firing
        //   * the violation for policyB was attributed AFTER the rule's last firing
        final var childProject = new Project();
        childProject.setParent(parentProject);
        childProject.setName("acme-app-child");
        qm.persist(childProject);
        final var childProjectComponent = new Component();
        childProjectComponent.setProject(childProject);
        childProjectComponent.setName("acme-lib-child");
        childProjectComponent.setVersion("1.0.0");
        qm.persist(childProjectComponent);
        {
            final var policyViolationA = new PolicyViolation();
            policyViolationA.setPolicyCondition(policyConditionA);
            policyViolationA.setComponent(childProjectComponent);
            policyViolationA.setType(PolicyViolation.Type.OPERATIONAL);
            policyViolationA.setTimestamp(Date.from(beforeRuleLastFiredAt));
            qm.persist(policyViolationA);
            final var policyViolationB = new PolicyViolation();
            policyViolationB.setPolicyCondition(policyConditionB);
            policyViolationB.setComponent(childProjectComponent);
            policyViolationB.setType(PolicyViolation.Type.SECURITY);
            policyViolationB.setTimestamp(Date.from(afterRuleLastFiredAt));
            qm.persist(policyViolationB);
        }

        // Create an inactive project with violation for policyA..
        final var inactiveProject = new Project();
        inactiveProject.setName("acme-app-inactive");
        inactiveProject.setActive(false);
        qm.persist(inactiveProject);
        final var inactiveProjectComponent = new Component();
        inactiveProjectComponent.setProject(inactiveProject);
        inactiveProjectComponent.setName("acme-lib-inactive");
        qm.persist(inactiveProjectComponent);
        {
            final var policyViolationA = new PolicyViolation();
            policyViolationA.setPolicyCondition(policyConditionA);
            policyViolationA.setComponent(inactiveProjectComponent);
            policyViolationA.setType(PolicyViolation.Type.OPERATIONAL);
            policyViolationA.setTimestamp(Date.from(beforeRuleLastFiredAt));
            qm.persist(policyViolationA);
        }

        final var publisher = qm.createNotificationPublisher(
                "foo", null, WebhookPublisher.class, "template", "templateMimeType", false);
        final var rule = qm.createScheduledNotificationRule(
                "foo", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setNotifyOn(Set.of(NotificationGroup.NEW_POLICY_VIOLATIONS_SUMMARY));
        rule.setProjects(List.of(parentProject, inactiveProject));
        rule.setNotifyChildren(true);
        rule.setScheduleCron("* * * * *"); // Every minute.
        rule.setScheduleLastTriggeredAt(Date.from(ruleLastFiredAt));
        rule.updateScheduleNextTriggerAt();
        rule.setScheduleSkipUnchanged(true);
        rule.setEnabled(true);

        new ScheduledNotificationDispatchTask().inform(new ScheduledNotificationDispatchEvent());

        final Notification notification = await("Notification Dispatch")
                .atMost(3, TimeUnit.SECONDS)
                .until(NOTIFICATIONS::poll, Objects::nonNull);
        assertThat(notification).isNotNull();

        assertThat(notification.getGroup()).isEqualTo(NotificationGroup.NEW_POLICY_VIOLATIONS_SUMMARY.name());
        assertThat(notification.getScope()).isEqualTo(NotificationScope.PORTFOLIO.name());
        assertThat(notification.getLevel()).isEqualTo(NotificationLevel.INFORMATIONAL);
        assertThat(notification.getSubject()).isInstanceOf(NewPolicyViolationsSummary.class);

        assertThatJson(notification.getSubject())
                .withMatcher("ruleId", equalTo(BigDecimal.valueOf(rule.getId())))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
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
                            "suppressedNewViolationsCount": 1
                          },
                          "summary": {
                            "projectSummaries": {
                              "acme-app-parent": {
                                "newViolationsCountByType": {
                                  "OPERATIONAL": 1
                                },
                                "suppressedNewViolationsCountByType": {
                                  "SECURITY": 1
                                },
                                "totalNewViolationsCountByType": {
                                  "SECURITY": 1,
                                  "OPERATIONAL": 1
                                }
                              },
                              "acme-app-child": {
                                "newViolationsCountByType": {
                                  "SECURITY": 1
                                },
                                "suppressedNewViolationsCountByType": {},
                                "totalNewViolationsCountByType": {
                                  "SECURITY": 1
                                }
                              }
                            }
                          },
                          "details": {
                            "violationsByProject": {
                              "acme-app-parent": [
                                {
                                  "component": {
                                    "name": "acme-lib-parent",
                                    "version": "1.0.0",
                                    "uuid": "${json-unit.any-string}"
                                  },
                                  "policyCondition": {
                                    "policy": {
                                      "name": "policy-a",
                                      "violationState": "WARN",
                                      "uuid": "${json-unit.any-string}"
                                    },
                                    "operator": "IS",
                                    "subject": "VERSION",
                                    "value": "1.0.0",
                                    "uuid": "${json-unit.any-string}"
                                  },
                                  "type": "OPERATIONAL",
                                  "timestamp": "${json-unit.any-number}",
                                  "suppressed": false
                                },
                                {
                                  "component": {
                                    "name": "acme-lib-parent",
                                    "version": "1.0.0",
                                    "uuid": "${json-unit.any-string}"
                                  },
                                  "policyCondition": {
                                    "policy": {
                                      "name": "policy-b",
                                      "violationState": "WARN",
                                      "uuid": "${json-unit.any-string}"
                                    },
                                    "operator": "IS",
                                    "subject": "SEVERITY",
                                    "value": "HIGH",
                                    "uuid": "${json-unit.any-string}"
                                  },
                                  "type": "SECURITY",
                                  "timestamp": "${json-unit.any-number}",
                                  "suppressed": true
                                }
                              ],
                              "acme-app-child": [
                                {
                                  "component": {
                                    "name": "acme-lib-child",
                                    "version": "1.0.0",
                                    "uuid": "${json-unit.any-string}"
                                  },
                                  "policyCondition": {
                                    "policy": {
                                      "name": "policy-b",
                                      "violationState": "WARN",
                                      "uuid": "${json-unit.any-string}"
                                    },
                                    "operator": "IS",
                                    "subject": "SEVERITY",
                                    "value": "HIGH",
                                    "uuid": "${json-unit.any-string}"
                                  },
                                  "type": "SECURITY",
                                  "timestamp": "${json-unit.any-number}",
                                  "suppressed": false
                                }
                              ]
                            }
                          },
                          "ruleId": "${json-unit.matches:ruleId}"
                        }
                        """);
    }

    @Test
    public void shouldNotDispatchNotificationWhenNoNewFindingsAndSkipPublishIfUnchangedIsEnabled() {
        final Instant ruleLastFiredAt = Instant.now().minus(10, ChronoUnit.MINUTES);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var publisher = qm.createNotificationPublisher(
                "foo", null, WebhookPublisher.class, "template", "templateMimeType", false);
        final var rule = qm.createScheduledNotificationRule(
                "foo", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setNotifyOn(Set.of(
                NotificationGroup.NEW_VULNERABILITIES_SUMMARY,
                NotificationGroup.NEW_POLICY_VIOLATIONS_SUMMARY));
        rule.setProjects(List.of(project));
        rule.setNotifyChildren(true);
        rule.setScheduleCron("* * * * *"); // Every minute.
        rule.setScheduleLastTriggeredAt(Date.from(ruleLastFiredAt));
        rule.updateScheduleNextTriggerAt();
        rule.setScheduleSkipUnchanged(true);
        rule.setEnabled(true);

        new ScheduledNotificationDispatchTask().inform(new ScheduledNotificationDispatchEvent());

        assertThat(NOTIFICATIONS.poll()).isNull();
    }

    @Test
    public void shouldDispatchNotificationWhenNoNewFindingsAndSkipPublishIfUnchangedIsDisabled() {
        final Instant ruleLastFiredAt = Instant.now().minus(10, ChronoUnit.MINUTES);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var publisher = qm.createNotificationPublisher(
                "foo", null, WebhookPublisher.class, "template", "templateMimeType", false);
        final var rule = qm.createScheduledNotificationRule(
                "foo", NotificationScope.PORTFOLIO, NotificationLevel.INFORMATIONAL, publisher);
        rule.setNotifyOn(Set.of(
                NotificationGroup.NEW_VULNERABILITIES_SUMMARY,
                NotificationGroup.NEW_POLICY_VIOLATIONS_SUMMARY));
        rule.setProjects(List.of(project));
        rule.setNotifyChildren(true);
        rule.setScheduleCron("* * * * *"); // Every minute.
        rule.setScheduleLastTriggeredAt(Date.from(ruleLastFiredAt));
        rule.updateScheduleNextTriggerAt();
        rule.setScheduleSkipUnchanged(false);
        rule.setEnabled(true);

        new ScheduledNotificationDispatchTask().inform(new ScheduledNotificationDispatchEvent());

        await("Notification Dispatch")
                .atMost(3, TimeUnit.SECONDS)
                .untilAsserted(() -> assertThat(NOTIFICATIONS.size()).isEqualTo(2));

        assertThat(NOTIFICATIONS).satisfiesExactlyInAnyOrder(
                notification -> assertThat(notification.getGroup()).isEqualTo(NotificationGroup.NEW_VULNERABILITIES_SUMMARY.name()),
                notification -> assertThat(notification.getGroup()).isEqualTo(NotificationGroup.NEW_POLICY_VIOLATIONS_SUMMARY.name()));
    }

}