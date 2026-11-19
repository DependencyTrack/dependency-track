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

import com.google.protobuf.Any;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.NotificationTriggerType;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.notification.api.TestNotificationFactory;
import org.dependencytrack.notification.proto.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.notification.proto.v1.Group;
import org.dependencytrack.notification.proto.v1.Level;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.PolicyViolationUpdatedSubject;
import org.dependencytrack.notification.proto.v1.Scope;
import org.jdbi.v3.core.Handle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.notification.NotificationModelConverter.convert;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

class NotificationRouterTest extends PersistenceCapableTest {

    private Handle jdbiHandle;
    private NotificationRouter router;

    @BeforeEach
    void beforeEach() {
        jdbiHandle = openJdbiHandle();
        router = new NotificationRouter(jdbiHandle, new SimpleMeterRegistry());
    }

    @AfterEach
    void afterEach() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }
    }

    @Nested
    class ConstructorTest {

        @Test
        void constructorShouldThrowWhenJdbiHandleIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> new NotificationRouter(null, new SimpleMeterRegistry()))
                    .withMessage("jdbiHandle must not be null");
        }

        @Test
        void constructorShouldThrowWhenMeterRegistryIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> new NotificationRouter(jdbiHandle, null))
                    .withMessage("meterRegistry must not be null");
        }
    }

    @Nested
    class RouteTest {

        @Test
        void routeShouldThrowWhenNotificationsIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> router.route(null))
                    .withMessage("notifications must not be null");
        }

        @Test
        void routeShouldReturnEmptyListWhenNotificationsIsEmpty() {
            assertThat(router.route(Collections.emptyList())).isEmpty();
        }

        @Test
        void routeShouldMatchEnabledRules() {
            // Create a rule that is enabled.
            final var enabledRule = new NotificationRule();
            enabledRule.setTriggerType(NotificationTriggerType.EVENT);
            enabledRule.setName("A");
            enabledRule.setScope(NotificationScope.PORTFOLIO);
            enabledRule.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
            enabledRule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            enabledRule.setEnabled(true);
            qm.persist(enabledRule);

            // Create a rule that disabled.
            final var disabledRule = new NotificationRule();
            disabledRule.setTriggerType(NotificationTriggerType.EVENT);
            disabledRule.setName("B");
            disabledRule.setScope(NotificationScope.PORTFOLIO);
            disabledRule.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
            disabledRule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            disabledRule.setEnabled(false);
            qm.persist(disabledRule);

            final Notification notification = TestNotificationFactory.createBomConsumedTestNotification();

            // Only the enabled rule should have matched.
            assertThat(router.route(List.of(notification))).satisfiesExactly(result -> {
                assertThat(result.ruleNames()).containsOnly(enabledRule.getName());
                assertThat(result.notification()).isEqualTo(notification);
            });
        }

        @Test
        void routeShouldMatchRulesWithMatchingProject() throws Exception {
            final var projectA = new Project();
            projectA.setName("acme-app-a");
            qm.persist(projectA);

            final var projectB = new Project();
            projectB.setName("acme-app-b");
            qm.persist(projectB);

            // Create a rule that is limited to project A.
            final var ruleProjectA = new NotificationRule();
            ruleProjectA.setTriggerType(NotificationTriggerType.EVENT);
            ruleProjectA.setName("A");
            ruleProjectA.setScope(NotificationScope.PORTFOLIO);
            ruleProjectA.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
            ruleProjectA.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            ruleProjectA.setEnabled(true);
            ruleProjectA.setProjects(List.of(projectA));
            qm.persist(ruleProjectA);

            // Create a rule that is limited to project B.
            final var ruleProjectB = new NotificationRule();
            ruleProjectB.setTriggerType(NotificationTriggerType.EVENT);
            ruleProjectB.setName("B");
            ruleProjectB.setScope(NotificationScope.PORTFOLIO);
            ruleProjectB.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
            ruleProjectB.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            ruleProjectB.setEnabled(true);
            ruleProjectB.setProjects(List.of(projectB));
            qm.persist(ruleProjectB);

            // Create a notification for project A.
            final Notification.Builder notificationBuilder =
                    TestNotificationFactory.createBomConsumedTestNotification().toBuilder();
            final BomConsumedOrProcessedSubject.Builder subjectBuilder =
                    notificationBuilder.getSubject().unpack(BomConsumedOrProcessedSubject.class).toBuilder();
            subjectBuilder.setProject(org.dependencytrack.notification.proto.v1.Project.newBuilder()
                    .setUuid(projectA.getUuid().toString())
                    .setName(projectA.getName())
                    .build());
            final Notification notification = notificationBuilder
                    .setSubject(Any.pack(subjectBuilder.build()))
                    .build();

            // Only the rule limited to project A must have matched.
            assertThat(router.route(List.of(notification))).satisfiesExactly(result -> {
                assertThat(result.ruleNames()).containsOnly(ruleProjectA.getName());
                assertThat(result.notification()).isEqualTo(notification);
            });
        }

        @Test
        void routeShouldMatchRulesWithMatchingParentProject() throws Exception {
            final var parentProject = new Project();
            parentProject.setName("acme-app-parent");
            qm.persist(parentProject);

            final var childProject = new Project();
            childProject.setParent(parentProject);
            childProject.setName("acme-app-child");
            qm.persist(childProject);

            // Create a rule that is limited to the parent project,
            // but has the "notify children" feature ENABLED.
            final var ruleNotifyChildren = new NotificationRule();
            ruleNotifyChildren.setTriggerType(NotificationTriggerType.EVENT);
            ruleNotifyChildren.setName("A");
            ruleNotifyChildren.setScope(NotificationScope.PORTFOLIO);
            ruleNotifyChildren.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
            ruleNotifyChildren.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            ruleNotifyChildren.setEnabled(true);
            ruleNotifyChildren.setProjects(List.of(parentProject));
            ruleNotifyChildren.setNotifyChildren(true);
            qm.persist(ruleNotifyChildren);

            // Create a rule that is limited to the parent project,
            // but has the "notify children" feature DISABLED.
            final var ruleDoNotNotifyChildren = new NotificationRule();
            ruleDoNotNotifyChildren.setTriggerType(NotificationTriggerType.EVENT);
            ruleDoNotNotifyChildren.setName("B");
            ruleDoNotNotifyChildren.setScope(NotificationScope.PORTFOLIO);
            ruleDoNotNotifyChildren.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
            ruleDoNotNotifyChildren.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            ruleDoNotNotifyChildren.setEnabled(true);
            ruleDoNotNotifyChildren.setProjects(List.of(parentProject));
            ruleDoNotNotifyChildren.setNotifyChildren(false);
            qm.persist(ruleDoNotNotifyChildren);

            // Create a notification for the child project.
            final Notification.Builder notificationBuilder =
                    TestNotificationFactory.createBomConsumedTestNotification().toBuilder();
            final BomConsumedOrProcessedSubject.Builder subjectBuilder =
                    notificationBuilder.getSubject().unpack(BomConsumedOrProcessedSubject.class).toBuilder();
            subjectBuilder.setProject(org.dependencytrack.notification.proto.v1.Project.newBuilder()
                    .setUuid(childProject.getUuid().toString())
                    .setName(childProject.getName())
                    .build());
            final Notification notification = notificationBuilder
                    .setSubject(Any.pack(subjectBuilder.build()))
                    .build();

            // Only the rule with "notify children" ENABLED should have matched.
            assertThat(router.route(List.of(notification))).satisfiesExactly(result -> {
                assertThat(result.ruleNames()).containsOnly(ruleNotifyChildren.getName());
                assertThat(result.notification()).isEqualTo(notification);
            });
        }

        @Test
        void routeShouldMatchRulesWithMatchingProjectTags() throws Exception {
            final var tagA = qm.persist(new Tag("a"));
            final var tagB = qm.persist(new Tag("b"));

            // Create a project tagged with tag A.
            final var project = new Project();
            project.setName("acme-app");
            project.setTags(Set.of(tagA));
            qm.persist(project);

            // Create a rule limited to tag A.
            final var ruleTagA = new NotificationRule();
            ruleTagA.setTriggerType(NotificationTriggerType.EVENT);
            ruleTagA.setName("A");
            ruleTagA.setScope(NotificationScope.PORTFOLIO);
            ruleTagA.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
            ruleTagA.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            ruleTagA.setEnabled(true);
            ruleTagA.setTags(Set.of(tagA));
            qm.persist(ruleTagA);

            // Create a rule limited to tag B.
            final var ruleTagB = new NotificationRule();
            ruleTagB.setTriggerType(NotificationTriggerType.EVENT);
            ruleTagB.setName("B");
            ruleTagB.setScope(NotificationScope.PORTFOLIO);
            ruleTagB.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
            ruleTagB.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            ruleTagB.setEnabled(true);
            ruleTagB.setTags(Set.of(tagB));
            qm.persist(ruleTagB);

            // Create a notification for the project tagged with tag A.
            final Notification.Builder notificationBuilder =
                    TestNotificationFactory.createBomConsumedTestNotification().toBuilder();
            final BomConsumedOrProcessedSubject.Builder subjectBuilder =
                    notificationBuilder.getSubject().unpack(BomConsumedOrProcessedSubject.class).toBuilder();
            subjectBuilder.setProject(org.dependencytrack.notification.proto.v1.Project.newBuilder()
                    .setUuid(project.getUuid().toString())
                    .setName(project.getName())
                    .addTags(tagA.getName())
                    .build());
            final Notification notification = notificationBuilder
                    .setSubject(Any.pack(subjectBuilder.build()))
                    .build();

            // Only the rule limited to tag A must have matched.
            assertThat(router.route(List.of(notification))).satisfiesExactly(result -> {
                assertThat(result.ruleNames()).containsOnly(ruleTagA.getName());
                assertThat(result.notification()).isEqualTo(notification);
            });
        }

        @Test
        void routeShouldMatchMultipleRules() {
            final var ruleA = new NotificationRule();
            ruleA.setTriggerType(NotificationTriggerType.EVENT);
            ruleA.setName("A");
            ruleA.setScope(NotificationScope.PORTFOLIO);
            ruleA.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
            ruleA.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            ruleA.setEnabled(true);
            qm.persist(ruleA);

            final var ruleB = new NotificationRule();
            ruleB.setTriggerType(NotificationTriggerType.EVENT);
            ruleB.setName("B");
            ruleB.setScope(NotificationScope.PORTFOLIO);
            ruleB.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
            ruleB.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            ruleB.setEnabled(true);
            qm.persist(ruleB);

            final Notification notification = TestNotificationFactory.createBomConsumedTestNotification();

            assertThat(router.route(List.of(notification))).satisfiesExactlyInAnyOrder(result -> {
                assertThat(result.ruleNames()).containsOnly(ruleA.getName(), ruleB.getName());
                assertThat(result.notification()).isEqualTo(notification);
            });
        }

        @SuppressWarnings("unused")
        private static List<Notification> routeShouldHandleAllNotificationTypesParams() {
            final var notifications = new ArrayList<Notification>();

            for (final var scope : Scope.values()) {
                for (final var group : Group.values()) {
                    for (final var level : Level.values()) {
                        final Notification notification =
                                TestNotificationFactory.createTestNotification(scope, group, level);
                        if (notification != null) {
                            notifications.add(notification);
                        }
                    }
                }
            }

            return notifications;
        }

        @ParameterizedTest
        @MethodSource("routeShouldHandleAllNotificationTypesParams")
        void routeShouldHandleAllNotificationTypes(final Notification notification) {
            final var rule = new NotificationRule();
            rule.setTriggerType(NotificationTriggerType.EVENT);
            rule.setName("foo");
            rule.setScope(convert(notification.getScope()));
            rule.setNotifyOn(Set.of(convert(notification.getGroup())));
            rule.setNotificationLevel(convert(notification.getLevel()));
            rule.setEnabled(true);
            qm.persist(rule);

            assertThat(router.route(List.of(notification))).satisfiesExactly(result -> {
                assertThat(result.ruleNames()).containsOnly(rule.getName());
                assertThat(result.notification()).isEqualTo(notification);
            });
        }
    }

    @Test
    void shouldRequireIndependentUpdateSubscription() {
        final var legacyRule = new NotificationRule();
        legacyRule.setName("creation-only");
        legacyRule.setTriggerType(NotificationTriggerType.EVENT);
        legacyRule.setScope(NotificationScope.PORTFOLIO);
        legacyRule.setNotifyOn(Set.of(NotificationGroup.POLICY_VIOLATION));
        legacyRule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        legacyRule.setEnabled(true);
        qm.persist(legacyRule);

        final Notification updated = TestNotificationFactory.createPolicyViolationUpdatedTestNotification();
        assertThat(router.route(List.of(updated))).isEmpty();

        final var updateRule = new NotificationRule();
        updateRule.setName("updates");
        updateRule.setTriggerType(NotificationTriggerType.EVENT);
        updateRule.setScope(NotificationScope.PORTFOLIO);
        updateRule.setNotifyOn(Set.of(NotificationGroup.POLICY_VIOLATION_UPDATED));
        updateRule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        updateRule.setEnabled(true);
        updateRule.setFilterExpression("group == Group.GROUP_POLICY_VIOLATION_UPDATED"
                + " && subject.previous_message == 'CVE-2021-44228'"
                + " && subject.current_message.contains('CVE-2021-45046')");
        qm.persist(updateRule);

        final var filteredRule = new NotificationRule();
        filteredRule.setName("filtered-out");
        filteredRule.setTriggerType(NotificationTriggerType.EVENT);
        filteredRule.setScope(NotificationScope.PORTFOLIO);
        filteredRule.setNotifyOn(Set.of(NotificationGroup.POLICY_VIOLATION_UPDATED));
        filteredRule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        filteredRule.setEnabled(true);
        filteredRule.setFilterExpression("subject.current_message == 'unmatched'");
        qm.persist(filteredRule);

        assertThat(router.route(List.of(updated))).satisfiesExactly(result -> {
            assertThat(result.ruleNames()).containsOnly("updates");
            assertThat(result.notification()).isEqualTo(updated);
        });
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void shouldApplyDocumentedOptionalFieldFiltersWithoutMatchingAbsentValues(boolean reviewed) throws Exception {
        final Notification notification = reviewed
                ? TestNotificationFactory.createReviewedPolicyViolationUpdatedTestNotification()
                : TestNotificationFactory.createPolicyViolationUpdatedTestNotification();
        final var expressions = List.of(
                "has(subject.current_message) && subject.current_message.contains('CVE-2021-45046')",
                "has(subject.analysis_state) && subject.analysis_state == 'APPROVED'",
                "has(subject.suppressed) && subject.suppressed");
        final var names = List.of("current-message", "approved", "suppressed");
        for (int index = 0; index < expressions.size(); index++) {
            final var rule = new NotificationRule();
            rule.setName(names.get(index));
            rule.setTriggerType(NotificationTriggerType.EVENT);
            rule.setScope(NotificationScope.PORTFOLIO);
            rule.setNotifyOn(Set.of(convert(notification.getGroup())));
            rule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            rule.setEnabled(true);
            rule.setFilterExpression(expressions.get(index));
            qm.persist(rule);
        }
        assertThat(router.route(List.of(notification)))
                .satisfiesExactly(result -> assertThat(result.ruleNames())
                        .containsExactlyInAnyOrderElementsOf(reviewed ? names : List.of("current-message")));

        final var absent = notification.getSubject().unpack(PolicyViolationUpdatedSubject.class).toBuilder()
                .clearCurrentMessage()
                .clearAnalysisState()
                .clearSuppressed()
                .build();
        assertThat(router.route(List.of(
                        notification.toBuilder().setSubject(Any.pack(absent)).build())))
                .isEmpty();
        if (reviewed) {
            final var unsuppressed = notification.getSubject().unpack(PolicyViolationUpdatedSubject.class).toBuilder()
                    .setSuppressed(false)
                    .build();
            assertThat(router.route(List.of(notification.toBuilder()
                            .setSubject(Any.pack(unsuppressed))
                            .build())))
                    .satisfiesExactly(result ->
                            assertThat(result.ruleNames()).containsExactlyInAnyOrder("current-message", "approved"));
        }
    }

    @Test
    void shouldApplyProjectAndTagLimitsToUpdates() throws Exception {
        final var tag = qm.persist(new Tag("selected"));
        final var project = new Project();
        project.setName("selected-project");
        project.setTags(Set.of(tag));
        qm.persist(project);
        final var otherProject = new Project();
        otherProject.setName("other-project");
        qm.persist(otherProject);

        final var allowed = new NotificationRule();
        allowed.setName("allowed");
        allowed.setTriggerType(NotificationTriggerType.EVENT);
        allowed.setScope(NotificationScope.PORTFOLIO);
        allowed.setNotifyOn(Set.of(NotificationGroup.POLICY_VIOLATION_UPDATED));
        allowed.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        allowed.setEnabled(true);
        allowed.setProjects(List.of(project));
        allowed.setTags(Set.of(tag));
        qm.persist(allowed);
        final var denied = new NotificationRule();
        denied.setName("other-project");
        denied.setTriggerType(NotificationTriggerType.EVENT);
        denied.setScope(NotificationScope.PORTFOLIO);
        denied.setNotifyOn(Set.of(NotificationGroup.POLICY_VIOLATION_UPDATED));
        denied.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        denied.setEnabled(true);
        denied.setProjects(List.of(otherProject));
        qm.persist(denied);

        final var builder = TestNotificationFactory.createPolicyViolationUpdatedTestNotification().toBuilder();
        final var subject = builder.getSubject().unpack(PolicyViolationUpdatedSubject.class).toBuilder()
                .setProject(convert(project))
                .build();
        final Notification updated = builder.setSubject(Any.pack(subject)).build();

        assertThat(router.route(List.of(updated))).satisfiesExactly(result -> {
            assertThat(result.ruleNames()).containsOnly("allowed");
        });
    }

    @Test
    void shouldRequireExplicitReviewedSubscriptionEvenWhenOrdinaryFilterFailsOpen() {
        final var ordinary = new NotificationRule();
        ordinary.setName("ordinary-updates");
        ordinary.setTriggerType(NotificationTriggerType.EVENT);
        ordinary.setScope(NotificationScope.PORTFOLIO);
        ordinary.setNotifyOn(Set.of(NotificationGroup.POLICY_VIOLATION_UPDATED));
        ordinary.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        ordinary.setEnabled(true);
        ordinary.setFilterExpression("this is not valid CEL");
        qm.persist(ordinary);
        final Notification reviewed = TestNotificationFactory.createReviewedPolicyViolationUpdatedTestNotification();
        assertThat(router.route(List.of(reviewed))).isEmpty();

        final var optIn = new NotificationRule();
        optIn.setName("reviewed-opt-in");
        optIn.setTriggerType(NotificationTriggerType.EVENT);
        optIn.setScope(NotificationScope.PORTFOLIO);
        optIn.setNotifyOn(Set.of(NotificationGroup.POLICY_VIOLATION_UPDATED_REVIEWED));
        optIn.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        optIn.setEnabled(true);
        optIn.setFilterExpression("group == Group.GROUP_POLICY_VIOLATION_UPDATED_REVIEWED"
                + " && subject.analysis_state == 'APPROVED' && subject.suppressed"
                + " && subject.current_message.contains('CVE-2021-45046')");
        qm.persist(optIn);
        assertThat(router.route(List.of(reviewed))).satisfiesExactly(result -> {
            assertThat(result.ruleNames()).containsOnly("reviewed-opt-in");
            assertThat(result.notification()).isEqualTo(reviewed);
        });
        assertThat(router.route(List.of(TestNotificationFactory.createPolicyViolationUpdatedTestNotification())))
                .satisfiesExactly(result -> assertThat(result.ruleNames()).containsOnly("ordinary-updates"));
    }

    @Test
    void shouldApplyProjectAndTagLimitsToReviewedUpdates() throws Exception {
        final var tag = qm.persist(new Tag("reviewed-selected"));
        final var project = new Project();
        project.setName("reviewed-project");
        project.setTags(Set.of(tag));
        qm.persist(project);
        final var other = new Project();
        other.setName("other-reviewed-project");
        qm.persist(other);
        final var allowed = new NotificationRule();
        allowed.setName("reviewed-project-opt-in");
        allowed.setTriggerType(NotificationTriggerType.EVENT);
        allowed.setScope(NotificationScope.PORTFOLIO);
        allowed.setNotifyOn(Set.of(NotificationGroup.POLICY_VIOLATION_UPDATED_REVIEWED));
        allowed.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        allowed.setEnabled(true);
        allowed.setProjects(List.of(project));
        allowed.setTags(Set.of(tag));
        qm.persist(allowed);
        final var denied = new NotificationRule();
        denied.setName("other-reviewed-project-opt-in");
        denied.setTriggerType(NotificationTriggerType.EVENT);
        denied.setScope(NotificationScope.PORTFOLIO);
        denied.setNotifyOn(Set.of(NotificationGroup.POLICY_VIOLATION_UPDATED_REVIEWED));
        denied.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        denied.setEnabled(true);
        denied.setProjects(List.of(other));
        qm.persist(denied);
        final var builder = TestNotificationFactory.createReviewedPolicyViolationUpdatedTestNotification().toBuilder();
        final var subject = builder.getSubject().unpack(PolicyViolationUpdatedSubject.class).toBuilder()
                .setProject(convert(project))
                .build();
        final Notification reviewed = builder.setSubject(Any.pack(subject)).build();
        assertThat(router.route(List.of(reviewed)))
                .satisfiesExactly(result -> assertThat(result.ruleNames()).containsOnly("reviewed-project-opt-in"));
        allowed.setEnabled(false);
        qm.persist(allowed);
        assertThat(router.route(List.of(reviewed))).isEmpty();
    }

    @Nested
    class FilterExpressionTest {

        @Test
        void shouldMatchWhenFilterExpressionEvaluatesToTrue() {
            final var rule = new NotificationRule();
            rule.setName("rule");
            rule.setScope(NotificationScope.PORTFOLIO);
            rule.setNotifyOn(Set.of(NotificationGroup.NEW_VULNERABILITY));
            rule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            rule.setEnabled(true);
            rule.setTriggerType(NotificationTriggerType.EVENT);
            rule.setFilterExpression("subject.vulnerability.severity == \"MEDIUM\"");
            qm.persist(rule);

            final Notification notification = TestNotificationFactory.createNewVulnerabilityTestNotification();

            assertThat(router.route(List.of(notification))).satisfiesExactly(result -> {
                assertThat(result.ruleNames()).containsOnly(rule.getName());
                assertThat(result.notification()).isEqualTo(notification);
            });
        }

        @Test
        void shouldNotMatchWhenFilterExpressionEvaluatesToFalse() {
            final var rule = new NotificationRule();
            rule.setName("rule");
            rule.setScope(NotificationScope.PORTFOLIO);
            rule.setNotifyOn(Set.of(NotificationGroup.NEW_VULNERABILITY));
            rule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            rule.setEnabled(true);
            rule.setTriggerType(NotificationTriggerType.EVENT);
            rule.setFilterExpression("subject.vulnerability.severity == \"CRITICAL\"");
            qm.persist(rule);

            final Notification notification = TestNotificationFactory.createNewVulnerabilityTestNotification();

            assertThat(router.route(List.of(notification))).isEmpty();
        }

        @Test
        void shouldFilterOnNotificationLevel() {
            final var rule = new NotificationRule();
            rule.setName("rule");
            rule.setScope(NotificationScope.PORTFOLIO);
            rule.setNotifyOn(Set.of(NotificationGroup.NEW_VULNERABILITY));
            rule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            rule.setEnabled(true);
            rule.setTriggerType(NotificationTriggerType.EVENT);
            rule.setFilterExpression("level == Level.LEVEL_INFORMATIONAL");
            qm.persist(rule);

            final Notification notification = TestNotificationFactory.createNewVulnerabilityTestNotification();

            assertThat(router.route(List.of(notification)))
                    .satisfiesExactly(result -> assertThat(result.ruleNames()).containsOnly(rule.getName()));
        }

        @Test
        void shouldFilterOnSubjectProjectName() {
            final var rule = new NotificationRule();
            rule.setName("rule");
            rule.setScope(NotificationScope.PORTFOLIO);
            rule.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
            rule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            rule.setEnabled(true);
            rule.setTriggerType(NotificationTriggerType.EVENT);
            rule.setFilterExpression("subject.project.name.startsWith(\"project\")");
            qm.persist(rule);

            final Notification notification = TestNotificationFactory.createBomConsumedTestNotification();

            assertThat(router.route(List.of(notification)))
                    .satisfiesExactly(result -> assertThat(result.ruleNames()).containsOnly(rule.getName()));
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void shouldFilterOnSubjectProjectLatestStatus(boolean isLatest) throws Exception {
            final var rule = new NotificationRule();
            rule.setName("rule");
            rule.setScope(NotificationScope.PORTFOLIO);
            rule.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
            rule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            rule.setEnabled(true);
            rule.setTriggerType(NotificationTriggerType.EVENT);
            rule.setFilterExpression("subject.project.is_latest == true");
            qm.persist(rule);

            final var project = new Project();
            project.setName("projectName");
            project.setIsLatest(isLatest);
            qm.persist(project);

            final var notificationBuilder = TestNotificationFactory.createBomConsumedTestNotification().toBuilder();
            final var subject = notificationBuilder.getSubject().unpack(BomConsumedOrProcessedSubject.class).toBuilder()
                    .setProject(convert(project))
                    .build();
            final var notification =
                    notificationBuilder.setSubject(Any.pack(subject)).build();

            if (isLatest) {
                assertThat(router.route(List.of(notification))).satisfiesExactly(result -> {
                    assertThat(result.ruleNames()).containsOnly(rule.getName());
                    assertThat(result.notification()).isEqualTo(notification);
                });
            } else {
                assertThat(router.route(List.of(notification))).isEmpty();
            }
        }

        @Test
        void shouldFailOpenOnInvalidFilterExpression() {
            final var rule = new NotificationRule();
            rule.setName("rule");
            rule.setScope(NotificationScope.PORTFOLIO);
            rule.setNotifyOn(Set.of(NotificationGroup.NEW_VULNERABILITY));
            rule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            rule.setEnabled(true);
            rule.setTriggerType(NotificationTriggerType.EVENT);
            rule.setFilterExpression("this is not valid CEL");
            qm.persist(rule);

            final Notification notification = TestNotificationFactory.createNewVulnerabilityTestNotification();

            assertThat(router.route(List.of(notification)))
                    .satisfiesExactly(result -> assertThat(result.ruleNames()).containsOnly(rule.getName()));
        }

        @Test
        void shouldFailOpenOnFilterRuntimeError() {
            // Create a rule with invalid filter expression,
            // i.e. an expression accessing fields that are not available.
            final var invalidRule = new NotificationRule();
            invalidRule.setName("expression-runtime-error");
            invalidRule.setScope(NotificationScope.PORTFOLIO);
            invalidRule.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
            invalidRule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            invalidRule.setEnabled(true);
            invalidRule.setTriggerType(NotificationTriggerType.EVENT);
            invalidRule.setFilterExpression("subject.nonExistentField == \"whatever\"");
            qm.persist(invalidRule);

            // Also create a rule with valid expression that evaluates to false,
            // to confirm that fail-open is actually triggered.
            final var validRule = new NotificationRule();
            validRule.setName("expression-valid-false");
            validRule.setScope(NotificationScope.PORTFOLIO);
            validRule.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
            validRule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            validRule.setEnabled(true);
            validRule.setTriggerType(NotificationTriggerType.EVENT);
            validRule.setFilterExpression("subject.project.name == \"nonexistent\"");
            qm.persist(validRule);

            final Notification notification = TestNotificationFactory.createBomConsumedTestNotification();

            assertThat(router.route(List.of(notification)))
                    .satisfiesExactly(result -> assertThat(result.ruleNames()).containsOnly(invalidRule.getName()));
        }

        @Test
        void shouldApplyProjectFilterBeforeFilterExpression() throws Exception {
            final var project = new Project();
            project.setName("acme-app");
            qm.persist(project);

            final var otherProject = new Project();
            otherProject.setName("other-app");
            qm.persist(otherProject);

            // Rule is limited to otherProject, but expression would match.
            final var rule = new NotificationRule();
            rule.setName("rule");
            rule.setScope(NotificationScope.PORTFOLIO);
            rule.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
            rule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            rule.setEnabled(true);
            rule.setTriggerType(NotificationTriggerType.EVENT);
            rule.setProjects(List.of(otherProject));
            rule.setFilterExpression("true");
            qm.persist(rule);

            // Notification is for project, not otherProject.
            final Notification.Builder notificationBuilder =
                    TestNotificationFactory.createBomConsumedTestNotification().toBuilder();
            final Notification notification = notificationBuilder
                    .setSubject(Any.pack(
                            notificationBuilder.getSubject().unpack(BomConsumedOrProcessedSubject.class).toBuilder()
                                    .setProject(org.dependencytrack.notification.proto.v1.Project.newBuilder()
                                            .setUuid(project.getUuid().toString())
                                            .setName(project.getName())
                                            .build())
                                    .build()))
                    .build();

            assertThat(router.route(List.of(notification))).isEmpty();
        }

        @Test
        void shouldNotApplyFilterExpressionWhenExpressionIsBlank() {
            final var rule = new NotificationRule();
            rule.setName("rule");
            rule.setScope(NotificationScope.PORTFOLIO);
            rule.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
            rule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
            rule.setEnabled(true);
            rule.setTriggerType(NotificationTriggerType.EVENT);
            rule.setFilterExpression("   ");
            qm.persist(rule);

            final Notification notification = TestNotificationFactory.createBomConsumedTestNotification();

            assertThat(router.route(List.of(notification)))
                    .satisfiesExactly(result -> assertThat(result.ruleNames()).containsOnly(rule.getName()));
        }
    }
}
