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
package org.dependencytrack.policy.cel.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.notification.JdbiNotificationEmitter;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.policy.cel.persistence.CelPolicyDao.ViolationChanges;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.transaction.TransactionIsolationLevel;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.notification.NotificationTestUtil.createCatchAllNotificationRule;
import static org.dependencytrack.notification.NotificationTestUtil.getNotificationOutbox;
import static org.dependencytrack.notification.api.TestNotificationFactory.createPolicyViolationUpdatedTestNotification;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class CelPolicyViolationChangesTest extends PersistenceCapableTest {

    private record Fixture(long projectId, long componentId, PolicyCondition condition) {}

    private record Contention(ViolationChanges first, ViolationChanges second) {}

    @Test
    void shouldDeleteAndRecreateWithNewIdentity() {
        final var fixture = fixture("one");
        final var first = reconcile(fixture, "A");
        final long originalId = first.createdIds().iterator().next();
        final var removed = inJdbiTransaction(
                handle -> new CelPolicyDao(handle).reconcileViolationChanges(fixture.projectId(), Map.of()));
        assertThat(removed.createdIds()).isEmpty();
        assertThat(removed.updatedById()).isEmpty();
        assertThat(countViolations(fixture.projectId())).isZero();
        final var restored = reconcile(fixture, "B");
        assertThat(restored.createdIds()).hasSize(1).doesNotContain(originalId);
        assertThat(restored.updatedById()).isEmpty();
    }

    @Test
    void shouldReconcileMultipleComponentsAndPoliciesWithoutTouchingAnotherProject() {
        final var first = fixture("first");
        final var other = fixture("other");
        final var secondComponent = new Component();
        secondComponent.setProject(qm.getObjectById(Project.class, first.projectId()));
        secondComponent.setName("second");
        qm.persist(secondComponent);
        final var secondPolicy = qm.createPolicy("second", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        final var secondCondition = condition(secondPolicy);
        final var samePolicyCondition = condition(first.condition().getPolicy());
        final var reports = Map.of(
                first.componentId(),
                        List.of(
                                violation(first.condition(), "A"),
                                violation(secondCondition, "A"),
                                violation(samePolicyCondition, "A")),
                secondComponent.getId(), List.of(violation(first.condition(), "A")));
        assertThat(reconcile(other, "untouched").createdIds()).hasSize(1);
        assertThat(inJdbiTransaction(handle ->
                                new CelPolicyDao(handle).reconcileViolationChanges(first.projectId(), reports))
                        .createdIds())
                .hasSize(4);
        reports.values().forEach(violations -> violations.forEach(violation -> violation.setText("A,B")));
        final var changed = inJdbiTransaction(
                handle -> new CelPolicyDao(handle).reconcileViolationChanges(first.projectId(), reports));
        assertThat(changed.createdIds()).isEmpty();
        assertThat(changed.updatedById()).hasSize(4);
        assertThat(changed.updatedById().values()).allSatisfy(change -> {
            assertThat(change.previousMessage()).isEqualTo("A");
            assertThat(change.currentMessage()).isEqualTo("A,B");
            assertThat(change.uuid()).isNotNull();
            assertThat(change.changedAt()).isNotNull();
        });
        assertThat(reconcile(other, "untouched").updatedById()).isEmpty();
        assertThat(countViolations(other.projectId())).isEqualTo(1);
    }

    @Test
    void shouldSerializeConcurrentIdenticalInitialReports() throws Exception {
        final var fixture = fixture("initial");
        final var changes = contend(fixture, reports(fixture, "A"), reports(fixture, "A"));
        assertThat(changes.first().createdIds()).hasSize(1);
        assertThat(changes.second().createdIds()).isEmpty();
        assertThat(changes.second().updatedById()).isEmpty();
        assertThat(countViolations(fixture.projectId())).isEqualTo(1);
    }

    @Test
    void shouldSerializeConcurrentIdenticalUpdates() throws Exception {
        final var fixture = fixture("same-update");
        final long id = reconcile(fixture, "A").createdIds().iterator().next();
        final var changes = contend(fixture, reports(fixture, "A,B"), reports(fixture, "A,B"));
        assertThat(changes.first().updatedById()).containsOnlyKeys(id);
        assertThat(changes.second().createdIds()).isEmpty();
        assertThat(changes.second().updatedById()).isEmpty();
        assertThat(message(id)).isEqualTo("A,B");
    }

    @Test
    void shouldReadCommittedPredecessorAfterConcurrentUpdate() throws Exception {
        final var fixture = fixture("different-update");
        final long id = reconcile(fixture, "A").createdIds().iterator().next();
        final var changes = contend(fixture, reports(fixture, "A,B"), reports(fixture, "A,B,C"));
        assertThat(changes.first().updatedById().get(id).previousMessage()).isEqualTo("A");
        final var second = changes.second().updatedById().get(id);
        assertThat(second.previousMessage()).isEqualTo("A,B");
        assertThat(second.currentMessage()).isEqualTo("A,B,C");
        assertThat(second.uuid())
                .isEqualTo(changes.first().updatedById().get(id).uuid());
        assertThat(message(id)).isEqualTo("A,B,C");
    }

    @Test
    void shouldReadCommittedPredecessorAfterConcurrentInsert() throws Exception {
        final var fixture = fixture("concurrent-insert");
        final var changes = contend(fixture, reports(fixture, "A,B"), reports(fixture, "A,B,C"));
        final long id = changes.first().createdIds().iterator().next();
        assertThat(changes.second().createdIds()).isEmpty();
        assertThat(changes.second().updatedById()).containsOnlyKeys(id);
        assertThat(changes.second().updatedById().get(id).previousMessage()).isEqualTo("A,B");
        assertThat(changes.second().updatedById().get(id).currentMessage()).isEqualTo("A,B,C");
    }

    @Test
    void shouldSerializeDeletionAndConcurrentReappearance() throws Exception {
        final var fixture = fixture("delete-update");
        final long originalId = reconcile(fixture, "A").createdIds().iterator().next();
        final var changes = contend(fixture, Map.of(), reports(fixture, "B"));
        assertThat(changes.second().createdIds()).hasSize(1).doesNotContain(originalId);
        assertThat(changes.second().updatedById()).isEmpty();
        assertThat(countViolations(fixture.projectId())).isEqualTo(1);
    }

    @Test
    void shouldAllowDifferentProjectsToReconcileConcurrently() throws Exception {
        final var first = fixture("parallel-one");
        final var second = fixture("parallel-two");
        try (final var executor = Executors.newSingleThreadExecutor();
                final var handle = openJdbiHandle()) {
            handle.begin();
            try {
                new CelPolicyDao(handle).reconcileViolationChanges(first.projectId(), reports(first, "A"));
                final var future = executor.submit(() -> reconcile(second, "B"));
                assertThat(future.get(5, TimeUnit.SECONDS).createdIds()).hasSize(1);
                handle.commit();
            } finally {
                if (handle.isInTransaction()) {
                    handle.rollback();
                }
            }
        }
        assertThat(countViolations(first.projectId())).isEqualTo(1);
        assertThat(countViolations(second.projectId())).isEqualTo(1);
    }

    @Test
    void shouldDeleteWhenComponentHasNoReportedConditions() {
        final var fixture = fixture("empty-conditions");
        reconcile(fixture, "A");
        final var changes = inJdbiTransaction(handle -> new CelPolicyDao(handle)
                .reconcileViolationChanges(fixture.projectId(), Map.of(fixture.componentId(), List.of())));
        assertThat(changes.createdIds()).isEmpty();
        assertThat(changes.updatedById()).isEmpty();
        assertThat(countViolations(fixture.projectId())).isZero();
    }

    @Test
    void shouldRollBackMessageAndDurableNotificationTogether() {
        final var fixture = fixture("rollback");
        final long id = reconcile(fixture, "A").createdIds().iterator().next();
        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);
        assertThatThrownBy(() -> inJdbiTransaction(handle -> {
                    final var changes = new CelPolicyDao(handle)
                            .reconcileViolationChanges(fixture.projectId(), reports(fixture, "A,B"));
                    assertThat(changes.updatedById()).containsOnlyKeys(id);
                    new JdbiNotificationEmitter(handle).emit(createPolicyViolationUpdatedTestNotification());
                    assertThat(handle.createQuery("SELECT COUNT(*) FROM \"NOTIFICATION_OUTBOX\"")
                                    .mapTo(Integer.class)
                                    .one())
                            .isEqualTo(1);
                    throw new IllegalStateException("controlled rollback");
                }))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("controlled rollback");
        assertThat(message(id)).isEqualTo("A");
        assertThat(getNotificationOutbox()).isEmpty();
        assertThat(reconcile(fixture, "A,B").updatedById().get(id).previousMessage())
                .isEqualTo("A");
    }

    @Test
    void shouldRollBackDuplicateIdentityConflict() {
        final var fixture = fixture("conflict");
        final long id = reconcile(fixture, "A").createdIds().iterator().next();
        assertThatThrownBy(() -> inJdbiTransaction(handle -> new CelPolicyDao(handle)
                        .reconcileViolationChanges(
                                fixture.projectId(),
                                Map.of(
                                        fixture.componentId(),
                                        List.of(
                                                violation(fixture.condition(), "B"),
                                                violation(fixture.condition(), "C"))))))
                .isInstanceOf(org.jdbi.v3.core.statement.UnableToExecuteStatementException.class);
        assertThat(message(id)).isEqualTo("A");
        assertThat(countViolations(fixture.projectId())).isEqualTo(1);
    }

    @Test
    void shouldRejectMissingTransactionAndUnsupportedIsolation() {
        final var fixture = fixture("isolation");
        try (final var handle = openJdbiHandle()) {
            assertThatThrownBy(() -> new CelPolicyDao(handle)
                            .reconcileViolationChanges(fixture.projectId(), reports(fixture, "A")))
                    .isInstanceOf(IllegalStateException.class);
            handle.setTransactionIsolation(TransactionIsolationLevel.REPEATABLE_READ);
            handle.begin();
            try {
                assertThatThrownBy(() -> new CelPolicyDao(handle)
                                .reconcileViolationChanges(fixture.projectId(), reports(fixture, "A")))
                        .isInstanceOf(IllegalStateException.class);
            } finally {
                handle.rollback();
            }
        }
        assertThat(countViolations(fixture.projectId())).isZero();
    }

    @Test
    void shouldMeasureActualBulkDaoAtOneAndTenThousandComponents() {
        for (final int size : List.of(1_000, 10_000)) {
            final var fixture = fixture("benchmark-" + size);
            final List<Long> componentIds = inJdbiTransaction(handle -> handle.createQuery("""
                            INSERT INTO "COMPONENT" ("PROJECT_ID", "NAME", "UUID")
                            SELECT :projectId, 'benchmark-' || i, gen_random_uuid()
                              FROM generate_series(1, :size) i RETURNING "ID"
                            """)
                    .bind("projectId", fixture.projectId())
                    .bind("size", size)
                    .mapTo(Long.class)
                    .list());
            final var input = new HashMap<Long, List<PolicyViolation>>();
            componentIds.forEach(id -> input.put(id, List.of(violation(fixture.condition(), "A"))));
            final var inserted = measured(fixture.projectId(), size, "insert", input);
            assertThat(inserted.createdIds()).hasSize(size);
            assertThat(inserted.updatedById()).isEmpty();
            for (int iteration = 1; iteration <= 3; iteration++) {
                final var unchanged = measured(fixture.projectId(), size, "unchanged-" + iteration, input);
                assertThat(unchanged.createdIds()).isEmpty();
                assertThat(unchanged.updatedById()).isEmpty();
            }
            input.values().forEach(violations -> violations.getFirst().setText("A,B"));
            final var changed = measured(fixture.projectId(), size, "changed", input);
            assertThat(changed.createdIds()).isEmpty();
            assertThat(changed.updatedById()).hasSize(size);
            assertThat(changed.updatedById().values()).allSatisfy(change -> {
                assertThat(change.previousMessage()).isEqualTo("A");
                assertThat(change.currentMessage()).isEqualTo("A,B");
            });
            assertThat(countViolations(fixture.projectId())).isEqualTo(size);
        }
    }

    private ViolationChanges measured(long projectId, int size, String phase, Map<Long, List<PolicyViolation>> input) {
        final long start = System.nanoTime();
        final var changes =
                inJdbiTransaction(handle -> new CelPolicyDao(handle).reconcileViolationChanges(projectId, input));
        System.out.printf(
                "DAO_BENCHMARK rows=%d phase=%s elapsed_ms=%.3f created=%d updated=%d%n",
                size,
                phase,
                (System.nanoTime() - start) / 1_000_000.0,
                changes.createdIds().size(),
                changes.updatedById().size());
        return changes;
    }

    private Contention contend(
            Fixture fixture, Map<Long, List<PolicyViolation>> firstInput, Map<Long, List<PolicyViolation>> secondInput)
            throws Exception {
        try (final var executor = Executors.newSingleThreadExecutor();
                final Handle firstHandle = openJdbiHandle()) {
            firstHandle.begin();
            try {
                final var first =
                        new CelPolicyDao(firstHandle).reconcileViolationChanges(fixture.projectId(), firstInput);
                final var secondPid = new CompletableFuture<Integer>();
                final var secondFuture = executor.submit(() -> inJdbiTransaction(handle -> {
                    handle.execute("SET LOCAL lock_timeout = '10s'");
                    secondPid.complete(handle.createQuery("SELECT pg_backend_pid()")
                            .mapTo(Integer.class)
                            .one());
                    return new CelPolicyDao(handle).reconcileViolationChanges(fixture.projectId(), secondInput);
                }));
                final int pid = secondPid.get(5, TimeUnit.SECONDS);
                // Observe an actual PostgreSQL lock wait; no timing-only sleep or mock synchronization.
                await("second reconciliation waits on the first project's row lock")
                        .atMost(5, TimeUnit.SECONDS)
                        .until(() -> firstHandle
                                .createQuery("SELECT cardinality(pg_blocking_pids(:pid)) > 0")
                                .bind("pid", pid)
                                .mapTo(Boolean.class)
                                .one());
                firstHandle.commit();
                return new Contention(first, secondFuture.get(10, TimeUnit.SECONDS));
            } finally {
                if (firstHandle.isInTransaction()) {
                    firstHandle.rollback();
                }
            }
        }
    }

    private Fixture fixture(String name) {
        final var project = new Project();
        project.setName(name);
        qm.persist(project);
        final var component = new Component();
        component.setName(name);
        component.setProject(project);
        qm.persist(component);
        final var policy = qm.createPolicy(name, Policy.Operator.ANY, Policy.ViolationState.FAIL);
        return new Fixture(project.getId(), component.getId(), condition(policy));
    }

    private PolicyCondition condition(Policy policy) {
        return qm.createPolicyCondition(
                policy,
                PolicyCondition.Subject.EXPRESSION,
                PolicyCondition.Operator.MATCHES,
                "true",
                PolicyViolation.Type.SECURITY);
    }

    private static PolicyViolation violation(PolicyCondition condition, String text) {
        final var violation = new PolicyViolation();
        violation.setPolicyCondition(condition);
        violation.setType(PolicyViolation.Type.SECURITY);
        violation.setTimestamp(new Date());
        violation.setText(text);
        return violation;
    }

    private static Map<Long, List<PolicyViolation>> reports(Fixture fixture, String message) {
        return Map.of(fixture.componentId(), List.of(violation(fixture.condition(), message)));
    }

    private static ViolationChanges reconcile(Fixture fixture, String message) {
        return inJdbiTransaction(handle ->
                new CelPolicyDao(handle).reconcileViolationChanges(fixture.projectId(), reports(fixture, message)));
    }

    private static String message(long id) {
        return withJdbiHandle(handle -> handle.createQuery("SELECT \"TEXT\" FROM \"POLICYVIOLATION\" WHERE \"ID\"=:id")
                .bind("id", id)
                .mapTo(String.class)
                .one());
    }

    private static long countViolations(long projectId) {
        return withJdbiHandle(
                handle -> handle.createQuery("SELECT COUNT(*) FROM \"POLICYVIOLATION\" WHERE \"PROJECT_ID\"=:projectId")
                        .bind("projectId", projectId)
                        .mapTo(Long.class)
                        .one());
    }
}
