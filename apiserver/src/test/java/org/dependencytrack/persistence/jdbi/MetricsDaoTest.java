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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.ProjectMetrics;
import org.jdbi.v3.core.Handle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class MetricsDaoTest extends PersistenceCapableTest {

    private Handle jdbiHandle;
    private MetricsDao metricsDao;
    private MetricsTestDao metricsTestDao;

    @BeforeEach
    public void before() throws Exception {
        super.before();
        jdbiHandle = openJdbiHandle();
        metricsDao = jdbiHandle.attach(MetricsDao.class);
        metricsTestDao = jdbiHandle.attach(MetricsTestDao.class);
    }

    @AfterEach
    public void after() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }
        super.after();
    }

    @Test
    public void testGetProjectMetricsForXDays() {
        final var project = qm.createProject("acme-app", null, "1.0.0", null, null, null, null, false);

        metricsTestDao.createPartitionForDaysAgo("PROJECTMETRICS", 40);

        var metrics = new ProjectMetrics();
        metrics.setProjectId(project.getId());
        metrics.setVulnerabilities(4);
        metrics.setFirstOccurrence(Date.from(Instant.now()));
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(40))));
        metricsTestDao.createProjectMetrics(metrics);

        metricsTestDao.createPartitionForDaysAgo("PROJECTMETRICS", 30);
        metrics = new ProjectMetrics();
        metrics.setProjectId(project.getId());
        metrics.setVulnerabilities(3);
        metrics.setFirstOccurrence(Date.from(Instant.now()));
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(30))));
        metricsTestDao.createProjectMetrics(metrics);

        metricsTestDao.createPartitionForDaysAgo("PROJECTMETRICS", 20);
        metrics = new ProjectMetrics();
        metrics.setProjectId(project.getId());
        metrics.setVulnerabilities(2);
        metrics.setFirstOccurrence(Date.from(Instant.now()));
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(20))));
        metricsTestDao.createProjectMetrics(metrics);

        var projectMetrics = withJdbiHandle(handle ->
                handle.attach(MetricsDao.class).getProjectMetricsSince(project.getId(), Instant.now().minus(Duration.ofDays(35))));
        assertThat(projectMetrics.size()).isEqualTo(2);
        assertThat(projectMetrics.get(0).getVulnerabilities()).isEqualTo(3);
        assertThat(projectMetrics.get(1).getVulnerabilities()).isEqualTo(2);
    }

    @Test
    public void testGetDependencyMetricsForXDays() {
        final var project = qm.createProject("acme-app", null, "1.0.0", null, null, null, null, false);
        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);

        metricsTestDao.createPartitionForDaysAgo("DEPENDENCYMETRICS", 40);
        var metrics = new DependencyMetrics();
        metrics.setProjectId(project.getId());
        metrics.setComponentId(component.getId());
        metrics.setVulnerabilities(4);
        metrics.setFirstOccurrence(Date.from(Instant.now()));
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(40))));
        metricsTestDao.createDependencyMetrics(metrics);

        metricsTestDao.createPartitionForDaysAgo("DEPENDENCYMETRICS", 30);
        metrics = new DependencyMetrics();
        metrics.setProjectId(project.getId());
        metrics.setComponentId(component.getId());
        metrics.setVulnerabilities(3);
        metrics.setFirstOccurrence(Date.from(Instant.now()));
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(30))));
        metricsTestDao.createDependencyMetrics(metrics);

        metricsTestDao.createPartitionForDaysAgo("DEPENDENCYMETRICS", 20);
        metrics = new DependencyMetrics();
        metrics.setProjectId(project.getId());
        metrics.setComponentId(component.getId());
        metrics.setVulnerabilities(2);
        metrics.setFirstOccurrence(Date.from(Instant.now()));
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(20))));
        metricsTestDao.createDependencyMetrics(metrics);

        var dependencyMetrics = metricsDao.getDependencyMetricsSince(component.getId(), Instant.now().minus(Duration.ofDays(35)));
        assertThat(dependencyMetrics.size()).isEqualTo(2);
        assertThat(dependencyMetrics.get(0).getVulnerabilities()).isEqualTo(3);
        assertThat(dependencyMetrics.get(1).getVulnerabilities()).isEqualTo(2);
    }

    @Test
    public void testCreateMetricsPartitions() {
        metricsDao.createMetricsPartitions();

        final LocalDate todayDate = jdbiHandle.createQuery("SELECT CURRENT_DATE")
                .mapTo(LocalDate.class)
                .one();
        var today = todayDate.format(DateTimeFormatter.BASIC_ISO_DATE);
        var tomorrow = todayDate.plusDays(1).format(DateTimeFormatter.BASIC_ISO_DATE);

        var projectPartitions = metricsDao.getProjectMetricsPartitions();
        assertThat(projectPartitions).contains("\"PROJECTMETRICS_%s\"".formatted(today));
        assertThat(projectPartitions).contains("\"PROJECTMETRICS_%s\"".formatted(tomorrow));

        var dependencyPartitions = metricsDao.getDependencyMetricsPartitions();
        assertThat(dependencyPartitions).contains("\"DEPENDENCYMETRICS_%s\"".formatted(today));
        assertThat(dependencyPartitions).contains("\"DEPENDENCYMETRICS_%s\"".formatted(tomorrow));

        // If called again on the same day with partitions already created,
        // it won't create more.
        metricsDao.createMetricsPartitions();
        assertThat(Collections.frequency(metricsDao.getProjectMetricsPartitions(), "\"PROJECTMETRICS_%s\"".formatted(today))).isEqualTo(1);
        assertThat(Collections.frequency(metricsDao.getDependencyMetricsPartitions(), "\"DEPENDENCYMETRICS_%s\"".formatted(today))).isEqualTo(1);
    }

    @Test
    public void testDropPartitionsWithPendingDetach() throws Exception {
        metricsTestDao.createPartitionForDaysAgo("PROJECTMETRICS", 91);
        final String partitionSuffix = LocalDate.now().minusDays(91).format(DateTimeFormatter.BASIC_ISO_DATE);
        final String partitionName = "\"PROJECTMETRICS_%s\"".formatted(partitionSuffix);

        // Simulate the partition into 'pending_detach' state
        // by holding lock to block phase 2 of DETACH PARTITION CONCURRENTLY
        try (final Handle lockHandle = openJdbiHandle()) {
            lockHandle.begin();
            try {
                lockHandle.execute("LOCK TABLE %s IN ACCESS SHARE MODE".formatted(partitionName));

                final CompletableFuture<Integer> detachBackendPid = new CompletableFuture<>();
                final var future = CompletableFuture.runAsync(() -> {
                    try (final Handle handle = openJdbiHandle()) {
                        detachBackendPid.complete(handle.createQuery("SELECT pg_backend_pid()")
                                .mapTo(Integer.class)
                                .one());
                        handle.execute("ALTER TABLE %s DETACH PARTITION %s CONCURRENTLY".formatted("\"PROJECTMETRICS\"", partitionName));
                    }
                });

                await("partition pending detach")
                        .atMost(5, TimeUnit.SECONDS)
                        .until(() -> metricsDao.isPartitionDetachPending("\"PROJECTMETRICS\"", partitionName));

                assertThat(jdbiHandle.createQuery("SELECT pg_cancel_backend(:pid)")
                        .bind("pid", detachBackendPid.get(5, TimeUnit.SECONDS))
                        .mapTo(Boolean.class)
                        .one())
                        .isTrue();
                assertThat(metricsDao.isPartitionDetachPending("\"PROJECTMETRICS\"", partitionName)).isTrue();
            } finally {
                lockHandle.rollback();
            }
        }
        assertThat(metricsDao.dropPartitions("\"PROJECTMETRICS\"", List.of(partitionName))).isEqualTo(1);
    }
}
