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
package org.dependencytrack.tasks.maintenance;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.dependencytrack.persistence.jdbi.MetricsTestDao;
import org.jdbi.v3.core.Handle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.function.BiConsumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_METRICS_RETENTION_DAYS;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

public class MetricsMaintenanceTaskTest extends PersistenceCapableTest {

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
    public void test() throws Exception {
        qm.createConfigProperty(
                MAINTENANCE_METRICS_RETENTION_DAYS.getGroupName(),
                MAINTENANCE_METRICS_RETENTION_DAYS.getPropertyName(),
                MAINTENANCE_METRICS_RETENTION_DAYS.getDefaultPropertyValue(),
                MAINTENANCE_METRICS_RETENTION_DAYS.getPropertyType(),
                MAINTENANCE_METRICS_RETENTION_DAYS.getDescription()
        );

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final BiConsumer<Instant, Integer> createComponentMetricsForLastOccurrence = (lastOccurrence, vulns) -> {
            var metrics = new DependencyMetrics();
            metrics.setProjectId(project.getId());
            metrics.setComponentId(component.getId());
            metrics.setVulnerabilities(vulns);
            metrics.setFirstOccurrence(Date.from(lastOccurrence));
            metrics.setLastOccurrence(Date.from(lastOccurrence));
            metricsTestDao.createDependencyMetrics(metrics);
        };

        final BiConsumer<Instant, Integer> createProjectMetricsForLastOccurrence = (lastOccurrence, vulns) -> {
            var metrics = new ProjectMetrics();
            metrics.setProjectId(project.getId());
            metrics.setVulnerabilities(vulns);
            metrics.setFirstOccurrence(Date.from(lastOccurrence));
            metrics.setLastOccurrence(Date.from(lastOccurrence));
            metricsTestDao.createProjectMetrics(metrics);
        };

        final Instant now = Instant.now();

        // Create component metrics partitions for dates required
        metricsTestDao.createPartitionForDaysAgo("DEPENDENCYMETRICS", 91);
        metricsTestDao.createPartitionForDaysAgo("DEPENDENCYMETRICS", 90);
        metricsTestDao.createPartitionForDaysAgo("DEPENDENCYMETRICS", 89);

        createComponentMetricsForLastOccurrence.accept(now.minus(91, ChronoUnit.DAYS), 91);
        createComponentMetricsForLastOccurrence.accept(now.minus(90, ChronoUnit.DAYS), 90);
        createComponentMetricsForLastOccurrence.accept(now.minus(89, ChronoUnit.DAYS), 89);

        // Create project metrics partitions for dates required
        metricsTestDao.createPartitionForDaysAgo("PROJECTMETRICS", 91);
        metricsTestDao.createPartitionForDaysAgo("PROJECTMETRICS", 90);
        metricsTestDao.createPartitionForDaysAgo("PROJECTMETRICS", 89);

        createProjectMetricsForLastOccurrence.accept(now.minus(91, ChronoUnit.DAYS), 91);
        createProjectMetricsForLastOccurrence.accept(now.minus(90, ChronoUnit.DAYS), 90);
        createProjectMetricsForLastOccurrence.accept(now.minus(89, ChronoUnit.DAYS), 89);

        final var task = new MetricsMaintenanceTask();
        assertThatNoException().isThrownBy(() -> task.run());

        assertThat(metricsDao.getDependencyMetricsSince(component.getId(), now.minus(91, ChronoUnit.DAYS))).satisfiesExactly(
                metrics -> assertThat(metrics.getVulnerabilities()).isEqualTo(89));

        assertThat(metricsDao.getProjectMetricsSince(project.getId(), now.minus(91, ChronoUnit.DAYS))).satisfiesExactly(
                metrics -> assertThat(metrics.getVulnerabilities()).isEqualTo(89));
    }

    @Test
    public void testCreateMetricsPartitions() {
        qm.createConfigProperty(
                MAINTENANCE_METRICS_RETENTION_DAYS.getGroupName(),
                MAINTENANCE_METRICS_RETENTION_DAYS.getPropertyName(),
                MAINTENANCE_METRICS_RETENTION_DAYS.getDefaultPropertyValue(),
                MAINTENANCE_METRICS_RETENTION_DAYS.getPropertyType(),
                MAINTENANCE_METRICS_RETENTION_DAYS.getDescription());

        new MetricsMaintenanceTask().run();
        var today = LocalDate.now().format(DateTimeFormatter.BASIC_ISO_DATE);
        var tomorrow = LocalDate.now().plusDays(1).format(DateTimeFormatter.BASIC_ISO_DATE);

        var metricsPartitions = metricsDao.getProjectMetricsPartitions();
        assertThat(metricsPartitions.getFirst()).isEqualTo("\"PROJECTMETRICS_%s\"".formatted(today));
        assertThat(metricsPartitions.getLast()).isEqualTo("\"PROJECTMETRICS_%s\"".formatted(tomorrow));

        metricsPartitions = metricsDao.getDependencyMetricsPartitions();
        assertThat(metricsPartitions.getFirst()).isEqualTo("\"DEPENDENCYMETRICS_%s\"".formatted(today));
        assertThat(metricsPartitions.getLast()).isEqualTo("\"DEPENDENCYMETRICS_%s\"".formatted(tomorrow));
    }
}