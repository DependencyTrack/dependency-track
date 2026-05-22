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

import alpine.persistence.PaginatedResult;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.util.DateUtil;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_PROJECTS_RETENTION_DAYS;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_PROJECTS_RETENTION_TYPE;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_PROJECTS_RETENTION_VERSIONS;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class ProjectMaintenanceTaskTest extends PersistenceCapableTest {

    @Test
    void testWithRetentionTypeAge() {
        qm.createConfigProperty(
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getGroupName(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyName(),
                "AGE",
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyType(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getDescription());

        qm.createConfigProperty(
                MAINTENANCE_PROJECTS_RETENTION_DAYS.getGroupName(),
                MAINTENANCE_PROJECTS_RETENTION_DAYS.getPropertyName(),
                MAINTENANCE_PROJECTS_RETENTION_DAYS.getDefaultPropertyValue(),
                MAINTENANCE_PROJECTS_RETENTION_DAYS.getPropertyType(),
                MAINTENANCE_PROJECTS_RETENTION_DAYS.getDescription());

        final var projectA = new Project();
        projectA.setName("acme-app-A");
        projectA.setInactiveSince(Date.from(Instant.now().minus(Duration.ofDays(40))));

        final var projectB = new Project();
        projectB.setName("acme-app-B");
        projectB.setInactiveSince(new Date());
        qm.persist(projectA, projectB);

        // Delete projects older than default 30 days
        final var task = new ProjectMaintenanceTask();
        assertThatNoException().isThrownBy(() -> task.run());

        final PaginatedResult projects = withJdbiHandle(handle ->
                handle.attach(ProjectDao.class).getProjects(null, null, null, null, null, false, false, false));

        assertThat(projects.getList(Project.class)).satisfiesExactly(
                retainedProject -> assertThat(retainedProject.getName()).isEqualTo("acme-app-B")
        );
    }

    @Test
    void testWithRetentionTypeVersionsForSameProject() {
        qm.createConfigProperty(
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getGroupName(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyName(),
                "VERSIONS",
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyType(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getDescription());

        qm.createConfigProperty(
                MAINTENANCE_PROJECTS_RETENTION_VERSIONS.getGroupName(),
                MAINTENANCE_PROJECTS_RETENTION_VERSIONS.getPropertyName(),
                "2",
                MAINTENANCE_PROJECTS_RETENTION_VERSIONS.getPropertyType(),
                MAINTENANCE_PROJECTS_RETENTION_VERSIONS.getDescription());

        var project = new Project();
        project.setName("acme-app-A");
        project.setVersion("1.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20250105"));
        qm.persist(project);

        project = new Project();
        project.setName("acme-app-A");
        project.setVersion("2.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20250106"));
        qm.persist(project);

        project = new Project();
        project.setName("acme-app-A");
        project.setVersion("3.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20250107"));
        qm.persist(project);

        project = new Project();
        project.setName("acme-app-A");
        project.setVersion("4.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20250108"));
        qm.persist(project);

        project = new Project();
        project.setName("acme-app-A");
        project.setVersion("5.0.0");
        qm.persist(project);

        // Retain all active and last 2 inactive versions of a project and delete rest
        final var task = new ProjectMaintenanceTask();
        assertThatNoException().isThrownBy(() -> task.run());
        final PaginatedResult projects = withJdbiHandle(handle ->
                handle.attach(ProjectDao.class).getProjects(null, null, null, null, null, false, false, false));
        assertThat(projects.getList(Project.class)).satisfiesExactly(
                retainedProject -> assertThat(retainedProject.getVersion()).isEqualTo("5.0.0"),
                retainedProject -> assertThat(retainedProject.getVersion()).isEqualTo("4.0.0"),
                retainedProject -> assertThat(retainedProject.getVersion()).isEqualTo("3.0.0")
        );
    }

    @Test
    void testWithRetentionTypeVersionsForDifferentProjects() {
        qm.createConfigProperty(
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getGroupName(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyName(),
                "VERSIONS",
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyType(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getDescription());

        qm.createConfigProperty(
                MAINTENANCE_PROJECTS_RETENTION_VERSIONS.getGroupName(),
                MAINTENANCE_PROJECTS_RETENTION_VERSIONS.getPropertyName(),
                "1",
                MAINTENANCE_PROJECTS_RETENTION_VERSIONS.getPropertyType(),
                MAINTENANCE_PROJECTS_RETENTION_VERSIONS.getDescription());

        var project = new Project();
        project.setName("acme-app-A");
        project.setVersion("1.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20250105"));
        qm.persist(project);

        project = new Project();
        project.setName("acme-app-A");
        project.setVersion("2.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20250107"));
        qm.persist(project);

        project = new Project();
        project.setName("acme-app-B");
        project.setVersion("1.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20250108"));
        qm.persist(project);

        project = new Project();
        project.setName("acme-app-B");
        project.setVersion("2.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20250109"));
        qm.persist(project);

        project = new Project();
        project.setName("acme-app-B");
        project.setVersion("3.0.0");
        qm.persist(project);

        // Retain all active and last 2 inactive versions of all projects and delete rest
        final var task = new ProjectMaintenanceTask();
        assertThatNoException().isThrownBy(() -> task.run());
        final PaginatedResult projects = withJdbiHandle(handle ->
                handle.attach(ProjectDao.class).getProjects(null, null, null, null, null, false, false, false));
        assertThat(projects.getList(Project.class)).satisfiesExactlyInAnyOrder(
                retainedProject -> {
                    assertThat(retainedProject.getName()).isEqualTo("acme-app-A");
                    assertThat(retainedProject.getVersion()).isEqualTo("2.0.0");
                },
                retainedProject -> {
                    assertThat(retainedProject.getName()).isEqualTo("acme-app-B");
                    assertThat(retainedProject.getVersion()).isEqualTo("2.0.0");
                },
                retainedProject -> {
                    assertThat(retainedProject.getName()).isEqualTo("acme-app-B");
                    assertThat(retainedProject.getVersion()).isEqualTo("3.0.0");
                }
        );
    }

    @Test
    void testWithProjectRetentionDisabled() {
        qm.createConfigProperty(
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getGroupName(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyName(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getDefaultPropertyValue(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyType(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getDescription());

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20100109"));
        qm.persist(project);

        final var task = new ProjectMaintenanceTask();
        assertThatNoException().isThrownBy(() -> task.run());
        final PaginatedResult projects = withJdbiHandle(handle ->
                handle.attach(ProjectDao.class).getProjects(null, null, null, null, null, false, false, false));
        assertThat(projects).isNotNull();
    }

    @Test
    void testWithProjectRetentionDisabledWithEmptyValue() {
        qm.createConfigProperty(
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getGroupName(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyName(),
                "",
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyType(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getDescription());

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20100109"));
        qm.persist(project);

        final var task = new ProjectMaintenanceTask();
        assertThatNoException().isThrownBy(() -> task.run());
        final PaginatedResult projects = withJdbiHandle(handle ->
                handle.attach(ProjectDao.class).getProjects(null, null, null, null, null, false, false, false));
        assertThat(projects).isNotNull();
    }
}