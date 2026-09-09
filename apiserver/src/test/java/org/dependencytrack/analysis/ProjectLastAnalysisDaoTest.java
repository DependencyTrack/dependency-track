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
package org.dependencytrack.analysis;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.jdbi.v3.core.Handle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

class ProjectLastAnalysisDaoTest extends PersistenceCapableTest {

    private static final Duration MAX_ANALYSIS_AGE = Duration.ofHours(24);

    private Handle jdbiHandle;
    private ProjectLastAnalysisDao dao;

    @BeforeEach
    public void before() throws Exception {
        super.before();
        jdbiHandle = openJdbiHandle();
        dao = jdbiHandle.attach(ProjectLastAnalysisDao.class);
    }

    @AfterEach
    public void after() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }
        super.after();
    }

    @Test
    void shouldReturnProjectsThatWereNeverAttempted() {
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        assertThat(dao.getProjectsDue(Instant.now().minus(MAX_ANALYSIS_AGE), 10))
                .extracting(ProjectDueForAnalysis::uuid)
                .containsExactlyInAnyOrder(projectA.getUuid(), projectB.getUuid());
    }

    @Test
    void shouldNotReturnInactiveProjects() {
        final var activeProject = new Project();
        activeProject.setName("acme-app-active");
        qm.persist(activeProject);

        final var inactiveProject = new Project();
        inactiveProject.setName("acme-app-inactive");
        inactiveProject.setInactiveSince(new Date());
        qm.persist(inactiveProject);

        assertThat(dao.getProjectsDue(Instant.now().minus(MAX_ANALYSIS_AGE), 10))
                .extracting(ProjectDueForAnalysis::uuid)
                .containsExactly(activeProject.getUuid());
    }

    @Test
    void shouldStopAndResumeReturningProjectAsItIsDeactivatedAndReactivated() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);
        dao.recordAttempt(new long[] {project.getId()}, Instant.now().minus(Duration.ofDays(3)));

        project.setInactiveSince(new Date());
        qm.persist(project);
        assertThat(dao.getProjectsDue(Instant.now().minus(MAX_ANALYSIS_AGE), 10))
                .isEmpty();

        project.setInactiveSince(null);
        qm.persist(project);
        assertThat(dao.getProjectsDue(Instant.now().minus(MAX_ANALYSIS_AGE), 10))
                .extracting(ProjectDueForAnalysis::uuid)
                .containsExactly(project.getUuid());
    }

    @Test
    void shouldReturnProjectsThatWaitedLongestFirst() {
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        final var projectC = new Project();
        projectC.setName("acme-app-c");
        qm.persist(projectC);

        final Instant now = Instant.now();
        dao.recordAttempt(new long[] {projectA.getId()}, now.minus(Duration.ofDays(3)));
        dao.recordAttempt(new long[] {projectB.getId()}, now.minus(Duration.ofDays(5)));
        dao.recordAttempt(new long[] {projectC.getId()}, now.minus(Duration.ofDays(4)));

        assertThat(dao.getProjectsDue(Instant.now().minus(MAX_ANALYSIS_AGE), 10))
                .extracting(ProjectDueForAnalysis::uuid)
                .containsExactly(projectB.getUuid(), projectC.getUuid(), projectA.getUuid());
    }

    @Test
    void shouldNotReturnProjectsAnalyzedWithinMaxAnalysisAge() {
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        dao.recordAttempt(new long[] {projectA.getId()}, Instant.now());

        assertThat(dao.getProjectsDue(Instant.now().minus(MAX_ANALYSIS_AGE), 10))
                .extracting(ProjectDueForAnalysis::uuid)
                .containsExactly(projectB.getUuid());
    }

    @Test
    void shouldNotReturnMoreProjectsThanTheLimitAllows() {
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        final var projectC = new Project();
        projectC.setName("acme-app-c");
        qm.persist(projectC);

        assertThat(dao.getProjectsDue(Instant.now().minus(MAX_ANALYSIS_AGE), 2)).hasSize(2);
    }

    @Test
    void shouldRecordAttemptForGivenProjectsOnly() {
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        assertThat(dao.recordAttempt(new long[] {projectA.getId()}, Instant.now()))
                .isEqualTo(1);

        assertThat(dao.getProjectsDue(Instant.now().minus(MAX_ANALYSIS_AGE), 10))
                .extracting(ProjectDueForAnalysis::uuid)
                .containsExactly(projectB.getUuid());
    }

    @Test
    void shouldRecordAttemptByProjectUuid() {
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        assertThat(dao.recordAttempt(projectA.getUuid(), Instant.now())).isEqualTo(1);

        assertThat(dao.getProjectsDue(Instant.now().minus(MAX_ANALYSIS_AGE), 10))
                .extracting(ProjectDueForAnalysis::uuid)
                .containsExactly(projectB.getUuid());
    }

    @Test
    void shouldNotRecordAttemptForInactiveProject() {
        final var inactiveProject = new Project();
        inactiveProject.setName("acme-app-inactive");
        inactiveProject.setInactiveSince(new Date());
        qm.persist(inactiveProject);

        assertThat(dao.recordAttempt(inactiveProject.getUuid(), Instant.now())).isZero();
    }
}
