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
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Vex;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationLevel;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.command.MakeViolationAnalysisCommand;
import org.dependencytrack.persistence.jdbi.command.CloneProjectCommand;
import org.dependencytrack.util.DateUtil;
import org.jdbi.v3.core.Handle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.jdo.JDOObjectNotFoundException;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;

public class ProjectDaoTest extends PersistenceCapableTest {

    private Handle jdbiHandle;
    private ProjectDao projectDao;

    @BeforeEach
    public void before() throws Exception {
        super.before();
        jdbiHandle = openJdbiHandle();
        projectDao = jdbiHandle.attach(ProjectDao.class);
    }

    @AfterEach
    public void after() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }
        super.after();
    }

    @Test
    public void testCascadeDeleteProject() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var author = new OrganizationalContact();
        author.setName("authorName");
        final var projectMetadata = new ProjectMetadata();
        projectMetadata.setProject(project);
        projectMetadata.setAuthors(List.of(author));
        qm.persist(projectMetadata);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("2.0.0");
        qm.persist(component);

        // Assign a vulnerability and an accompanying analysis with comments to component.
        final var vuln = new Vulnerability();
        vuln.setVulnId("INT-123");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vuln);
        qm.addVulnerability(vuln, component, "internal");
        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vuln)
                        .withState(AnalysisState.NOT_AFFECTED)
                        .withJustification(AnalysisJustification.CODE_NOT_REACHABLE)
                        .withResponse(AnalysisResponse.WORKAROUND_AVAILABLE)
                        .withDetails("analysisDetails")
                        .withComment("someComment"));

        // Create a child component to validate that deletion is indeed recursive.
        final var componentChild = new Component();
        componentChild.setProject(project);
        componentChild.setParent(component);
        componentChild.setName("acme-sub-lib");
        componentChild.setVersion("3.0.0");
        qm.persist(componentChild);

        // Assign a policy violation and an accompanying analysis with comments to componentChild.
        final var policy = new Policy();
        policy.setName("Test Policy");
        policy.setViolationState(Policy.ViolationState.WARN);
        policy.setOperator(Policy.Operator.ALL);
        policy.setProjects(List.of(project));
        qm.persist(policy);
        final var policyCondition = new PolicyCondition();
        policyCondition.setPolicy(policy);
        policyCondition.setSubject(PolicyCondition.Subject.COORDINATES);
        policyCondition.setOperator(PolicyCondition.Operator.MATCHES);
        policyCondition.setValue("someValue");
        qm.persist(policyCondition);
        final var policyViolation = new PolicyViolation();
        policyViolation.setPolicyCondition(policyCondition);
        policyViolation.setComponent(componentChild);
        policyViolation.setType(PolicyViolation.Type.OPERATIONAL);
        policyViolation.setTimestamp(new Date());
        qm.persist(policyViolation);
        qm.makeViolationAnalysis(
                new MakeViolationAnalysisCommand(componentChild, policyViolation)
                        .withState(ViolationAnalysisState.REJECTED)
                        .withCommenter("someCommenter")
                        .withComment("someComment"));

        // Create metrics for project and component.
        useJdbiHandle(handle -> {
            var dao = handle.attach(MetricsTestDao.class);
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", LocalDate.of(2025, 1, 1));
            dao.createMetricsPartitionsForDate("DEPENDENCYMETRICS", LocalDate.of(2025, 1, 1));

            var projectMetrics = new ProjectMetrics();
            projectMetrics.setProjectId(project.getId());
            projectMetrics.setFirstOccurrence(Date.from(Instant.now()));
            projectMetrics.setLastOccurrence(DateUtil.parseShortDate("20250101"));
            dao.createProjectMetrics(projectMetrics);

            var dependencyMetrics = new DependencyMetrics();
            dependencyMetrics.setProjectId(project.getId());
            dependencyMetrics.setComponentId(component.getId());
            dependencyMetrics.setFirstOccurrence(Date.from(Instant.now()));
            dependencyMetrics.setLastOccurrence(DateUtil.parseShortDate("20250101"));
            dao.createDependencyMetrics(dependencyMetrics);
        });

        // Create a BOM.
        final Bom bom = qm.createBom(project, new Date(), Bom.Format.CYCLONEDX, "1.4", 1, "serialNumber", UUID.randomUUID(), null);

        // Create a child project with an accompanying component.
        final var projectChild = new Project();
        projectChild.setParent(project);
        projectChild.setName("acme-sub-app");
        projectChild.setVersion("1.1.0");
        qm.persist(projectChild);
        final var projectChildComponent = new Component();
        projectChildComponent.setProject(projectChild);
        projectChildComponent.setName("acme-lib-x");
        projectChildComponent.setVersion("4.0.0");
        qm.persist(projectChildComponent);

        // Create a VEX for projectChild.
        final var vex = new Vex();
        vex.setProject(projectChild);
        vex.setImported(new Date());
        vex.setVexFormat(Vex.Format.CYCLONEDX);
        vex.setSpecVersion("1.3");
        vex.setVexVersion(1);
        vex.setSerialNumber("serialNumber");
        qm.persist(vex);

        // Create a notification rule and associate projectChild with it.
        final NotificationPublisher notificationPublisher = qm.createNotificationPublisher("name", "description", "extensionName", "templateContent", "templateMimeType", true);
        final NotificationRule notificationRule = qm.createNotificationRule("name", NotificationScope.PORTFOLIO, NotificationLevel.WARNING, notificationPublisher);
        notificationRule.getProjects().add(projectChild);
        qm.persist(notificationRule);

        final var serviceComponent = new ServiceComponent();
        serviceComponent.setName("service-component");
        serviceComponent.setProject(project);
        qm.persist(serviceComponent);

        projectDao.deleteProject(project.getUuid());

        // Ensure everything has been deleted as expected.
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(Project.class, project.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(Project.class, projectChild.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(Component.class, component.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(Component.class, componentChild.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(Component.class, projectChildComponent.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(ProjectMetadata.class, projectMetadata.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(Bom.class, bom.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(Vex.class, vex.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(ServiceComponent.class, serviceComponent.getId()));

        // Ensure associated objects were NOT deleted.
        assertThatNoException().isThrownBy(() -> qm.getObjectById(Vulnerability.class, vuln.getId()));
        assertThatNoException().isThrownBy(() -> qm.getObjectById(PolicyCondition.class, policyCondition.getId()));
        assertThatNoException().isThrownBy(() -> qm.getObjectById(Policy.class, policy.getId()));
        assertThatNoException().isThrownBy(() -> qm.getObjectById(NotificationRule.class, notificationRule.getId()));
        assertThatNoException().isThrownBy(() -> qm.getObjectById(NotificationPublisher.class, notificationPublisher.getId()));

        // Ensure that associations have been cleaned up.
        qm.getPersistenceManager().refresh(notificationRule);
        assertThat(notificationRule.getProjects()).isEmpty();
        qm.getPersistenceManager().refresh(policy);
        assertThat(policy.getProjects()).isEmpty();

        // Ensure that metrics have been deleted.
        MetricsDao dao = jdbiHandle.attach(MetricsDao.class);
        assertThat(dao.getProjectMetricsSince(project.getId(), DateUtil.parseShortDate("20250101").toInstant())).isEmpty();
        assertThat(dao.getDependencyMetricsSince(component.getId(), DateUtil.parseShortDate("20250101").toInstant())).isEmpty();
    }

    @Test
    public void shouldExcludeInactiveFindingsWhenCloningProject() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("2.0.0");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("INT-123");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, "internal");

        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vuln)
                        .withState(AnalysisState.NOT_AFFECTED)
                        .withJustification(AnalysisJustification.CODE_NOT_REACHABLE)
                        .withResponse(AnalysisResponse.WORKAROUND_AVAILABLE)
                        .withDetails("analysisDetails")
                        .withCommenter("someCommenter")
                        .withComment("someComment"));

        jdbiHandle.createUpdate(/* language=SQL */ """
                        UPDATE "FINDINGATTRIBUTION"
                           SET "DELETED_AT" = NOW()
                         WHERE "COMPONENT_ID" = :componentId
                           AND "VULNERABILITY_ID" = :vulnerabilityId
                        """)
                .bind("componentId", component.getId())
                .bind("vulnerabilityId", vuln.getId())
                .execute();

        final UUID clonedUuid = projectDao.cloneProject(new CloneProjectCommand(
                project.getUuid(),
                "1.1.0",
                /* targetProjectVersionIsLatest */ false,
                /* includeAcl */ false,
                /* includeComponents */ true,
                /* includeFindings */ true,
                /* includeFindingsAuditHistory */ true,
                /* includePolicyViolations */ false,
                /* includePolicyViolationsAuditHistory */ false,
                /* includeProperties */ false,
                /* includeServices */ false,
                /* includeTags */ false));

        final Long clonedComponentId = jdbiHandle.createQuery(/* language=SQL */ """
                        SELECT c."ID"
                          FROM "COMPONENT" AS c
                         INNER JOIN "PROJECT" AS p
                            ON p."ID" = c."PROJECT_ID"
                         WHERE p."UUID" = :projectUuid
                        """)
                .bind("projectUuid", clonedUuid)
                .mapTo(Long.class)
                .one();

        final long clonedCvCount = jdbiHandle.createQuery(/* language=SQL */ """
                        SELECT COUNT(*)
                          FROM "COMPONENTS_VULNERABILITIES"
                         WHERE "COMPONENT_ID" = :componentId
                        """)
                .bind("componentId", clonedComponentId)
                .mapTo(Long.class)
                .one();
        assertThat(clonedCvCount).isZero();

        final long clonedAttributionCount = jdbiHandle.createQuery(/* language=SQL */ """
                        SELECT COUNT(*)
                          FROM "FINDINGATTRIBUTION"
                         WHERE "COMPONENT_ID" = :componentId
                        """)
                .bind("componentId", clonedComponentId)
                .mapTo(Long.class)
                .one();
        assertThat(clonedAttributionCount).isZero();

        final long clonedAnalysisCount = jdbiHandle.createQuery(/* language=SQL */ """
                        SELECT COUNT(*)
                          FROM "ANALYSIS"
                         WHERE "COMPONENT_ID" = :componentId
                        """)
                .bind("componentId", clonedComponentId)
                .mapTo(Long.class)
                .one();
        assertThat(clonedAnalysisCount).isZero();

        final long clonedCommentCount = jdbiHandle.createQuery(/* language=SQL */ """
                        SELECT COUNT(*)
                          FROM "ANALYSISCOMMENT" AS ac
                         INNER JOIN "ANALYSIS" AS a
                            ON a."ID" = ac."ANALYSIS_ID"
                         WHERE a."COMPONENT_ID" = :componentId
                        """)
                .bind("componentId", clonedComponentId)
                .mapTo(Long.class)
                .one();
        assertThat(clonedCommentCount).isZero();
    }

    @Test
    public void shouldCloneActiveFindingsWhenCloningProject() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("2.0.0");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("INT-123");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, "internal");

        final UUID clonedUuid = projectDao.cloneProject(new CloneProjectCommand(
                project.getUuid(),
                "1.1.0",
                /* targetProjectVersionIsLatest */ false,
                /* includeAcl */ false,
                /* includeComponents */ true,
                /* includeFindings */ true,
                /* includeFindingsAuditHistory */ true,
                /* includePolicyViolations */ false,
                /* includePolicyViolationsAuditHistory */ false,
                /* includeProperties */ false,
                /* includeServices */ false,
                /* includeTags */ false));

        final long clonedCvCount = jdbiHandle.createQuery(/* language=SQL */ """
                        SELECT COUNT(*)
                          FROM "COMPONENTS_VULNERABILITIES" cv
                         INNER JOIN "COMPONENT" c
                            ON c."ID" = cv."COMPONENT_ID"
                         INNER JOIN "PROJECT" p
                            ON p."ID" = c."PROJECT_ID"
                         WHERE p."UUID" = :projectUuid
                        """)
                .bind("projectUuid", clonedUuid)
                .mapTo(Long.class)
                .one();
        assertThat(clonedCvCount).isOne();
    }

    @Test
    public void testGetProjectId() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        assertThat(projectDao.getProjectId(project.getUuid())).isEqualTo(null);
        qm.persist(project);
        assertThat(projectDao.getProjectId(project.getUuid())).isEqualTo(project.getId());
    }
}