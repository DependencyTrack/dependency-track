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

import org.dependencytrack.filestorage.proto.v1.FileMetadata;
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
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

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

        // Metrics are NOT deleted, see ADR 029.
        MetricsDao dao = jdbiHandle.attach(MetricsDao.class);
        assertThat(dao.getProjectMetricsSince(project.getId(), DateUtil.parseShortDate("20250101").toInstant())).isNotEmpty();
        assertThat(dao.getDependencyMetricsSince(component.getId(), DateUtil.parseShortDate("20250101").toInstant())).isNotEmpty();
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

    @Test
    public void testDeleteProjectsReturnsRequestedProjectsAndCascadeDeletedDescendants() {
        final var parent = new Project();
        parent.setName("acme-app-parent");
        parent.setVersion("1.0.0");
        qm.persist(parent);

        final var child = new Project();
        child.setParent(parent);
        child.setName("acme-app-child");
        child.setVersion("1.0.0");
        qm.persist(child);

        final var grandChild = new Project();
        grandChild.setParent(child);
        grandChild.setName("acme-app-grandchild");
        grandChild.setVersion("1.0.0");
        qm.persist(grandChild);

        final var unrelated = new Project();
        unrelated.setName("other-app");
        unrelated.setVersion("1.0.0");
        qm.persist(unrelated);

        final List<ProjectDao.DeletedProjectRow> deleted = withJdbiHandle(handle ->
                handle.attach(ProjectDao.class).deleteProjects(List.of(parent.getUuid())));

        assertThat(deleted).satisfiesExactlyInAnyOrder(
                row -> {
                    assertThat(row.uuid()).isEqualTo(parent.getUuid());
                    assertThat(row.name()).isEqualTo("acme-app-parent");
                    assertThat(row.version()).isEqualTo("1.0.0");
                    assertThat(row.ancestorUuid()).isNull();
                },
                row -> {
                    assertThat(row.uuid()).isEqualTo(child.getUuid());
                    assertThat(row.name()).isEqualTo("acme-app-child");
                    assertThat(row.version()).isEqualTo("1.0.0");
                    assertThat(row.ancestorUuid()).isEqualTo(parent.getUuid());
                },
                row -> {
                    assertThat(row.uuid()).isEqualTo(grandChild.getUuid());
                    assertThat(row.name()).isEqualTo("acme-app-grandchild");
                    assertThat(row.version()).isEqualTo("1.0.0");
                    assertThat(row.ancestorUuid()).isEqualTo(parent.getUuid());
                });

        assertThat(projectDao.getProjectId(parent.getUuid())).isNull();
        assertThat(projectDao.getProjectId(child.getUuid())).isNull();
        assertThat(projectDao.getProjectId(grandChild.getUuid())).isNull();
        assertThat(projectDao.getProjectId(unrelated.getUuid())).isEqualTo(unrelated.getId());
    }

    @Test
    public void testDeleteProjectsAttributesDescendantsToClosestRequestedAncestor() {
        final var parent = new Project();
        parent.setName("acme-app-parent");
        parent.setVersion("1.0.0");
        qm.persist(parent);

        final var child = new Project();
        child.setParent(parent);
        child.setName("acme-app-child");
        child.setVersion("1.0.0");
        qm.persist(child);

        final var grandChild = new Project();
        grandChild.setParent(child);
        grandChild.setName("acme-app-grandchild");
        grandChild.setVersion("1.0.0");
        qm.persist(grandChild);

        // Child is explicitly requested, so it is a deletion root rather than a descendant of parent.
        final List<ProjectDao.DeletedProjectRow> deleted = withJdbiHandle(handle ->
                handle.attach(ProjectDao.class).deleteProjects(List.of(parent.getUuid(), child.getUuid())));

        assertThat(deleted).satisfiesExactlyInAnyOrder(
                row -> {
                    assertThat(row.uuid()).isEqualTo(parent.getUuid());
                    assertThat(row.ancestorUuid()).isNull();
                },
                row -> {
                    assertThat(row.uuid()).isEqualTo(child.getUuid());
                    assertThat(row.ancestorUuid()).isNull();
                },
                row -> {
                    assertThat(row.uuid()).isEqualTo(grandChild.getUuid());
                    assertThat(row.ancestorUuid()).isEqualTo(child.getUuid());
                });
    }

    @Test
    public void testDeleteProjectsWithOriginalBomFiles() {
        final var parent = new Project();
        parent.setName("acme-app-parent");
        parent.setVersion("1.0.0");
        qm.persist(parent);

        final var child = new Project();
        child.setParent(parent);
        child.setName("acme-app-child");
        child.setVersion("1.0.0");
        qm.persist(child);

        final var unrelated = new Project();
        unrelated.setName("other-app");
        unrelated.setVersion("1.0.0");
        qm.persist(unrelated);

        final FileMetadata parentFileMetadataA = FileMetadata.newBuilder()
                .setProviderName("test")
                .setLocation("test:///parent-original-a")
                .setMediaType("application/vnd.cyclonedx+json")
                .setSha256Digest("parent-a")
                .build();
        final FileMetadata parentFileMetadataB = FileMetadata.newBuilder()
                .setProviderName("test")
                .setLocation("test:///parent-original-b")
                .setMediaType("application/vnd.cyclonedx+xml")
                .setSha256Digest("parent-b")
                .build();
        final FileMetadata childFileMetadata = FileMetadata.newBuilder()
                .setProviderName("test")
                .setLocation("test:///child-original")
                .setMediaType("application/vnd.cyclonedx+json")
                .setSha256Digest("child")
                .build();
        final FileMetadata unrelatedFileMetadata = FileMetadata.newBuilder()
                .setProviderName("test")
                .setLocation("test:///unrelated-original")
                .setMediaType("application/vnd.cyclonedx+json")
                .setSha256Digest("unrelated")
                .build();

        final Bom parentBomA = qm.createBom(
                parent,
                new Date(),
                Bom.Format.CYCLONEDX,
                "1.6",
                1,
                null,
                UUID.randomUUID(),
                null);
        parentBomA.setOriginalFileMetadata(
                parentFileMetadataA.toByteArray());

        final Bom parentBomB = qm.createBom(
                parent,
                new Date(),
                Bom.Format.CYCLONEDX,
                "1.6",
                1,
                null,
                UUID.randomUUID(),
                null);
        parentBomB.setOriginalFileMetadata(
                parentFileMetadataB.toByteArray());

        final Bom childBom = qm.createBom(
                child,
                new Date(),
                Bom.Format.CYCLONEDX,
                "1.6",
                1,
                null,
                UUID.randomUUID(),
                null);
        childBom.setOriginalFileMetadata(
                childFileMetadata.toByteArray());

        final Bom unrelatedBom = qm.createBom(
                unrelated,
                new Date(),
                Bom.Format.CYCLONEDX,
                "1.6",
                1,
                null,
                UUID.randomUUID(),
                null);
        unrelatedBom.setOriginalFileMetadata(
                unrelatedFileMetadata.toByteArray());

        final ProjectDao.ProjectDeletionResult result =
                inJdbiTransaction(handle -> handle
                        .attach(ProjectDao.class)
                        .deleteProjectsWithOriginalBomFiles(
                                List.of(parent.getUuid())));

        assertThat(result.deletedProjects()).satisfiesExactlyInAnyOrder(
                deletedProject -> {
                    assertThat(deletedProject.uuid())
                            .isEqualTo(parent.getUuid());
                    assertThat(deletedProject.ancestorUuid()).isNull();
                },
                deletedProject -> {
                    assertThat(deletedProject.uuid())
                            .isEqualTo(child.getUuid());
                    assertThat(deletedProject.ancestorUuid())
                            .isEqualTo(parent.getUuid());
                });

        assertThat(result.originalBomFiles())
                .hasSize(3)
                .anySatisfy(row -> {
                    assertThat(row.projectUuid())
                            .isEqualTo(parent.getUuid());
                    assertThat(row.serializedFileMetadata())
                            .containsExactly(
                                    parentFileMetadataA.toByteArray());
                })
                .anySatisfy(row -> {
                    assertThat(row.projectUuid())
                            .isEqualTo(parent.getUuid());
                    assertThat(row.serializedFileMetadata())
                            .containsExactly(
                                    parentFileMetadataB.toByteArray());
                })
                .anySatisfy(row -> {
                    assertThat(row.projectUuid())
                            .isEqualTo(child.getUuid());
                    assertThat(row.serializedFileMetadata())
                            .containsExactly(
                                    childFileMetadata.toByteArray());
                });

        assertThat(result.originalBomFiles())
                .noneSatisfy(row -> assertThat(
                        row.serializedFileMetadata())
                        .containsExactly(
                                unrelatedFileMetadata.toByteArray()));

        assertThat(projectDao.getProjectId(parent.getUuid())).isNull();
        assertThat(projectDao.getProjectId(child.getUuid())).isNull();
        assertThat(projectDao.getProjectId(unrelated.getUuid()))
                .isEqualTo(unrelated.getId());
    }

    @Test
    public void testDeleteInactiveProjectsWithOriginalBomFiles() {
        final var expiredProject = new Project();
        expiredProject.setName("expired-project");
        expiredProject.setVersion("1.0");
        expiredProject.setInactiveSince(
                Date.from(Instant.parse("2026-01-01T00:00:00Z")));
        qm.persist(expiredProject);

        final var childProject = new Project();
        childProject.setName("child-project");
        childProject.setVersion("1.0");
        childProject.setParent(expiredProject);
        qm.persist(childProject);

        final var retainedProject = new Project();
        retainedProject.setName("retained-project");
        retainedProject.setVersion("1.0");
        retainedProject.setInactiveSince(
                Date.from(Instant.parse("2026-03-01T00:00:00Z")));
        qm.persist(retainedProject);

        final FileMetadata expiredFileMetadata = FileMetadata.newBuilder()
                .setProviderName("test")
                .setLocation("test:///expired-original")
                .setMediaType("application/vnd.cyclonedx+json")
                .setSha256Digest("expired")
                .build();
        final FileMetadata childFileMetadata = FileMetadata.newBuilder()
                .setProviderName("test")
                .setLocation("test:///child-original")
                .setMediaType("application/vnd.cyclonedx+xml")
                .setSha256Digest("child")
                .build();
        final FileMetadata retainedFileMetadata = FileMetadata.newBuilder()
                .setProviderName("test")
                .setLocation("test:///retained-original")
                .setMediaType("application/vnd.cyclonedx+json")
                .setSha256Digest("retained")
                .build();

        final Bom expiredBom = qm.createBom(
                expiredProject,
                new Date(),
                Bom.Format.CYCLONEDX,
                "1.6",
                1,
                null,
                UUID.randomUUID(),
                null);
        expiredBom.setOriginalFileMetadata(
                expiredFileMetadata.toByteArray());

        final Bom childBom = qm.createBom(
                childProject,
                new Date(),
                Bom.Format.CYCLONEDX,
                "1.6",
                1,
                null,
                UUID.randomUUID(),
                null);
        childBom.setOriginalFileMetadata(
                childFileMetadata.toByteArray());

        final Bom retainedBom = qm.createBom(
                retainedProject,
                new Date(),
                Bom.Format.CYCLONEDX,
                "1.6",
                1,
                null,
                UUID.randomUUID(),
                null);
        retainedBom.setOriginalFileMetadata(
                retainedFileMetadata.toByteArray());

        final ProjectDao.MaintenanceProjectDeletionResult result =
                inJdbiTransaction(handle -> handle
                        .attach(ProjectDao.class)
                        .deleteInactiveProjectsWithOriginalBomFiles(
                                Instant.parse(
                                        "2026-02-01T00:00:00Z"),
                                25));

        assertThat(result.deletedProjects())
                .singleElement()
                .satisfies(deletedProject -> {
                    assertThat(deletedProject.uuid())
                            .isEqualTo(expiredProject.getUuid());
                    assertThat(deletedProject.name())
                            .isEqualTo("expired-project");
                    assertThat(deletedProject.version())
                            .isEqualTo("1.0");
                });

        assertThat(result.originalBomFiles())
                .hasSize(2)
                .anySatisfy(row -> {
                    assertThat(row.projectUuid())
                            .isEqualTo(expiredProject.getUuid());
                    assertThat(row.serializedFileMetadata())
                            .containsExactly(
                                    expiredFileMetadata.toByteArray());
                })
                .anySatisfy(row -> {
                    assertThat(row.projectUuid())
                            .isEqualTo(childProject.getUuid());
                    assertThat(row.serializedFileMetadata())
                            .containsExactly(
                                    childFileMetadata.toByteArray());
                });

        assertThat(result.originalBomFiles())
                .noneSatisfy(row -> assertThat(
                        row.serializedFileMetadata())
                        .containsExactly(
                                retainedFileMetadata.toByteArray()));

        assertThat(projectDao.getProjectId(
                expiredProject.getUuid())).isNull();
        assertThat(projectDao.getProjectId(
                childProject.getUuid())).isNull();
        assertThat(projectDao.getProjectId(
                retainedProject.getUuid()))
                .isEqualTo(retainedProject.getId());
    }

    @Test
    public void testDeleteExcessProjectVersionsWithOriginalBomFiles() {
        final var oldestProject = new Project();
        oldestProject.setName("versioned-project");
        oldestProject.setVersion("1.0");
        oldestProject.setInactiveSince(
                Date.from(Instant.parse("2026-01-01T00:00:00Z")));
        qm.persist(oldestProject);

        final var newerProject = new Project();
        newerProject.setName("versioned-project");
        newerProject.setVersion("2.0");
        newerProject.setInactiveSince(
                Date.from(Instant.parse("2026-02-01T00:00:00Z")));
        qm.persist(newerProject);

        final var retainedProject = new Project();
        retainedProject.setName("versioned-project");
        retainedProject.setVersion("3.0");
        retainedProject.setInactiveSince(
                Date.from(Instant.parse("2026-03-01T00:00:00Z")));
        qm.persist(retainedProject);

        final FileMetadata oldestFileMetadata = FileMetadata.newBuilder()
                .setProviderName("test")
                .setLocation("test:///oldest-version-original")
                .setMediaType("application/vnd.cyclonedx+json")
                .setSha256Digest("oldest")
                .build();
        final FileMetadata newerFileMetadata = FileMetadata.newBuilder()
                .setProviderName("test")
                .setLocation("test:///newer-version-original")
                .setMediaType("application/vnd.cyclonedx+xml")
                .setSha256Digest("newer")
                .build();
        final FileMetadata retainedFileMetadata = FileMetadata.newBuilder()
                .setProviderName("test")
                .setLocation("test:///retained-version-original")
                .setMediaType("application/vnd.cyclonedx+json")
                .setSha256Digest("retained")
                .build();

        final Bom oldestBom = qm.createBom(
                oldestProject,
                new Date(),
                Bom.Format.CYCLONEDX,
                "1.6",
                1,
                null,
                UUID.randomUUID(),
                null);
        oldestBom.setOriginalFileMetadata(
                oldestFileMetadata.toByteArray());

        final Bom newerBom = qm.createBom(
                newerProject,
                new Date(),
                Bom.Format.CYCLONEDX,
                "1.6",
                1,
                null,
                UUID.randomUUID(),
                null);
        newerBom.setOriginalFileMetadata(
                newerFileMetadata.toByteArray());

        final Bom retainedBom = qm.createBom(
                retainedProject,
                new Date(),
                Bom.Format.CYCLONEDX,
                "1.6",
                1,
                null,
                UUID.randomUUID(),
                null);
        retainedBom.setOriginalFileMetadata(
                retainedFileMetadata.toByteArray());

        final ProjectDao.MaintenanceProjectDeletionResult result =
                inJdbiTransaction(handle -> handle
                        .attach(ProjectDao.class)
                        .deleteExcessProjectVersionsWithOriginalBomFiles(
                                1,
                                25));

        assertThat(result.deletedProjects())
                .extracting(ProjectDao.DeletedProject::uuid)
                .containsExactlyInAnyOrder(
                        oldestProject.getUuid(),
                        newerProject.getUuid());

        assertThat(result.originalBomFiles())
                .hasSize(2)
                .anySatisfy(row -> {
                    assertThat(row.projectUuid())
                            .isEqualTo(oldestProject.getUuid());
                    assertThat(row.serializedFileMetadata())
                            .containsExactly(
                                    oldestFileMetadata.toByteArray());
                })
                .anySatisfy(row -> {
                    assertThat(row.projectUuid())
                            .isEqualTo(newerProject.getUuid());
                    assertThat(row.serializedFileMetadata())
                            .containsExactly(
                                    newerFileMetadata.toByteArray());
                });

        assertThat(result.originalBomFiles())
                .noneSatisfy(row -> assertThat(
                        row.serializedFileMetadata())
                        .containsExactly(
                                retainedFileMetadata.toByteArray()));

        assertThat(projectDao.getProjectId(
                oldestProject.getUuid())).isNull();
        assertThat(projectDao.getProjectId(
                newerProject.getUuid())).isNull();
        assertThat(projectDao.getProjectId(
                retainedProject.getUuid()))
                .isEqualTo(retainedProject.getId());
    }

    @Test
    public void testDeleteExcessProjectVersionsBreaksTimestampTiesById() {
        final Date inactiveSince =
                Date.from(Instant.parse("2026-01-01T00:00:00Z"));

        final var lowerIdProject = new Project();
        lowerIdProject.setName("versioned-project-with-tied-timestamps");
        lowerIdProject.setVersion("1.0");
        lowerIdProject.setInactiveSince(inactiveSince);
        qm.persist(lowerIdProject);

        final var higherIdProject = new Project();
        higherIdProject.setName("versioned-project-with-tied-timestamps");
        higherIdProject.setVersion("2.0");
        higherIdProject.setInactiveSince(inactiveSince);
        qm.persist(higherIdProject);

        assertThat(higherIdProject.getId()).isGreaterThan(lowerIdProject.getId());

        final ProjectDao.MaintenanceProjectDeletionResult result =
                inJdbiTransaction(handle -> handle
                        .attach(ProjectDao.class)
                        .deleteExcessProjectVersionsWithOriginalBomFiles(
                                1,
                                25));

        assertThat(result.deletedProjects())
                .extracting(ProjectDao.DeletedProject::uuid)
                .containsExactly(lowerIdProject.getUuid());
        assertThat(projectDao.getProjectId(lowerIdProject.getUuid())).isNull();
        assertThat(projectDao.getProjectId(higherIdProject.getUuid()))
                .isEqualTo(higherIdProject.getId());
    }
}
