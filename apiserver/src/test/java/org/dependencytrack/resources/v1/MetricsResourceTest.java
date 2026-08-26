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
package org.dependencytrack.resources.v1;

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthFeature;
import alpine.server.resources.GlobalExceptionHandler;
import jakarta.ws.rs.core.Response;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectCollectionLogic;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.Tag;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.dependencytrack.persistence.jdbi.MetricsTestDao;
import org.glassfish.jersey.inject.hk2.AbstractBinder;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.hamcrest.Matchers.closeTo;
import static org.mockito.Mockito.mock;

public class MetricsResourceTest extends ResourceTest {

    private static final DexEngine DEX_ENGINE_MOCK = mock(DexEngine.class);

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(MetricsResource.class)
                    .register(ApiFilter.class)
                    .register(AuthFeature.class)
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bind(DEX_ENGINE_MOCK).to(DexEngine.class);
                        }
                    })
                    .register(GlobalExceptionHandler.class));

    @Test
    public void getProjectCurrentMetricsAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/project/" + project.getUuid() + "/current")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void getProjectMetricsSinceAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/project/" + project.getUuid() + "/since/20250101")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void getProjectMetricsXDaysAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/project/" + project.getUuid() + "/days/666")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void refreshProjectMetricsAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/project/" + project.getUuid() + "/refresh")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void getComponentCurrentMetricsAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/component/" + component.getUuid() + "/current")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void getComponentMetricsSinceAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/component/" + component.getUuid() + "/since/20250101")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void getComponentMetricsXDaysAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/component/" + component.getUuid() + "/days/666")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void refreshComponentMetricsAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/component/" + component.getUuid() + "/refresh")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void getCurrentPortfolioMetricsEmptyTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final Response response = jersey
                .target(V1_METRICS + "/portfolio/current")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "components": 0,
                          "critical": 0,
                          "findingsAudited": 0,
                          "findingsTotal": 0,
                          "findingsUnaudited": 0,
                          "firstOccurrence": "${json-unit.any-number}",
                          "high": 0,
                          "inheritedRiskScore": 0.0,
                          "kev": 0,
                          "lastOccurrence": "${json-unit.any-number}",
                          "low": 0,
                          "medium": 0,
                          "policyViolationsAudited": 0,
                          "policyViolationsFail": 0,
                          "policyViolationsInfo": 0,
                          "policyViolationsLicenseAudited": 0,
                          "policyViolationsLicenseTotal": 0,
                          "policyViolationsLicenseUnaudited": 0,
                          "policyViolationsOperationalAudited": 0,
                          "policyViolationsOperationalTotal": 0,
                          "policyViolationsOperationalUnaudited": 0,
                          "policyViolationsSecurityAudited": 0,
                          "policyViolationsSecurityTotal": 0,
                          "policyViolationsSecurityUnaudited": 0,
                          "policyViolationsTotal": 0,
                          "policyViolationsUnaudited": 0,
                          "policyViolationsWarn": 0,
                          "projects": 0,
                          "suppressed": 0,
                          "unassigned": 0,
                          "vulnerabilities": 0,
                          "vulnerableComponents": 0,
                          "vulnerableProjects": 0
                        }
                        """);
    }

    @Test
    public void getCurrentPortfolioMetricsAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var accessibleProjectA = new Project();
        accessibleProjectA.setName("acme-app-a");
        accessibleProjectA.addAccessTeam(super.team);
        qm.persist(accessibleProjectA);

        final var accessibleProjectB = new Project();
        accessibleProjectB.setName("acme-app-b");
        accessibleProjectB.addAccessTeam(super.team);
        qm.persist(accessibleProjectB);

        final var inactiveAccessibleProject = new Project();
        inactiveAccessibleProject.setName("acme-app-inactive");
        inactiveAccessibleProject.setInactiveSince(new Date());
        inactiveAccessibleProject.addAccessTeam(super.team);
        qm.persist(inactiveAccessibleProject);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("acme-app-inaccessible");
        qm.persist(inaccessibleProject);

        final LocalDate today = LocalDate.now(ZoneOffset.UTC);
        final Instant now = Instant.now();

        useJdbiHandle(handle -> {
            var dao = handle.attach(MetricsTestDao.class);

            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today);
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today.minusDays(1));
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today.minusDays(2));

            {
                // Create metrics for "yesterday".

                var accessibleProjectAMetrics = new ProjectMetrics();
                accessibleProjectAMetrics.setProjectId(accessibleProjectA.getId());
                accessibleProjectAMetrics.setComponents(2);
                accessibleProjectAMetrics.setFirstOccurrence(Date.from(now.minus(1, ChronoUnit.DAYS)));
                accessibleProjectAMetrics.setLastOccurrence(accessibleProjectAMetrics.getFirstOccurrence());
                dao.createProjectMetrics(accessibleProjectAMetrics);
            }

            {
                // Create metrics for "today".

                // Do not create metrics for accessibleProjectA.
                // Its metrics from "yesterday" are supposed to carry over to "today".

                var accessibleProjectBMetrics = new ProjectMetrics();
                accessibleProjectBMetrics.setProjectId(accessibleProjectB.getId());
                accessibleProjectBMetrics.setComponents(1);
                accessibleProjectBMetrics.setFirstOccurrence(Date.from(now));
                accessibleProjectBMetrics.setLastOccurrence(accessibleProjectBMetrics.getFirstOccurrence());
                dao.createProjectMetrics(accessibleProjectBMetrics);

                // Metrics of inactive projects must not be considered.
                var inactiveAccessibleProjectMetrics = new ProjectMetrics();
                inactiveAccessibleProjectMetrics.setProjectId(inactiveAccessibleProject.getId());
                inactiveAccessibleProjectMetrics.setComponents(111);
                inactiveAccessibleProjectMetrics.setFirstOccurrence(Date.from(now));
                inactiveAccessibleProjectMetrics.setLastOccurrence(inactiveAccessibleProjectMetrics.getFirstOccurrence());
                dao.createProjectMetrics(inactiveAccessibleProjectMetrics);

                // Metrics of inaccessible projects must not be considered.
                var inaccessibleProjectMetrics = new ProjectMetrics();
                inaccessibleProjectMetrics.setProjectId(inaccessibleProject.getId());
                inaccessibleProjectMetrics.setComponents(666);
                inaccessibleProjectMetrics.setFirstOccurrence(Date.from(now));
                inaccessibleProjectMetrics.setLastOccurrence(inaccessibleProjectMetrics.getFirstOccurrence());
                dao.createProjectMetrics(inaccessibleProjectMetrics);
            }
        });

        final Response response = jersey
                .target(V1_METRICS + "/portfolio/current")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "projects": 2,
                          "components": 3
                        }
                        """);
    }

    @Test
    public void getCurrentPortfolioMetricsGlobalTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        // Portfolio ACL is disabled.

        final var accessibleProjectA = new Project();
        accessibleProjectA.setName("acme-app-a");
        accessibleProjectA.addAccessTeam(super.team);
        qm.persist(accessibleProjectA);

        final var accessibleProjectB = new Project();
        accessibleProjectB.setName("acme-app-b");
        accessibleProjectB.addAccessTeam(super.team);
        qm.persist(accessibleProjectB);

        final var inactiveAccessibleProject = new Project();
        inactiveAccessibleProject.setName("acme-app-inactive");
        inactiveAccessibleProject.setInactiveSince(new Date());
        inactiveAccessibleProject.addAccessTeam(super.team);
        qm.persist(inactiveAccessibleProject);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("acme-app-inaccessible");
        qm.persist(inaccessibleProject);

        final LocalDate today = LocalDate.now(ZoneOffset.UTC);
        final Instant now = Instant.now();

        useJdbiHandle(handle -> {
            var dao = handle.attach(MetricsTestDao.class);

            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today);
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today.minusDays(1));
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today.minusDays(2));

            {
                // Create metrics for "yesterday".

                var accessibleProjectAMetrics = new ProjectMetrics();
                accessibleProjectAMetrics.setProjectId(accessibleProjectA.getId());
                accessibleProjectAMetrics.setComponents(2);
                accessibleProjectAMetrics.setFirstOccurrence(Date.from(now.minus(1, ChronoUnit.DAYS)));
                accessibleProjectAMetrics.setLastOccurrence(accessibleProjectAMetrics.getFirstOccurrence());
                dao.createProjectMetrics(accessibleProjectAMetrics);
            }

            {
                // Create metrics for "today".

                // Do not create metrics for accessibleProjectA.
                // Its metrics from "yesterday" are supposed to carry over to "today".

                var accessibleProjectBMetrics = new ProjectMetrics();
                accessibleProjectBMetrics.setProjectId(accessibleProjectB.getId());
                accessibleProjectBMetrics.setComponents(1);
                accessibleProjectBMetrics.setFirstOccurrence(Date.from(now));
                accessibleProjectBMetrics.setLastOccurrence(accessibleProjectBMetrics.getFirstOccurrence());
                dao.createProjectMetrics(accessibleProjectBMetrics);

                // Metrics of inactive projects must not be considered.
                var inactiveAccessibleProjectMetrics = new ProjectMetrics();
                inactiveAccessibleProjectMetrics.setProjectId(inactiveAccessibleProject.getId());
                inactiveAccessibleProjectMetrics.setComponents(111);
                inactiveAccessibleProjectMetrics.setFirstOccurrence(Date.from(now));
                inactiveAccessibleProjectMetrics.setLastOccurrence(inactiveAccessibleProjectMetrics.getFirstOccurrence());
                dao.createProjectMetrics(inactiveAccessibleProjectMetrics);

                // Metrics of "inaccessible" project must be considered because portfolio ACL is disabled.
                var inaccessibleProjectMetrics = new ProjectMetrics();
                inaccessibleProjectMetrics.setProjectId(inaccessibleProject.getId());
                inaccessibleProjectMetrics.setComponents(666);
                inaccessibleProjectMetrics.setFirstOccurrence(Date.from(now));
                inaccessibleProjectMetrics.setLastOccurrence(inaccessibleProjectMetrics.getFirstOccurrence());
                dao.createProjectMetrics(inaccessibleProjectMetrics);
            }

            handle.useTransaction(tx -> tx.attach(MetricsDao.class).refreshGlobalPortfolioMetrics());
        });

        final Response response = jersey
                .target(V1_METRICS + "/portfolio/current")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "projects": 3,
                          "components": 669
                        }
                        """);
    }

    @Test
    public void getPortfolioMetricsXDaysAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var accessibleProjectA = new Project();
        accessibleProjectA.setName("acme-app-a");
        accessibleProjectA.addAccessTeam(super.team);
        qm.persist(accessibleProjectA);

        final var accessibleProjectB = new Project();
        accessibleProjectB.setName("acme-app-b");
        accessibleProjectB.addAccessTeam(super.team);
        qm.persist(accessibleProjectB);

        final var inactiveAccessibleProject = new Project();
        inactiveAccessibleProject.setName("acme-app-inactive");
        inactiveAccessibleProject.setInactiveSince(new Date());
        inactiveAccessibleProject.addAccessTeam(super.team);
        qm.persist(inactiveAccessibleProject);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("acme-app-inaccessible");
        qm.persist(inaccessibleProject);

        final LocalDate today = LocalDate.now(ZoneOffset.UTC);
        final Instant now = Instant.now();

        useJdbiHandle(handle -> {
            var dao = handle.attach(MetricsTestDao.class);

            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today);
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today.minusDays(1));
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today.minusDays(2));

            {
                // Create metrics for "yesterday".

                var accessibleProjectAMetrics = new ProjectMetrics();
                accessibleProjectAMetrics.setProjectId(accessibleProjectA.getId());
                accessibleProjectAMetrics.setComponents(1);
                accessibleProjectAMetrics.setCritical(1);
                accessibleProjectAMetrics.setFindingsAudited(1);
                accessibleProjectAMetrics.setFindingsTotal(1);
                accessibleProjectAMetrics.setFindingsUnaudited(1);
                accessibleProjectAMetrics.setHigh(1);
                accessibleProjectAMetrics.setInheritedRiskScore(1.1);
                accessibleProjectAMetrics.setLow(1);
                accessibleProjectAMetrics.setMedium(1);
                accessibleProjectAMetrics.setPolicyViolationsAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsFail(1);
                accessibleProjectAMetrics.setPolicyViolationsInfo(1);
                accessibleProjectAMetrics.setPolicyViolationsLicenseAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsLicenseTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsLicenseUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsOperationalAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsOperationalTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsOperationalUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsSecurityAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsSecurityTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsSecurityUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsWarn(1);
                accessibleProjectAMetrics.setSuppressed(1);
                accessibleProjectAMetrics.setUnassigned(1);
                accessibleProjectAMetrics.setVulnerabilities(1);
                accessibleProjectAMetrics.setVulnerableComponents(1);
                accessibleProjectAMetrics.setFirstOccurrence(Date.from(now.minus(1, ChronoUnit.DAYS)));
                accessibleProjectAMetrics.setLastOccurrence(accessibleProjectAMetrics.getFirstOccurrence());
                dao.createProjectMetrics(accessibleProjectAMetrics);
            }

            {
                // Create metrics for "today".

                // Do not create metrics for accessibleProjectA.
                // Its metrics from "yesterday" are supposed to carry over to "today".

                var accessibleProjectBMetrics = new ProjectMetrics();
                accessibleProjectBMetrics.setProjectId(accessibleProjectB.getId());
                accessibleProjectBMetrics.setComponents(2);
                accessibleProjectBMetrics.setCritical(2);
                accessibleProjectBMetrics.setFindingsAudited(2);
                accessibleProjectBMetrics.setFindingsTotal(2);
                accessibleProjectBMetrics.setFindingsUnaudited(2);
                accessibleProjectBMetrics.setHigh(2);
                accessibleProjectBMetrics.setInheritedRiskScore(2.2);
                accessibleProjectBMetrics.setLow(2);
                accessibleProjectBMetrics.setMedium(2);
                accessibleProjectBMetrics.setPolicyViolationsAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsFail(2);
                accessibleProjectBMetrics.setPolicyViolationsInfo(2);
                accessibleProjectBMetrics.setPolicyViolationsLicenseAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsLicenseTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsLicenseUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsOperationalAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsOperationalTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsOperationalUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsSecurityAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsSecurityTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsSecurityUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsWarn(2);
                accessibleProjectBMetrics.setSuppressed(2);
                accessibleProjectBMetrics.setUnassigned(2);
                accessibleProjectBMetrics.setVulnerabilities(2);
                accessibleProjectBMetrics.setVulnerableComponents(2);
                accessibleProjectBMetrics.setFirstOccurrence(Date.from(now));
                accessibleProjectBMetrics.setLastOccurrence(accessibleProjectBMetrics.getFirstOccurrence());
                dao.createProjectMetrics(accessibleProjectBMetrics);

                // Metrics of inactive projects must not be considered.
                var inactiveAccessibleProjectMetrics = new ProjectMetrics();
                inactiveAccessibleProjectMetrics.setProjectId(inactiveAccessibleProject.getId());
                inactiveAccessibleProjectMetrics.setComponents(111);
                inactiveAccessibleProjectMetrics.setFirstOccurrence(Date.from(now));
                inactiveAccessibleProjectMetrics.setLastOccurrence(inactiveAccessibleProjectMetrics.getFirstOccurrence());
                dao.createProjectMetrics(inactiveAccessibleProjectMetrics);

                // Metrics of inaccessible projects must not be considered.
                var inaccessibleProjectMetrics = new ProjectMetrics();
                inaccessibleProjectMetrics.setProjectId(inaccessibleProject.getId());
                inaccessibleProjectMetrics.setVulnerabilities(666);
                inaccessibleProjectMetrics.setFirstOccurrence(Date.from(now));
                inaccessibleProjectMetrics.setLastOccurrence(inaccessibleProjectMetrics.getFirstOccurrence());
                dao.createProjectMetrics(inaccessibleProjectMetrics);
            }
        });

        final Response response = jersey
                .target(V1_METRICS + "/portfolio/3/days")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("inheritedRiskScoreDay2", closeTo(BigDecimal.valueOf(1.1), BigDecimal.valueOf(0.01)))
                .withMatcher("inheritedRiskScoreDay3", closeTo(BigDecimal.valueOf(3.3), BigDecimal.valueOf(0.01)))
                .isEqualTo(/* language=JSON */ """
                        [
                          {
                            "components": 0,
                            "critical": 0,
                            "findingsAudited": 0,
                            "findingsTotal": 0,
                            "findingsUnaudited": 0,
                            "firstOccurrence": "${json-unit.any-number}",
                            "high": 0,
                            "inheritedRiskScore": 0.0,
                            "kev": 0,
                            "lastOccurrence": "${json-unit.any-number}",
                            "low": 0,
                            "medium": 0,
                            "policyViolationsAudited": 0,
                            "policyViolationsFail": 0,
                            "policyViolationsInfo": 0,
                            "policyViolationsLicenseAudited": 0,
                            "policyViolationsLicenseTotal": 0,
                            "policyViolationsLicenseUnaudited": 0,
                            "policyViolationsOperationalAudited": 0,
                            "policyViolationsOperationalTotal": 0,
                            "policyViolationsOperationalUnaudited": 0,
                            "policyViolationsSecurityAudited": 0,
                            "policyViolationsSecurityTotal": 0,
                            "policyViolationsSecurityUnaudited": 0,
                            "policyViolationsTotal": 0,
                            "policyViolationsUnaudited": 0,
                            "policyViolationsWarn": 0,
                            "projects": 0,
                            "suppressed": 0,
                            "unassigned": 0,
                            "vulnerabilities": 0,
                            "vulnerableComponents": 0,
                            "vulnerableProjects": 0
                          },
                          {
                            "components": 1,
                            "critical": 1,
                            "findingsAudited": 1,
                            "findingsTotal": 1,
                            "findingsUnaudited": 1,
                            "firstOccurrence": "${json-unit.any-number}",
                            "high": 1,
                            "inheritedRiskScore": "${json-unit.matches:inheritedRiskScoreDay2}",
                            "kev": 0,
                            "lastOccurrence": "${json-unit.any-number}",
                            "low": 1,
                            "medium": 1,
                            "policyViolationsAudited": 1,
                            "policyViolationsFail": 1,
                            "policyViolationsInfo": 1,
                            "policyViolationsLicenseAudited": 1,
                            "policyViolationsLicenseTotal": 1,
                            "policyViolationsLicenseUnaudited": 1,
                            "policyViolationsOperationalAudited": 1,
                            "policyViolationsOperationalTotal": 1,
                            "policyViolationsOperationalUnaudited": 1,
                            "policyViolationsSecurityAudited": 1,
                            "policyViolationsSecurityTotal": 1,
                            "policyViolationsSecurityUnaudited": 1,
                            "policyViolationsTotal": 1,
                            "policyViolationsUnaudited": 1,
                            "policyViolationsWarn": 1,
                            "projects": 1,
                            "suppressed": 1,
                            "unassigned": 1,
                            "vulnerabilities": 1,
                            "vulnerableComponents": 1,
                            "vulnerableProjects": 1
                          },
                          {
                            "components": 3,
                            "critical": 3,
                            "findingsAudited": 3,
                            "findingsTotal": 3,
                            "findingsUnaudited": 3,
                            "firstOccurrence": "${json-unit.any-number}",
                            "high": 3,
                            "inheritedRiskScore": "${json-unit.matches:inheritedRiskScoreDay3}",
                            "kev": 0,
                            "lastOccurrence": "${json-unit.any-number}",
                            "low": 3,
                            "medium": 3,
                            "policyViolationsAudited": 3,
                            "policyViolationsFail": 3,
                            "policyViolationsInfo": 3,
                            "policyViolationsLicenseAudited": 3,
                            "policyViolationsLicenseTotal": 3,
                            "policyViolationsLicenseUnaudited": 3,
                            "policyViolationsOperationalAudited": 3,
                            "policyViolationsOperationalTotal": 3,
                            "policyViolationsOperationalUnaudited": 3,
                            "policyViolationsSecurityAudited": 3,
                            "policyViolationsSecurityTotal": 3,
                            "policyViolationsSecurityUnaudited": 3,
                            "policyViolationsTotal": 3,
                            "policyViolationsUnaudited": 3,
                            "policyViolationsWarn": 3,
                            "projects": 2,
                            "suppressed": 3,
                            "unassigned": 3,
                            "vulnerabilities": 3,
                            "vulnerableComponents": 3,
                            "vulnerableProjects": 2
                          }
                        ]
                        """);
    }

    @Test
    public void getPortfolioMetricsXDaysGlobalTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        // Portfolio ACL is disabled.

        final var accessibleProjectA = new Project();
        accessibleProjectA.setName("acme-app-a");
        accessibleProjectA.addAccessTeam(super.team);
        qm.persist(accessibleProjectA);

        final var accessibleProjectB = new Project();
        accessibleProjectB.setName("acme-app-b");
        accessibleProjectB.addAccessTeam(super.team);
        qm.persist(accessibleProjectB);

        final var inactiveAccessibleProject = new Project();
        inactiveAccessibleProject.setName("acme-app-inactive");
        inactiveAccessibleProject.setInactiveSince(new Date());
        inactiveAccessibleProject.addAccessTeam(super.team);
        qm.persist(inactiveAccessibleProject);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("acme-app-inaccessible");
        qm.persist(inaccessibleProject);

        final LocalDate today = LocalDate.now(ZoneOffset.UTC);
        final Instant now = Instant.now();

        useJdbiHandle(handle -> {
            var dao = handle.attach(MetricsTestDao.class);

            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today);
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today.minusDays(1));
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today.minusDays(2));

            {
                // Create metrics for "yesterday".

                var accessibleProjectAMetrics = new ProjectMetrics();
                accessibleProjectAMetrics.setProjectId(accessibleProjectA.getId());
                accessibleProjectAMetrics.setComponents(1);
                accessibleProjectAMetrics.setCritical(1);
                accessibleProjectAMetrics.setFindingsAudited(1);
                accessibleProjectAMetrics.setFindingsTotal(1);
                accessibleProjectAMetrics.setFindingsUnaudited(1);
                accessibleProjectAMetrics.setHigh(1);
                accessibleProjectAMetrics.setInheritedRiskScore(1.1);
                accessibleProjectAMetrics.setLow(1);
                accessibleProjectAMetrics.setMedium(1);
                accessibleProjectAMetrics.setPolicyViolationsAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsFail(1);
                accessibleProjectAMetrics.setPolicyViolationsInfo(1);
                accessibleProjectAMetrics.setPolicyViolationsLicenseAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsLicenseTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsLicenseUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsOperationalAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsOperationalTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsOperationalUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsSecurityAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsSecurityTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsSecurityUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsWarn(1);
                accessibleProjectAMetrics.setSuppressed(1);
                accessibleProjectAMetrics.setUnassigned(1);
                accessibleProjectAMetrics.setVulnerabilities(1);
                accessibleProjectAMetrics.setVulnerableComponents(1);
                accessibleProjectAMetrics.setFirstOccurrence(Date.from(now.minus(1, ChronoUnit.DAYS)));
                accessibleProjectAMetrics.setLastOccurrence(accessibleProjectAMetrics.getFirstOccurrence());
                dao.createProjectMetrics(accessibleProjectAMetrics);
            }

            {
                // Create metrics for "today".

                // Do not create metrics for accessibleProjectA.
                // Its metrics from "yesterday" are supposed to carry over to "today".

                var accessibleProjectBMetrics = new ProjectMetrics();
                accessibleProjectBMetrics.setProjectId(accessibleProjectB.getId());
                accessibleProjectBMetrics.setComponents(2);
                accessibleProjectBMetrics.setCritical(2);
                accessibleProjectBMetrics.setFindingsAudited(2);
                accessibleProjectBMetrics.setFindingsTotal(2);
                accessibleProjectBMetrics.setFindingsUnaudited(2);
                accessibleProjectBMetrics.setHigh(2);
                accessibleProjectBMetrics.setInheritedRiskScore(2.2);
                accessibleProjectBMetrics.setLow(2);
                accessibleProjectBMetrics.setMedium(2);
                accessibleProjectBMetrics.setPolicyViolationsAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsFail(2);
                accessibleProjectBMetrics.setPolicyViolationsInfo(2);
                accessibleProjectBMetrics.setPolicyViolationsLicenseAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsLicenseTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsLicenseUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsOperationalAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsOperationalTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsOperationalUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsSecurityAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsSecurityTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsSecurityUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsWarn(2);
                accessibleProjectBMetrics.setSuppressed(2);
                accessibleProjectBMetrics.setUnassigned(2);
                accessibleProjectBMetrics.setVulnerabilities(2);
                accessibleProjectBMetrics.setVulnerableComponents(2);
                accessibleProjectBMetrics.setFirstOccurrence(Date.from(now));
                accessibleProjectBMetrics.setLastOccurrence(accessibleProjectBMetrics.getFirstOccurrence());
                dao.createProjectMetrics(accessibleProjectBMetrics);

                // Metrics of inactive projects must not be considered.
                var inactiveAccessibleProjectMetrics = new ProjectMetrics();
                inactiveAccessibleProjectMetrics.setProjectId(inactiveAccessibleProject.getId());
                inactiveAccessibleProjectMetrics.setComponents(111);
                inactiveAccessibleProjectMetrics.setFirstOccurrence(Date.from(now));
                inactiveAccessibleProjectMetrics.setLastOccurrence(inactiveAccessibleProjectMetrics.getFirstOccurrence());
                dao.createProjectMetrics(inactiveAccessibleProjectMetrics);

                // Metrics of "inaccessible" project must be considered because portfolio ACL is disabled.
                var inaccessibleProjectMetrics = new ProjectMetrics();
                inaccessibleProjectMetrics.setProjectId(inaccessibleProject.getId());
                inaccessibleProjectMetrics.setVulnerabilities(666);
                inaccessibleProjectMetrics.setFirstOccurrence(Date.from(now));
                inaccessibleProjectMetrics.setLastOccurrence(inaccessibleProjectMetrics.getFirstOccurrence());
                dao.createProjectMetrics(inaccessibleProjectMetrics);
            }

            handle.useTransaction(tx -> tx.attach(MetricsDao.class).refreshGlobalPortfolioMetrics());
        });

        final Response response = jersey
                .target(V1_METRICS + "/portfolio/3/days")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("inheritedRiskScoreDay2", closeTo(BigDecimal.valueOf(1.1), BigDecimal.valueOf(0.01)))
                .withMatcher("inheritedRiskScoreDay3", closeTo(BigDecimal.valueOf(3.3), BigDecimal.valueOf(0.01)))
                .isEqualTo(/* language=JSON */ """
                        [
                          {
                            "components": 0,
                            "critical": 0,
                            "findingsAudited": 0,
                            "findingsTotal": 0,
                            "findingsUnaudited": 0,
                            "firstOccurrence": "${json-unit.any-number}",
                            "high": 0,
                            "inheritedRiskScore": 0.0,
                            "kev": 0,
                            "lastOccurrence": "${json-unit.any-number}",
                            "low": 0,
                            "medium": 0,
                            "policyViolationsAudited": 0,
                            "policyViolationsFail": 0,
                            "policyViolationsInfo": 0,
                            "policyViolationsLicenseAudited": 0,
                            "policyViolationsLicenseTotal": 0,
                            "policyViolationsLicenseUnaudited": 0,
                            "policyViolationsOperationalAudited": 0,
                            "policyViolationsOperationalTotal": 0,
                            "policyViolationsOperationalUnaudited": 0,
                            "policyViolationsSecurityAudited": 0,
                            "policyViolationsSecurityTotal": 0,
                            "policyViolationsSecurityUnaudited": 0,
                            "policyViolationsTotal": 0,
                            "policyViolationsUnaudited": 0,
                            "policyViolationsWarn": 0,
                            "projects": 0,
                            "suppressed": 0,
                            "unassigned": 0,
                            "vulnerabilities": 0,
                            "vulnerableComponents": 0,
                            "vulnerableProjects": 0
                          },
                          {
                            "components": 1,
                            "critical": 1,
                            "findingsAudited": 1,
                            "findingsTotal": 1,
                            "findingsUnaudited": 1,
                            "firstOccurrence": "${json-unit.any-number}",
                            "high": 1,
                            "inheritedRiskScore": "${json-unit.matches:inheritedRiskScoreDay2}",
                            "kev": 0,
                            "lastOccurrence": "${json-unit.any-number}",
                            "low": 1,
                            "medium": 1,
                            "policyViolationsAudited": 1,
                            "policyViolationsFail": 1,
                            "policyViolationsInfo": 1,
                            "policyViolationsLicenseAudited": 1,
                            "policyViolationsLicenseTotal": 1,
                            "policyViolationsLicenseUnaudited": 1,
                            "policyViolationsOperationalAudited": 1,
                            "policyViolationsOperationalTotal": 1,
                            "policyViolationsOperationalUnaudited": 1,
                            "policyViolationsSecurityAudited": 1,
                            "policyViolationsSecurityTotal": 1,
                            "policyViolationsSecurityUnaudited": 1,
                            "policyViolationsTotal": 1,
                            "policyViolationsUnaudited": 1,
                            "policyViolationsWarn": 1,
                            "projects": 1,
                            "suppressed": 1,
                            "unassigned": 1,
                            "vulnerabilities": 1,
                            "vulnerableComponents": 1,
                            "vulnerableProjects": 1
                          },
                          {
                            "components": 3,
                            "critical": 3,
                            "findingsAudited": 3,
                            "findingsTotal": 3,
                            "findingsUnaudited": 3,
                            "firstOccurrence": "${json-unit.any-number}",
                            "high": 3,
                            "inheritedRiskScore": "${json-unit.matches:inheritedRiskScoreDay3}",
                            "kev": 0,
                            "lastOccurrence": "${json-unit.any-number}",
                            "low": 3,
                            "medium": 3,
                            "policyViolationsAudited": 3,
                            "policyViolationsFail": 3,
                            "policyViolationsInfo": 3,
                            "policyViolationsLicenseAudited": 3,
                            "policyViolationsLicenseTotal": 3,
                            "policyViolationsLicenseUnaudited": 3,
                            "policyViolationsOperationalAudited": 3,
                            "policyViolationsOperationalTotal": 3,
                            "policyViolationsOperationalUnaudited": 3,
                            "policyViolationsSecurityAudited": 3,
                            "policyViolationsSecurityTotal": 3,
                            "policyViolationsSecurityUnaudited": 3,
                            "policyViolationsTotal": 3,
                            "policyViolationsUnaudited": 3,
                            "policyViolationsWarn": 3,
                            "projects": 3,
                            "suppressed": 3,
                            "unassigned": 3,
                            "vulnerabilities": 669,
                            "vulnerableComponents": 3,
                            "vulnerableProjects": 2
                          }
                        ]
                        """);
    }

    @Test
    public void getPortfolioMetricsSinceAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var accessibleProjectA = new Project();
        accessibleProjectA.setName("acme-app-a");
        accessibleProjectA.addAccessTeam(super.team);
        qm.persist(accessibleProjectA);

        final var accessibleProjectB = new Project();
        accessibleProjectB.setName("acme-app-b");
        accessibleProjectB.addAccessTeam(super.team);
        qm.persist(accessibleProjectB);

        final var inactiveAccessibleProject = new Project();
        inactiveAccessibleProject.setName("acme-app-inactive");
        inactiveAccessibleProject.setInactiveSince(new Date());
        inactiveAccessibleProject.addAccessTeam(super.team);
        qm.persist(inactiveAccessibleProject);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("acme-app-inaccessible");
        qm.persist(inaccessibleProject);

        final LocalDate today = LocalDate.now(ZoneOffset.UTC);
        final Instant now = Instant.now();

        useJdbiHandle(handle -> {
            var dao = handle.attach(MetricsTestDao.class);

            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today);
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today.minusDays(1));
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today.minusDays(2));

            {
                // Create metrics for "yesterday".

                var accessibleProjectAMetrics = new ProjectMetrics();
                accessibleProjectAMetrics.setProjectId(accessibleProjectA.getId());
                accessibleProjectAMetrics.setComponents(1);
                accessibleProjectAMetrics.setCritical(1);
                accessibleProjectAMetrics.setFindingsAudited(1);
                accessibleProjectAMetrics.setFindingsTotal(1);
                accessibleProjectAMetrics.setFindingsUnaudited(1);
                accessibleProjectAMetrics.setHigh(1);
                accessibleProjectAMetrics.setInheritedRiskScore(1.1);
                accessibleProjectAMetrics.setLow(1);
                accessibleProjectAMetrics.setMedium(1);
                accessibleProjectAMetrics.setPolicyViolationsAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsFail(1);
                accessibleProjectAMetrics.setPolicyViolationsInfo(1);
                accessibleProjectAMetrics.setPolicyViolationsLicenseAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsLicenseTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsLicenseUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsOperationalAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsOperationalTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsOperationalUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsSecurityAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsSecurityTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsSecurityUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsWarn(1);
                accessibleProjectAMetrics.setSuppressed(1);
                accessibleProjectAMetrics.setUnassigned(1);
                accessibleProjectAMetrics.setVulnerabilities(1);
                accessibleProjectAMetrics.setVulnerableComponents(1);
                accessibleProjectAMetrics.setFirstOccurrence(Date.from(now.minus(1, ChronoUnit.DAYS)));
                accessibleProjectAMetrics.setLastOccurrence(accessibleProjectAMetrics.getFirstOccurrence());
                dao.createProjectMetrics(accessibleProjectAMetrics);
            }

            {
                // Create metrics for "today".

                // Do not create metrics for accessibleProjectA.
                // Its metrics from "yesterday" are supposed to carry over to "today".

                var accessibleProjectBMetrics = new ProjectMetrics();
                accessibleProjectBMetrics.setProjectId(accessibleProjectB.getId());
                accessibleProjectBMetrics.setComponents(2);
                accessibleProjectBMetrics.setCritical(2);
                accessibleProjectBMetrics.setFindingsAudited(2);
                accessibleProjectBMetrics.setFindingsTotal(2);
                accessibleProjectBMetrics.setFindingsUnaudited(2);
                accessibleProjectBMetrics.setHigh(2);
                accessibleProjectBMetrics.setInheritedRiskScore(2.2);
                accessibleProjectBMetrics.setLow(2);
                accessibleProjectBMetrics.setMedium(2);
                accessibleProjectBMetrics.setPolicyViolationsAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsFail(2);
                accessibleProjectBMetrics.setPolicyViolationsInfo(2);
                accessibleProjectBMetrics.setPolicyViolationsLicenseAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsLicenseTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsLicenseUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsOperationalAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsOperationalTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsOperationalUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsSecurityAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsSecurityTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsSecurityUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsWarn(2);
                accessibleProjectBMetrics.setSuppressed(2);
                accessibleProjectBMetrics.setUnassigned(2);
                accessibleProjectBMetrics.setVulnerabilities(2);
                accessibleProjectBMetrics.setVulnerableComponents(2);
                accessibleProjectBMetrics.setFirstOccurrence(Date.from(now));
                accessibleProjectBMetrics.setLastOccurrence(accessibleProjectBMetrics.getFirstOccurrence());
                dao.createProjectMetrics(accessibleProjectBMetrics);

                // Metrics of inactive projects must not be considered.
                var inactiveAccessibleProjectMetrics = new ProjectMetrics();
                inactiveAccessibleProjectMetrics.setProjectId(inactiveAccessibleProject.getId());
                inactiveAccessibleProjectMetrics.setComponents(111);
                inactiveAccessibleProjectMetrics.setFirstOccurrence(Date.from(now));
                inactiveAccessibleProjectMetrics.setLastOccurrence(inactiveAccessibleProjectMetrics.getFirstOccurrence());
                dao.createProjectMetrics(inactiveAccessibleProjectMetrics);

                // Metrics of inaccessible projects must not be considered.
                var inaccessibleProjectMetrics = new ProjectMetrics();
                inaccessibleProjectMetrics.setProjectId(inaccessibleProject.getId());
                inaccessibleProjectMetrics.setVulnerabilities(666);
                inaccessibleProjectMetrics.setFirstOccurrence(Date.from(now));
                inaccessibleProjectMetrics.setLastOccurrence(inaccessibleProjectMetrics.getFirstOccurrence());
                dao.createProjectMetrics(inaccessibleProjectMetrics);
            }
        });

        final Response response = jersey
                .target(V1_METRICS + "/portfolio/since/" + today.minusDays(2).format(DateTimeFormatter.ofPattern("yyyyMMdd")))
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("inheritedRiskScoreDay2", closeTo(BigDecimal.valueOf(1.1), BigDecimal.valueOf(0.01)))
                .withMatcher("inheritedRiskScoreDay3", closeTo(BigDecimal.valueOf(3.3), BigDecimal.valueOf(0.01)))
                .isEqualTo(/* language=JSON */ """
                        [
                          {
                            "components": 0,
                            "critical": 0,
                            "findingsAudited": 0,
                            "findingsTotal": 0,
                            "findingsUnaudited": 0,
                            "firstOccurrence": "${json-unit.any-number}",
                            "high": 0,
                            "inheritedRiskScore": 0.0,
                            "kev": 0,
                            "lastOccurrence": "${json-unit.any-number}",
                            "low": 0,
                            "medium": 0,
                            "policyViolationsAudited": 0,
                            "policyViolationsFail": 0,
                            "policyViolationsInfo": 0,
                            "policyViolationsLicenseAudited": 0,
                            "policyViolationsLicenseTotal": 0,
                            "policyViolationsLicenseUnaudited": 0,
                            "policyViolationsOperationalAudited": 0,
                            "policyViolationsOperationalTotal": 0,
                            "policyViolationsOperationalUnaudited": 0,
                            "policyViolationsSecurityAudited": 0,
                            "policyViolationsSecurityTotal": 0,
                            "policyViolationsSecurityUnaudited": 0,
                            "policyViolationsTotal": 0,
                            "policyViolationsUnaudited": 0,
                            "policyViolationsWarn": 0,
                            "projects": 0,
                            "suppressed": 0,
                            "unassigned": 0,
                            "vulnerabilities": 0,
                            "vulnerableComponents": 0,
                            "vulnerableProjects": 0
                          },
                          {
                            "components": 1,
                            "critical": 1,
                            "findingsAudited": 1,
                            "findingsTotal": 1,
                            "findingsUnaudited": 1,
                            "firstOccurrence": "${json-unit.any-number}",
                            "high": 1,
                            "inheritedRiskScore": "${json-unit.matches:inheritedRiskScoreDay2}",
                            "kev": 0,
                            "lastOccurrence": "${json-unit.any-number}",
                            "low": 1,
                            "medium": 1,
                            "policyViolationsAudited": 1,
                            "policyViolationsFail": 1,
                            "policyViolationsInfo": 1,
                            "policyViolationsLicenseAudited": 1,
                            "policyViolationsLicenseTotal": 1,
                            "policyViolationsLicenseUnaudited": 1,
                            "policyViolationsOperationalAudited": 1,
                            "policyViolationsOperationalTotal": 1,
                            "policyViolationsOperationalUnaudited": 1,
                            "policyViolationsSecurityAudited": 1,
                            "policyViolationsSecurityTotal": 1,
                            "policyViolationsSecurityUnaudited": 1,
                            "policyViolationsTotal": 1,
                            "policyViolationsUnaudited": 1,
                            "policyViolationsWarn": 1,
                            "projects": 1,
                            "suppressed": 1,
                            "unassigned": 1,
                            "vulnerabilities": 1,
                            "vulnerableComponents": 1,
                            "vulnerableProjects": 1
                          },
                          {
                            "components": 3,
                            "critical": 3,
                            "findingsAudited": 3,
                            "findingsTotal": 3,
                            "findingsUnaudited": 3,
                            "firstOccurrence": "${json-unit.any-number}",
                            "high": 3,
                            "inheritedRiskScore": "${json-unit.matches:inheritedRiskScoreDay3}",
                            "kev": 0,
                            "lastOccurrence": "${json-unit.any-number}",
                            "low": 3,
                            "medium": 3,
                            "policyViolationsAudited": 3,
                            "policyViolationsFail": 3,
                            "policyViolationsInfo": 3,
                            "policyViolationsLicenseAudited": 3,
                            "policyViolationsLicenseTotal": 3,
                            "policyViolationsLicenseUnaudited": 3,
                            "policyViolationsOperationalAudited": 3,
                            "policyViolationsOperationalTotal": 3,
                            "policyViolationsOperationalUnaudited": 3,
                            "policyViolationsSecurityAudited": 3,
                            "policyViolationsSecurityTotal": 3,
                            "policyViolationsSecurityUnaudited": 3,
                            "policyViolationsTotal": 3,
                            "policyViolationsUnaudited": 3,
                            "policyViolationsWarn": 3,
                            "projects": 2,
                            "suppressed": 3,
                            "unassigned": 3,
                            "vulnerabilities": 3,
                            "vulnerableComponents": 3,
                            "vulnerableProjects": 2
                          }
                        ]
                        """);
    }

    @Test
    public void getPortfolioMetricsSinceGlobalTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        // Portfolio ACL is disabled.

        final var accessibleProjectA = new Project();
        accessibleProjectA.setName("acme-app-a");
        accessibleProjectA.addAccessTeam(super.team);
        qm.persist(accessibleProjectA);

        final var accessibleProjectB = new Project();
        accessibleProjectB.setName("acme-app-b");
        accessibleProjectB.addAccessTeam(super.team);
        qm.persist(accessibleProjectB);

        final var inactiveAccessibleProject = new Project();
        inactiveAccessibleProject.setName("acme-app-inactive");
        inactiveAccessibleProject.setInactiveSince(new Date());
        inactiveAccessibleProject.addAccessTeam(super.team);
        qm.persist(inactiveAccessibleProject);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("acme-app-inaccessible");
        qm.persist(inaccessibleProject);

        final LocalDate today = LocalDate.now(ZoneOffset.UTC);
        final Instant now = Instant.now();

        useJdbiHandle(handle -> {
            var dao = handle.attach(MetricsTestDao.class);

            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today);
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today.minusDays(1));
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today.minusDays(2));

            {
                // Create metrics for "yesterday".

                var accessibleProjectAMetrics = new ProjectMetrics();
                accessibleProjectAMetrics.setProjectId(accessibleProjectA.getId());
                accessibleProjectAMetrics.setComponents(1);
                accessibleProjectAMetrics.setCritical(1);
                accessibleProjectAMetrics.setFindingsAudited(1);
                accessibleProjectAMetrics.setFindingsTotal(1);
                accessibleProjectAMetrics.setFindingsUnaudited(1);
                accessibleProjectAMetrics.setHigh(1);
                accessibleProjectAMetrics.setInheritedRiskScore(1.1);
                accessibleProjectAMetrics.setLow(1);
                accessibleProjectAMetrics.setMedium(1);
                accessibleProjectAMetrics.setPolicyViolationsAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsFail(1);
                accessibleProjectAMetrics.setPolicyViolationsInfo(1);
                accessibleProjectAMetrics.setPolicyViolationsLicenseAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsLicenseTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsLicenseUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsOperationalAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsOperationalTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsOperationalUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsSecurityAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsSecurityTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsSecurityUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsWarn(1);
                accessibleProjectAMetrics.setSuppressed(1);
                accessibleProjectAMetrics.setUnassigned(1);
                accessibleProjectAMetrics.setVulnerabilities(1);
                accessibleProjectAMetrics.setVulnerableComponents(1);
                accessibleProjectAMetrics.setFirstOccurrence(Date.from(now.minus(1, ChronoUnit.DAYS)));
                accessibleProjectAMetrics.setLastOccurrence(accessibleProjectAMetrics.getFirstOccurrence());
                dao.createProjectMetrics(accessibleProjectAMetrics);
            }

            {
                // Create metrics for "today".

                // Do not create metrics for accessibleProjectA.
                // Its metrics from "yesterday" are supposed to carry over to "today".

                var accessibleProjectBMetrics = new ProjectMetrics();
                accessibleProjectBMetrics.setProjectId(accessibleProjectB.getId());
                accessibleProjectBMetrics.setComponents(2);
                accessibleProjectBMetrics.setCritical(2);
                accessibleProjectBMetrics.setFindingsAudited(2);
                accessibleProjectBMetrics.setFindingsTotal(2);
                accessibleProjectBMetrics.setFindingsUnaudited(2);
                accessibleProjectBMetrics.setHigh(2);
                accessibleProjectBMetrics.setInheritedRiskScore(2.2);
                accessibleProjectBMetrics.setLow(2);
                accessibleProjectBMetrics.setMedium(2);
                accessibleProjectBMetrics.setPolicyViolationsAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsFail(2);
                accessibleProjectBMetrics.setPolicyViolationsInfo(2);
                accessibleProjectBMetrics.setPolicyViolationsLicenseAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsLicenseTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsLicenseUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsOperationalAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsOperationalTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsOperationalUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsSecurityAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsSecurityTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsSecurityUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsWarn(2);
                accessibleProjectBMetrics.setSuppressed(2);
                accessibleProjectBMetrics.setUnassigned(2);
                accessibleProjectBMetrics.setVulnerabilities(2);
                accessibleProjectBMetrics.setVulnerableComponents(2);
                accessibleProjectBMetrics.setFirstOccurrence(Date.from(now));
                accessibleProjectBMetrics.setLastOccurrence(accessibleProjectBMetrics.getFirstOccurrence());
                dao.createProjectMetrics(accessibleProjectBMetrics);

                // Metrics of inactive projects must not be considered.
                var inactiveAccessibleProjectMetrics = new ProjectMetrics();
                inactiveAccessibleProjectMetrics.setProjectId(inactiveAccessibleProject.getId());
                inactiveAccessibleProjectMetrics.setComponents(111);
                inactiveAccessibleProjectMetrics.setFirstOccurrence(Date.from(now));
                inactiveAccessibleProjectMetrics.setLastOccurrence(inactiveAccessibleProjectMetrics.getFirstOccurrence());
                dao.createProjectMetrics(inactiveAccessibleProjectMetrics);

                // Metrics of "inaccessible" project must be considered because portfolio ACL is disabled.
                var inaccessibleProjectMetrics = new ProjectMetrics();
                inaccessibleProjectMetrics.setProjectId(inaccessibleProject.getId());
                inaccessibleProjectMetrics.setVulnerabilities(666);
                inaccessibleProjectMetrics.setFirstOccurrence(Date.from(now));
                inaccessibleProjectMetrics.setLastOccurrence(inaccessibleProjectMetrics.getFirstOccurrence());
                dao.createProjectMetrics(inaccessibleProjectMetrics);
            }

            handle.useTransaction(tx -> tx.attach(MetricsDao.class).refreshGlobalPortfolioMetrics());
        });

        final Response response = jersey
                .target(V1_METRICS + "/portfolio/since/" + today.minusDays(2).format(DateTimeFormatter.ofPattern("yyyyMMdd")))
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("inheritedRiskScoreDay2", closeTo(BigDecimal.valueOf(1.1), BigDecimal.valueOf(0.01)))
                .withMatcher("inheritedRiskScoreDay3", closeTo(BigDecimal.valueOf(3.3), BigDecimal.valueOf(0.01)))
                .isEqualTo(/* language=JSON */ """
                        [
                          {
                            "components": 0,
                            "critical": 0,
                            "findingsAudited": 0,
                            "findingsTotal": 0,
                            "findingsUnaudited": 0,
                            "firstOccurrence": "${json-unit.any-number}",
                            "high": 0,
                            "inheritedRiskScore": 0.0,
                            "kev": 0,
                            "lastOccurrence": "${json-unit.any-number}",
                            "low": 0,
                            "medium": 0,
                            "policyViolationsAudited": 0,
                            "policyViolationsFail": 0,
                            "policyViolationsInfo": 0,
                            "policyViolationsLicenseAudited": 0,
                            "policyViolationsLicenseTotal": 0,
                            "policyViolationsLicenseUnaudited": 0,
                            "policyViolationsOperationalAudited": 0,
                            "policyViolationsOperationalTotal": 0,
                            "policyViolationsOperationalUnaudited": 0,
                            "policyViolationsSecurityAudited": 0,
                            "policyViolationsSecurityTotal": 0,
                            "policyViolationsSecurityUnaudited": 0,
                            "policyViolationsTotal": 0,
                            "policyViolationsUnaudited": 0,
                            "policyViolationsWarn": 0,
                            "projects": 0,
                            "suppressed": 0,
                            "unassigned": 0,
                            "vulnerabilities": 0,
                            "vulnerableComponents": 0,
                            "vulnerableProjects": 0
                          },
                          {
                            "components": 1,
                            "critical": 1,
                            "findingsAudited": 1,
                            "findingsTotal": 1,
                            "findingsUnaudited": 1,
                            "firstOccurrence": "${json-unit.any-number}",
                            "high": 1,
                            "inheritedRiskScore": "${json-unit.matches:inheritedRiskScoreDay2}",
                            "kev": 0,
                            "lastOccurrence": "${json-unit.any-number}",
                            "low": 1,
                            "medium": 1,
                            "policyViolationsAudited": 1,
                            "policyViolationsFail": 1,
                            "policyViolationsInfo": 1,
                            "policyViolationsLicenseAudited": 1,
                            "policyViolationsLicenseTotal": 1,
                            "policyViolationsLicenseUnaudited": 1,
                            "policyViolationsOperationalAudited": 1,
                            "policyViolationsOperationalTotal": 1,
                            "policyViolationsOperationalUnaudited": 1,
                            "policyViolationsSecurityAudited": 1,
                            "policyViolationsSecurityTotal": 1,
                            "policyViolationsSecurityUnaudited": 1,
                            "policyViolationsTotal": 1,
                            "policyViolationsUnaudited": 1,
                            "policyViolationsWarn": 1,
                            "projects": 1,
                            "suppressed": 1,
                            "unassigned": 1,
                            "vulnerabilities": 1,
                            "vulnerableComponents": 1,
                            "vulnerableProjects": 1
                          },
                          {
                            "components": 3,
                            "critical": 3,
                            "findingsAudited": 3,
                            "findingsTotal": 3,
                            "findingsUnaudited": 3,
                            "firstOccurrence": "${json-unit.any-number}",
                            "high": 3,
                            "inheritedRiskScore": "${json-unit.matches:inheritedRiskScoreDay3}",
                            "kev": 0,
                            "lastOccurrence": "${json-unit.any-number}",
                            "low": 3,
                            "medium": 3,
                            "policyViolationsAudited": 3,
                            "policyViolationsFail": 3,
                            "policyViolationsInfo": 3,
                            "policyViolationsLicenseAudited": 3,
                            "policyViolationsLicenseTotal": 3,
                            "policyViolationsLicenseUnaudited": 3,
                            "policyViolationsOperationalAudited": 3,
                            "policyViolationsOperationalTotal": 3,
                            "policyViolationsOperationalUnaudited": 3,
                            "policyViolationsSecurityAudited": 3,
                            "policyViolationsSecurityTotal": 3,
                            "policyViolationsSecurityUnaudited": 3,
                            "policyViolationsTotal": 3,
                            "policyViolationsUnaudited": 3,
                            "policyViolationsWarn": 3,
                            "projects": 3,
                            "suppressed": 3,
                            "unassigned": 3,
                            "vulnerabilities": 669,
                            "vulnerableComponents": 3,
                            "vulnerableProjects": 2
                          }
                        ]
                        """);
    }

    @Test
    void shouldReturnZeroMetricsForEmptyCollectionProject() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var parentProject = new Project();
        parentProject.setName("acme-empty-parent");
        parentProject.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        qm.createProject(parentProject, List.of(), false);

        final Response response = jersey
                .target(V1_METRICS + "/project/" + parentProject.getUuid() + "/current")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "critical": 0,
                          "components": 0
                        }
                        """);
    }

    @Test
    void shouldReturnCollectionProjectMetricsForDirectChildren() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var parentProject = new Project();
        parentProject.setName("acme-parent");
        parentProject.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        qm.createProject(parentProject, List.of(), false);

        final var childA = new Project();
        childA.setName("acme-child-a");
        childA.setParent(parentProject);
        qm.persist(childA);

        final var childB = new Project();
        childB.setName("acme-child-b");
        childB.setParent(parentProject);
        qm.persist(childB);

        useJdbiHandle(handle -> {
            final var testDao = handle.attach(MetricsTestDao.class);
            final LocalDate today = LocalDate.now(ZoneOffset.UTC);
            testDao.createMetricsPartitionsForDate("PROJECTMETRICS", today);
            final Instant now = Instant.now();

            final var metricsA = new ProjectMetrics();
            metricsA.setProjectId(childA.getId());
            metricsA.setCritical(2);
            metricsA.setHigh(3);
            metricsA.setMedium(1);
            metricsA.setComponents(10);
            metricsA.setVulnerabilities(6);
            metricsA.setVulnerableComponents(4);
            metricsA.setFirstOccurrence(Date.from(now));
            metricsA.setLastOccurrence(Date.from(now));
            testDao.createProjectMetrics(metricsA);

            final var metricsB = new ProjectMetrics();
            metricsB.setProjectId(childB.getId());
            metricsB.setCritical(1);
            metricsB.setHigh(2);
            metricsB.setMedium(3);
            metricsB.setComponents(5);
            metricsB.setVulnerabilities(6);
            metricsB.setVulnerableComponents(3);
            metricsB.setFirstOccurrence(Date.from(now));
            metricsB.setLastOccurrence(Date.from(now));
            testDao.createProjectMetrics(metricsB);
        });

        final Response response = jersey
                .target(V1_METRICS + "/project/" + parentProject.getUuid() + "/current")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "critical": 3,
                          "high": 5,
                          "medium": 4,
                          "vulnerabilities": 12,
                          "vulnerableComponents": 7,
                          "components": 15,
                          "firstOccurrence": "${json-unit.any-number}",
                          "lastOccurrence": "${json-unit.any-number}"
                        }
                        """);
    }

    @Test
    void shouldReturnCollectionProjectMetricsForDirectChildrenWithTag() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Tag prodTag = qm.createTag("prod");

        final var parentProject = new Project();
        parentProject.setName("acme-parent");
        parentProject.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN_WITH_TAG);
        parentProject.setCollectionTag(prodTag);
        qm.createProject(parentProject, List.of(), false);

        final var childTagged = new Project();
        childTagged.setName("acme-child-tagged");
        childTagged.setParent(parentProject);
        qm.createProject(childTagged, List.of(prodTag), false);

        final var childUntagged = new Project();
        childUntagged.setName("acme-child-untagged");
        childUntagged.setParent(parentProject);
        qm.persist(childUntagged);

        useJdbiHandle(handle -> {
            final var testDao = handle.attach(MetricsTestDao.class);
            final LocalDate today = LocalDate.now(ZoneOffset.UTC);
            testDao.createMetricsPartitionsForDate("PROJECTMETRICS", today);
            final Instant now = Instant.now();

            final var metricsTagged = new ProjectMetrics();
            metricsTagged.setProjectId(childTagged.getId());
            metricsTagged.setCritical(5);
            metricsTagged.setComponents(10);
            metricsTagged.setFirstOccurrence(Date.from(now));
            metricsTagged.setLastOccurrence(Date.from(now));
            testDao.createProjectMetrics(metricsTagged);

            final var metricsUntagged = new ProjectMetrics();
            metricsUntagged.setProjectId(childUntagged.getId());
            metricsUntagged.setCritical(99);
            metricsUntagged.setComponents(99);
            metricsUntagged.setFirstOccurrence(Date.from(now));
            metricsUntagged.setLastOccurrence(Date.from(now));
            testDao.createProjectMetrics(metricsUntagged);
        });

        final Response response = jersey
                .target(V1_METRICS + "/project/" + parentProject.getUuid() + "/current")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "critical": 5,
                          "components": 10,
                          "firstOccurrence": "${json-unit.any-number}",
                          "lastOccurrence": "${json-unit.any-number}"
                        }
                        """);
    }

    @Test
    void shouldReturnCollectionProjectMetricsForDays() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var parentProject = new Project();
        parentProject.setName("acme-parent");
        parentProject.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        qm.createProject(parentProject, List.of(), false);

        final var child = new Project();
        child.setName("acme-child");
        child.setParent(parentProject);
        qm.persist(child);

        final LocalDate today = LocalDate.now(ZoneOffset.UTC);
        final LocalDate yesterday = today.minusDays(1);
        final Instant now = Instant.now();

        useJdbiHandle(handle -> {
            final var testDao = handle.attach(MetricsTestDao.class);
            testDao.createMetricsPartitionsForDate("PROJECTMETRICS", today);
            testDao.createMetricsPartitionsForDate("PROJECTMETRICS", yesterday);

            final var metricsToday = new ProjectMetrics();
            metricsToday.setProjectId(child.getId());
            metricsToday.setCritical(5);
            metricsToday.setComponents(10);
            metricsToday.setFirstOccurrence(Date.from(now));
            metricsToday.setLastOccurrence(metricsToday.getFirstOccurrence());
            testDao.createProjectMetrics(metricsToday);

            final var metricsYesterday = new ProjectMetrics();
            metricsYesterday.setProjectId(child.getId());
            metricsYesterday.setCritical(3);
            metricsYesterday.setComponents(8);
            metricsYesterday.setFirstOccurrence(Date.from(now.minus(1, ChronoUnit.DAYS)));
            metricsYesterday.setLastOccurrence(metricsYesterday.getFirstOccurrence());
            testDao.createProjectMetrics(metricsYesterday);
        });

        // /days/1 goes back 1 day (yesterday through today = 2 entries).
        final Response response = jersey
                .target(V1_METRICS + "/project/" + parentProject.getUuid() + "/days/1")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        [
                          {
                            "critical": 3,
                            "components": 8,
                            "firstOccurrence": "${json-unit.any-number}",
                            "lastOccurrence": "${json-unit.any-number}"
                          },
                          {
                            "critical": 5,
                            "components": 10,
                            "firstOccurrence": "${json-unit.any-number}",
                            "lastOccurrence": "${json-unit.any-number}"
                          }
                        ]
                        """);
    }

    @Test
    void shouldReturnCollectionProjectMetricsSince() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var parentProject = new Project();
        parentProject.setName("acme-parent");
        parentProject.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        qm.createProject(parentProject, List.of(), false);

        final var child = new Project();
        child.setName("acme-child");
        child.setParent(parentProject);
        qm.persist(child);

        final LocalDate today = LocalDate.now(ZoneOffset.UTC);
        final LocalDate yesterday = today.minusDays(1);
        final Instant now = Instant.now();

        useJdbiHandle(handle -> {
            final var testDao = handle.attach(MetricsTestDao.class);
            testDao.createMetricsPartitionsForDate("PROJECTMETRICS", today);
            testDao.createMetricsPartitionsForDate("PROJECTMETRICS", yesterday);

            final var metricsToday = new ProjectMetrics();
            metricsToday.setProjectId(child.getId());
            metricsToday.setCritical(4);
            metricsToday.setComponents(12);
            metricsToday.setFirstOccurrence(Date.from(now));
            metricsToday.setLastOccurrence(metricsToday.getFirstOccurrence());
            testDao.createProjectMetrics(metricsToday);

            final var metricsYesterday = new ProjectMetrics();
            metricsYesterday.setProjectId(child.getId());
            metricsYesterday.setCritical(2);
            metricsYesterday.setComponents(6);
            metricsYesterday.setFirstOccurrence(Date.from(now.minus(1, ChronoUnit.DAYS)));
            metricsYesterday.setLastOccurrence(metricsYesterday.getFirstOccurrence());
            testDao.createProjectMetrics(metricsYesterday);
        });

        // /since/{today} covers only today.
        final String todayStr = today.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        final Response response = jersey
                .target(V1_METRICS + "/project/" + parentProject.getUuid() + "/since/" + todayStr)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        [
                          {
                            "critical": 4,
                            "components": 12,
                            "firstOccurrence": "${json-unit.any-number}",
                            "lastOccurrence": "${json-unit.any-number}"
                          }
                        ]
                        """);

        // /since/{yesterday} covers yesterday + today.
        final String yesterdayStr = yesterday.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        final Response response2 = jersey
                .target(V1_METRICS + "/project/" + parentProject.getUuid() + "/since/" + yesterdayStr)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response2.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response2))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .inPath("$")
                .isArray()
                .hasSize(2);
    }

    @Test
    void shouldReturnCollectionProjectMetricsForLatestVersionChildren() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var parentProject = new Project();
        parentProject.setName("acme-parent");
        parentProject.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_LATEST_VERSION_CHILDREN);
        qm.createProject(parentProject, List.of(), false);

        final var childLatest = new Project();
        childLatest.setName("acme-child-latest");
        childLatest.setParent(parentProject);
        childLatest.setIsLatest(true);
        qm.persist(childLatest);

        final var childNotLatest = new Project();
        childNotLatest.setName("acme-child-old");
        childNotLatest.setParent(parentProject);
        childNotLatest.setIsLatest(false);
        qm.persist(childNotLatest);

        useJdbiHandle(handle -> {
            final var testDao = handle.attach(MetricsTestDao.class);
            final LocalDate today = LocalDate.now(ZoneOffset.UTC);
            testDao.createMetricsPartitionsForDate("PROJECTMETRICS", today);
            final Instant now = Instant.now();

            final var metricsLatest = new ProjectMetrics();
            metricsLatest.setProjectId(childLatest.getId());
            metricsLatest.setCritical(7);
            metricsLatest.setComponents(20);
            metricsLatest.setFirstOccurrence(Date.from(now));
            metricsLatest.setLastOccurrence(Date.from(now));
            testDao.createProjectMetrics(metricsLatest);

            final var metricsOld = new ProjectMetrics();
            metricsOld.setProjectId(childNotLatest.getId());
            metricsOld.setCritical(99);
            metricsOld.setComponents(99);
            metricsOld.setFirstOccurrence(Date.from(now));
            metricsOld.setLastOccurrence(Date.from(now));
            testDao.createProjectMetrics(metricsOld);
        });

        final Response response = jersey
                .target(V1_METRICS + "/project/" + parentProject.getUuid() + "/current")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "critical": 7,
                          "components": 20,
                          "firstOccurrence": "${json-unit.any-number}",
                          "lastOccurrence": "${json-unit.any-number}"
                        }
                        """);
    }

    @Test
    void shouldReturnNestedCollectionProjectMetrics() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final Tag prodTag = qm.createTag("prod");

        final var parent = new Project();
        parent.setName("acme-parent");
        parent.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        qm.createProject(parent, List.of(), false);

        final var childCollection = new Project();
        childCollection.setName("acme-child-collection");
        childCollection.setParent(parent);
        childCollection.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN_WITH_TAG);
        childCollection.setCollectionTag(prodTag);
        qm.createProject(childCollection, List.of(), false);

        final var childRegular = new Project();
        childRegular.setName("acme-child-regular");
        childRegular.setParent(parent);
        qm.persist(childRegular);

        final var grandchildTagged = new Project();
        grandchildTagged.setName("acme-grandchild-tagged");
        grandchildTagged.setParent(childCollection);
        qm.createProject(grandchildTagged, List.of(prodTag), false);

        final var grandchildUntagged = new Project();
        grandchildUntagged.setName("acme-grandchild-untagged");
        grandchildUntagged.setParent(childCollection);
        qm.persist(grandchildUntagged);

        useJdbiHandle(handle -> {
            final var testDao = handle.attach(MetricsTestDao.class);
            final LocalDate today = LocalDate.now(ZoneOffset.UTC);
            testDao.createMetricsPartitionsForDate("PROJECTMETRICS", today);
            final Instant now = Instant.now();

            final var metricsChildRegular = new ProjectMetrics();
            metricsChildRegular.setProjectId(childRegular.getId());
            metricsChildRegular.setCritical(3);
            metricsChildRegular.setFirstOccurrence(Date.from(now));
            metricsChildRegular.setLastOccurrence(Date.from(now));
            testDao.createProjectMetrics(metricsChildRegular);

            final var metricsGrandchildTagged = new ProjectMetrics();
            metricsGrandchildTagged.setProjectId(grandchildTagged.getId());
            metricsGrandchildTagged.setCritical(5);
            metricsGrandchildTagged.setFirstOccurrence(Date.from(now));
            metricsGrandchildTagged.setLastOccurrence(Date.from(now));
            testDao.createProjectMetrics(metricsGrandchildTagged);

            final var metricsGrandchildUntagged = new ProjectMetrics();
            metricsGrandchildUntagged.setProjectId(grandchildUntagged.getId());
            metricsGrandchildUntagged.setCritical(99);
            metricsGrandchildUntagged.setFirstOccurrence(Date.from(now));
            metricsGrandchildUntagged.setLastOccurrence(Date.from(now));
            testDao.createProjectMetrics(metricsGrandchildUntagged);
        });

        final Response response = jersey
                .target(V1_METRICS + "/project/" + parent.getUuid() + "/current")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "critical": 8,
                          "firstOccurrence": "${json-unit.any-number}",
                          "lastOccurrence": "${json-unit.any-number}"
                        }
                        """);
    }

    @Test
    void shouldReturnCollectionProjectMetricsWithAcl() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var parent = new Project();
        parent.setName("acme-parent");
        parent.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        qm.persist(parent);
        parent.addAccessTeam(super.team);

        final var childA = new Project();
        childA.setName("acme-child-a");
        childA.setParent(parent);
        qm.persist(childA);

        final var childB = new Project();
        childB.setName("acme-child-b");
        childB.setParent(parent);
        qm.persist(childB);

        useJdbiHandle(handle -> {
            final var testDao = handle.attach(MetricsTestDao.class);
            final LocalDate today = LocalDate.now(ZoneOffset.UTC);
            testDao.createMetricsPartitionsForDate("PROJECTMETRICS", today);

            final Instant now = Instant.now();

            final var metricsA = new ProjectMetrics();
            metricsA.setProjectId(childA.getId());
            metricsA.setCritical(5);
            metricsA.setFirstOccurrence(Date.from(now));
            metricsA.setLastOccurrence(Date.from(now));
            testDao.createProjectMetrics(metricsA);

            final var metricsB = new ProjectMetrics();
            metricsB.setProjectId(childB.getId());
            metricsB.setCritical(3);
            metricsB.setFirstOccurrence(Date.from(now));
            metricsB.setLastOccurrence(Date.from(now));
            testDao.createProjectMetrics(metricsB);
        });

        final Response response = jersey
                .target(V1_METRICS + "/project/" + parent.getUuid() + "/current")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "critical": 8,
                          "firstOccurrence": "${json-unit.any-number}",
                          "lastOccurrence": "${json-unit.any-number}"
                        }
                        """);
    }

    @Test
    void shouldReturnNestedCollectionProjectMetricsWithAcl() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var parent = new Project();
        parent.setName("acme-parent");
        parent.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        qm.persist(parent);
        parent.addAccessTeam(super.team);

        final var childCollection = new Project();
        childCollection.setName("acme-child-collection");
        childCollection.setParent(parent);
        childCollection.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        qm.persist(childCollection);

        final var grandchildA = new Project();
        grandchildA.setName("acme-grandchild-a");
        grandchildA.setParent(childCollection);
        qm.persist(grandchildA);

        final var grandchildB = new Project();
        grandchildB.setName("acme-grandchild-b");
        grandchildB.setParent(childCollection);
        qm.persist(grandchildB);

        useJdbiHandle(handle -> {
            final var testDao = handle.attach(MetricsTestDao.class);
            final LocalDate today = LocalDate.now(ZoneOffset.UTC);
            testDao.createMetricsPartitionsForDate("PROJECTMETRICS", today);

            final Instant now = Instant.now();

            final var metricsA = new ProjectMetrics();
            metricsA.setProjectId(grandchildA.getId());
            metricsA.setCritical(7);
            metricsA.setFirstOccurrence(Date.from(now));
            metricsA.setLastOccurrence(Date.from(now));
            testDao.createProjectMetrics(metricsA);

            final var metricsB = new ProjectMetrics();
            metricsB.setProjectId(grandchildB.getId());
            metricsB.setCritical(3);
            metricsB.setFirstOccurrence(Date.from(now));
            metricsB.setLastOccurrence(Date.from(now));
            testDao.createProjectMetrics(metricsB);
        });

        final Response response = jersey
                .target(V1_METRICS + "/project/" + parent.getUuid() + "/current")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "critical": 10,
                          "firstOccurrence": "${json-unit.any-number}",
                          "lastOccurrence": "${json-unit.any-number}"
                        }
                        """);
    }

}
