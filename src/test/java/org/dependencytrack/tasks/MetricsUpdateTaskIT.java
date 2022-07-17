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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks;

import alpine.event.framework.EventService;
import alpine.persistence.JdoProperties;
import alpine.server.persistence.PersistenceManagerFactory;
import org.apache.commons.lang3.SystemUtils;
import org.datanucleus.PropertyNames;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.dependencytrack.event.CallbackEvent;
import org.dependencytrack.event.MetricsUpdateEvent;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityMetrics;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.MSSQLServerContainer;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import javax.jdo.JDOHelper;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assume.assumeFalse;

/**
 * Integration test suite to verify that {@link MetricsUpdateTask}
 * works with all external databases we support. Necessary because we
 * make use of native SQL queries.
 * <p>
 * The tests are not supposed to be super thorough, that's what
 * {@link MetricsUpdateTaskTest} is for.
 *
 * @since 4.6.0
 */
@RunWith(Suite.class)
@SuiteClasses({
        MetricsUpdateTaskIT.MsSqlServerIT.class,
        MetricsUpdateTaskIT.MySqlIT.class,
        MetricsUpdateTaskIT.PostgreSqlIT.class,
})
public class MetricsUpdateTaskIT {

    @BeforeClass
    public static void setUpClass() {
        EventService.getInstance().subscribe(MetricsUpdateEvent.class, MetricsUpdateTask.class);
        EventService.getInstance().subscribe(CallbackEvent.class, CallbackTask.class);
    }

    @AfterClass
    public static void tearDownClass() {
        EventService.getInstance().unsubscribe(MetricsUpdateTask.class);
        EventService.getInstance().unsubscribe(CallbackTask.class);
    }

    public static class MsSqlServerIT extends AbstractMetricsUpdateTaskIT {

        @Rule
        @SuppressWarnings("rawtypes")
        public final MSSQLServerContainer container =
                new MSSQLServerContainer(DockerImageName.parse("mcr.microsoft.com/mssql/server:2019-latest"))
                        .acceptLicense();

        @BeforeClass
        public static void setUpClass() {
            // https://github.com/microsoft/mssql-docker/issues/668
            assumeFalse("The SQL Server image is not compatible with ARM", "aarch64".equals(SystemUtils.OS_ARCH));
        }

        @Override
        void setUpDatabase() throws Exception {
            // We need to create the database manually because the container won't do it automatically.
            final Container.ExecResult execResult = container.execInContainer("/opt/mssql-tools/bin/sqlcmd",
                    "-S", "localhost",
                    "-U", container.getUsername(),
                    "-P", container.getPassword(),
                    "-Q", "CREATE DATABASE dtrack");
            assertThat(execResult.getExitCode()).isZero();

            final Properties jdoProps = JdoProperties.get();
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_URL, container.getJdbcUrl() +
                    ";databaseName=dtrack;sendStringParametersAsUnicode=false;trustServerCertificate=true");
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_DRIVER_NAME, com.microsoft.sqlserver.jdbc.SQLServerDriver.class.getName());
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_USER_NAME, container.getUsername());
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_PASSWORD, container.getPassword());

            final var pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(jdoProps, "Alpine");
            PersistenceManagerFactory.setJdoPersistenceManagerFactory(pmf);
        }
    }

    public static class MySqlIT extends AbstractMetricsUpdateTaskIT {

        @Rule
        @SuppressWarnings("rawtypes")
        public final MySQLContainer container = new MySQLContainer(DockerImageName.parse("mysql:5.7"))
                .withConfigurationOverride("testcontainers/mysql");

        @Override
        void setUpDatabase() {
            final Properties jdoProps = JdoProperties.get();
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_URL, container.getJdbcUrl());
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_DRIVER_NAME, com.mysql.cj.jdbc.Driver.class.getName());
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_USER_NAME, container.getUsername());
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_PASSWORD, container.getPassword());

            final var pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(jdoProps, "Alpine");
            PersistenceManagerFactory.setJdoPersistenceManagerFactory(pmf);
        }
    }

    public static class PostgreSqlIT extends AbstractMetricsUpdateTaskIT {

        @Rule
        @SuppressWarnings("rawtypes")
        public final PostgreSQLContainer container = new PostgreSQLContainer(DockerImageName.parse("postgres:14-alpine"));

        @Override
        void setUpDatabase() {
            final Properties jdoProps = JdoProperties.get();
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_URL, container.getJdbcUrl());
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_DRIVER_NAME, org.postgresql.Driver.class.getName());
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_USER_NAME, container.getUsername());
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_PASSWORD, container.getPassword());

            final var pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(jdoProps, "Alpine");
            PersistenceManagerFactory.setJdoPersistenceManagerFactory(pmf);
        }
    }

    private static abstract class AbstractMetricsUpdateTaskIT {

        abstract void setUpDatabase() throws Exception;

        @Before
        public void setUp() throws Exception {
            setUpDatabase();
        }

        @After
        public void tearDown() {
            PersistenceManagerFactory.tearDown();
        }

        @Test
        public void testPortfolioMetricsUpdate() {
            try (final var qm = new QueryManager()) {
                var project = new Project();
                project.setName("acme-app");
                qm.createProject(project, List.of(), false);

                var component = new Component();
                component.setProject(project);
                component.setName("acme-lib");
                component = qm.createComponent(component, false);

                var vuln = new Vulnerability();
                vuln.setVulnId("INTERNAL-001");
                vuln.setSource(Vulnerability.Source.INTERNAL);
                vuln.setSeverity(Severity.HIGH);
                vuln = qm.createVulnerability(vuln, false);
                qm.addVulnerability(vuln, component, AnalyzerIdentity.NONE);
                qm.makeAnalysis(component, vuln, AnalysisState.NOT_AFFECTED, null, null, null, false);

                final var policy = qm.createPolicy(UUID.randomUUID().toString(), Policy.Operator.ALL, Policy.ViolationState.FAIL);
                final var policyCondition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, "");
                var policyViolation = new PolicyViolation();
                policyViolation.setComponent(component);
                policyViolation.setPolicyCondition(policyCondition);
                policyViolation.setTimestamp(new Date());
                policyViolation.setType(PolicyViolation.Type.OPERATIONAL);
                policyViolation = qm.addPolicyViolationIfNotExist(policyViolation);
                qm.makeViolationAnalysis(component, policyViolation, ViolationAnalysisState.APPROVED, false);
            }

            new MetricsUpdateTask().inform(new MetricsUpdateEvent(MetricsUpdateEvent.Type.PORTFOLIO));

            try (final var qm = new QueryManager()) {
                final PortfolioMetrics metrics = qm.getMostRecentPortfolioMetrics();
                assertThat(metrics).isNotNull();
                assertThat(metrics.getProjects()).isEqualTo(1);
                assertThat(metrics.getVulnerableProjects()).isEqualTo(1);
                assertThat(metrics.getComponents()).isEqualTo(1);
                assertThat(metrics.getVulnerableComponents()).isEqualTo(1);
                assertThat(metrics.getCritical()).isZero();
                assertThat(metrics.getHigh()).isEqualTo(1);
                assertThat(metrics.getMedium()).isZero();
                assertThat(metrics.getLow()).isZero();
                assertThat(metrics.getUnassigned()).isZero();
                assertThat(metrics.getVulnerabilities()).isEqualTo(1);
                assertThat(metrics.getSuppressed()).isZero();
                assertThat(metrics.getFindingsTotal()).isEqualTo(1);
                assertThat(metrics.getFindingsAudited()).isEqualTo(1);
                assertThat(metrics.getFindingsUnaudited()).isZero();
                assertThat(metrics.getInheritedRiskScore()).isEqualTo(5.0);
                assertThat(metrics.getPolicyViolationsFail()).isEqualTo(1);
                assertThat(metrics.getPolicyViolationsWarn()).isZero();
                assertThat(metrics.getPolicyViolationsInfo()).isZero();
                assertThat(metrics.getPolicyViolationsTotal()).isEqualTo(1);
                assertThat(metrics.getPolicyViolationsAudited()).isEqualTo(1);
                assertThat(metrics.getPolicyViolationsUnaudited()).isEqualTo(0);
                assertThat(metrics.getPolicyViolationsSecurityTotal()).isZero();
                assertThat(metrics.getPolicyViolationsSecurityAudited()).isZero();
                assertThat(metrics.getPolicyViolationsSecurityUnaudited()).isZero();
                assertThat(metrics.getPolicyViolationsLicenseTotal()).isZero();
                assertThat(metrics.getPolicyViolationsLicenseAudited()).isZero();
                assertThat(metrics.getPolicyViolationsLicenseUnaudited()).isZero();
                assertThat(metrics.getPolicyViolationsOperationalTotal()).isEqualTo(1);
                assertThat(metrics.getPolicyViolationsOperationalAudited()).isEqualTo(1);
                assertThat(metrics.getPolicyViolationsOperationalUnaudited()).isZero();
            }
        }

        @Test
        public void testVulnerabilityMetricsUpdate() {
            try (final var qm = new QueryManager()) {
                // Test that paging works by creating more vulnerabilities
                // than fit on a single page (of size 500). Paging is currently
                // the primary area where the supported databases behave differently.
                for (int i = 0; i < 750; i++) {
                    final var vuln = new Vulnerability();
                    vuln.setVulnId("INTERNAL-" + i);
                    vuln.setSource(Vulnerability.Source.INTERNAL);
                    vuln.setSeverity(Severity.HIGH);
                    vuln.setCreated(Date.from(LocalDateTime.of(2020, 10, 1, 6, 6, 6).toInstant(ZoneOffset.UTC)));
                    qm.createVulnerability(vuln, false);
                }
            }

            new MetricsUpdateTask().inform(new MetricsUpdateEvent(MetricsUpdateEvent.Type.VULNERABILITY));

            try (final var qm = new QueryManager()) {
                final List<VulnerabilityMetrics> metrics = qm.getVulnerabilityMetrics();

                assertThat(metrics).hasSize(2);
                assertThat(metrics).satisfiesExactlyInAnyOrder(
                        vm -> {
                            assertThat(vm.getYear()).isEqualTo(2020);
                            assertThat(vm.getMonth()).isNull();
                            assertThat(vm.getCount()).isEqualTo(750);
                        },
                        vm -> {
                            assertThat(vm.getYear()).isEqualTo(2020);
                            assertThat(vm.getMonth()).isEqualTo(10);
                            assertThat(vm.getCount()).isEqualTo(750);
                        }
                );
            }
        }
    }
}
