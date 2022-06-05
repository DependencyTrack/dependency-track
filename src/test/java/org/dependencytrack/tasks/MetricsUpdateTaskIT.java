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

import alpine.persistence.JdoProperties;
import alpine.server.persistence.PersistenceManagerFactory;
import org.datanucleus.PropertyNames;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
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
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.MSSQLServerContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import javax.jdo.JDOHelper;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class MetricsUpdateTaskIT {

    public static class MssqlIT {

        private static final DockerImageName IMAGE_NAME = DockerImageName.parse("mcr.microsoft.com/mssql/server:2019-latest");

        @Rule
        @SuppressWarnings("rawtypes")
        public final MSSQLServerContainer container = new MSSQLServerContainer(IMAGE_NAME).acceptLicense();

        @Before
        public void setUp() throws Exception {
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

            populateTestData();
        }

        @Test
        public void test() {
            new MetricsUpdateTask().inform(new MetricsUpdateEvent(MetricsUpdateEvent.Type.PORTFOLIO));

            try (final var qm = new QueryManager()) {
                assertResult(qm.getMostRecentPortfolioMetrics());
            }
        }

        @After
        public void tearDown() {
            PersistenceManagerFactory.tearDown();
        }

    }

    public static class PostgresIT {

        private static final DockerImageName IMAGE_NAME = DockerImageName.parse("postgres:14-alpine");

        @Rule
        @SuppressWarnings("rawtypes")
        public final PostgreSQLContainer container = new PostgreSQLContainer(IMAGE_NAME);

        @Before
        public void setUp() {
            final Properties jdoProps = JdoProperties.get();
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_URL, container.getJdbcUrl());
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_DRIVER_NAME, org.postgresql.Driver.class.getName());
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_USER_NAME, container.getUsername());
            jdoProps.setProperty(PropertyNames.PROPERTY_CONNECTION_PASSWORD, container.getPassword());

            final var pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(jdoProps, "Alpine");
            PersistenceManagerFactory.setJdoPersistenceManagerFactory(pmf);

            populateTestData();
        }

        @Test
        public void test() {
            new MetricsUpdateTask().inform(new MetricsUpdateEvent(MetricsUpdateEvent.Type.PORTFOLIO));

            try (final var qm = new QueryManager()) {
                assertResult(qm.getMostRecentPortfolioMetrics());
            }
        }

        @After
        public void tearDown() {
            PersistenceManagerFactory.tearDown();
        }

    }

    protected static void populateTestData() {
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
    }

    protected static void assertResult(final PortfolioMetrics metrics) {
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