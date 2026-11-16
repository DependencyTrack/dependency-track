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
package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.metrics.MetricsDao;
import org.dependencytrack.metrics.ProjectMetrics;
import org.dependencytrack.metrics.UpdateProjectMetricsActivity;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.proto.internal.workflow.v1.UpdateProjectMetricsArg;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class AnalysisQueryManagerTest extends PersistenceCapableTest {

    @Test
    void makeAnalysisShouldImmediatelyUpdateProjectMetricsWhenSuppressing() throws Exception {
        final var project = new Project();
        project.setName("acme-app");
        qm.createProject(project, java.util.List.of(), false);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.createComponent(component, false);

        var vuln = new Vulnerability();
        vuln.setVulnId("INTERNAL-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        vuln = qm.createVulnerability(vuln);
        qm.addVulnerability(vuln, component, "none");

        // Populate an initial metrics snapshot, as would exist after the day's
        // regular metrics run, *before* anyone touches the finding.
        executeMetricsActivity(project);

        final ProjectMetrics metricsBeforeSuppression =
                withJdbiHandle(handle -> handle.attach(MetricsDao.class).getMostRecentProjectMetrics(project.getId()));
        assertThat(metricsBeforeSuppression.getVulnerabilities()).isEqualTo(1);
        assertThat(metricsBeforeSuppression.getSuppressed()).isZero();

        // Suppress the finding. Nothing re-runs the metrics activity/workflow afterwards -
        // this is exactly what the UI and REST clients do when calling PUT /v1/analysis.
        qm.makeAnalysis(new MakeAnalysisCommand(component, vuln)
                .withState(AnalysisState.FALSE_POSITIVE)
                .withSuppress(true));

        final ProjectMetrics metricsAfterSuppression =
                withJdbiHandle(handle -> handle.attach(MetricsDao.class).getMostRecentProjectMetrics(project.getId()));
        assertThat(metricsAfterSuppression.getSuppressed())
                .as("suppressing a finding must trigger an immediate project metrics recalculation")
                .isEqualTo(1);
        assertThat(metricsAfterSuppression.getVulnerabilities()).isZero();
    }

    @Test
    void makeAnalysisShouldImmediatelyUpdateProjectMetricsWhenUnsuppressing() throws Exception {
        final var project = new Project();
        project.setName("acme-app");
        qm.createProject(project, java.util.List.of(), false);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.createComponent(component, false);

        var vuln = new Vulnerability();
        vuln.setVulnId("INTERNAL-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        vuln = qm.createVulnerability(vuln);
        qm.addVulnerability(vuln, component, "none");

        qm.makeAnalysis(new MakeAnalysisCommand(component, vuln)
                .withState(AnalysisState.FALSE_POSITIVE)
                .withSuppress(true));

        executeMetricsActivity(project);

        final ProjectMetrics metricsBeforeUnsuppression =
                withJdbiHandle(handle -> handle.attach(MetricsDao.class).getMostRecentProjectMetrics(project.getId()));
        assertThat(metricsBeforeUnsuppression.getSuppressed()).isEqualTo(1);
        assertThat(metricsBeforeUnsuppression.getVulnerabilities()).isZero();

        qm.makeAnalysis(new MakeAnalysisCommand(component, vuln).withSuppress(false));

        final ProjectMetrics metricsAfterUnsuppression =
                withJdbiHandle(handle -> handle.attach(MetricsDao.class).getMostRecentProjectMetrics(project.getId()));
        assertThat(metricsAfterUnsuppression.getSuppressed())
                .as("unsuppressing a finding must trigger an immediate project metrics recalculation")
                .isZero();
        assertThat(metricsAfterUnsuppression.getVulnerabilities()).isEqualTo(1);
    }

    private static void executeMetricsActivity(final Project project) throws Exception {
        new UpdateProjectMetricsActivity()
                .execute(
                        null,
                        UpdateProjectMetricsArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build());
    }
}
