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
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

class SuppressionExpiryMaintenanceTaskTest extends PersistenceCapableTest {

    @Test
    void shouldUnsuppressFindingsWithElapsedExpiry() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-001");
        vuln.setSource(Vulnerability.Source.NVD);
        qm.persist(vuln);

        final Component expired = createComponent(project, "acme-lib-expired");
        final Component notYetExpired = createComponent(project, "acme-lib-future");
        final Component noExpiry = createComponent(project, "acme-lib-none");

        qm.makeAnalysis(new MakeAnalysisCommand(expired, vuln)
                .withState(AnalysisState.NOT_AFFECTED)
                .withSuppress(true)
                .withSuppressionExpiresAt(Instant.now().minus(1, ChronoUnit.DAYS)));
        qm.makeAnalysis(new MakeAnalysisCommand(notYetExpired, vuln)
                .withState(AnalysisState.NOT_AFFECTED)
                .withSuppress(true)
                .withSuppressionExpiresAt(Instant.now().plus(1, ChronoUnit.DAYS)));
        qm.makeAnalysis(new MakeAnalysisCommand(noExpiry, vuln)
                .withState(AnalysisState.NOT_AFFECTED)
                .withSuppress(true));

        new SuppressionExpiryMaintenanceTask().run();

        // The task writes through JDBI; drop the JDO cache so the assertions below
        // observe the updated rows.
        qm.getPersistenceManager().evictAll();

        final Analysis expiredAnalysis = qm.getAnalysis(expired, vuln);
        assertThat(expiredAnalysis.isSuppressed()).isFalse();
        assertThat(expiredAnalysis.getSuppressionExpiresAt()).isNull();
        // The analysis state is deliberately left alone, matching manual unsuppression.
        assertThat(expiredAnalysis.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(expiredAnalysis.getAnalysisComments())
                .filteredOn(comment -> "Unsuppressed".equals(comment.getComment()))
                .singleElement()
                // Attributing it to the task keeps it distinguishable from a manual decision.
                .extracting(AnalysisComment::getCommenter)
                .isEqualTo("[SuppressionExpiry]");

        assertThat(qm.getAnalysis(notYetExpired, vuln).isSuppressed()).isTrue();
        assertThat(qm.getAnalysis(noExpiry, vuln).isSuppressed()).isTrue();
    }

    private Component createComponent(final Project project, final String name) {
        final var component = new Component();
        component.setProject(project);
        component.setName(name);
        component.setVersion("1.0");
        qm.persist(component);
        return component;
    }
}
