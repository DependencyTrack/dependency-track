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
package org.dependencytrack.tasks;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.model.Project;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.util.Collection;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class PortfolioAnalysisTaskTest extends PersistenceCapableTest {

    private final DexEngine dexEngineMock = mock(DexEngine.class);
    private final PortfolioAnalysisTask task = new PortfolioAnalysisTask(dexEngineMock);

    @AfterEach
    void afterEach() {
        Mockito.reset(dexEngineMock);
    }

    @Test
    void shouldScheduleVulnAnalysisForActiveProjects() {
        // Create an active project.
        var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        // Create an inactive project.
        var projectB = new Project();
        projectB.setName("acme-app-b");
        projectB.setInactiveSince(new Date());
        qm.persist(projectB);

        task.run();

        final ArgumentCaptor<Collection<CreateWorkflowRunRequest<?>>> requestsCaptor = ArgumentCaptor.captor();
        verify(dexEngineMock).createRuns(requestsCaptor.capture());

        assertThat(requestsCaptor.getValue()).satisfiesExactly(request -> {
            assertThat(request.workflowName()).isEqualTo("analyze-project");
            assertThat(request.workflowVersion()).isEqualTo(1);
            assertThat(request.workflowInstanceId()).isEqualTo("analyze-project-scheduled:" + projectA.getUuid());
            assertThat(request.concurrencyKey()).isEqualTo("analyze-project:" + projectA.getUuid());
            assertThat(request.labels()).containsOnly(Map.entry("project_uuid", projectA.getUuid().toString()));
            assertThat(request.priority()).isZero();
        });
    }

}